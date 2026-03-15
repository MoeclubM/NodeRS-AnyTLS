use anyhow::{Context, ensure};
use std::collections::VecDeque;
use std::future::poll_fn;
use std::io::IoSlice;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use crate::accounting::SessionControl;

use super::super::activity::ActivityTracker;
use super::super::traffic::TrafficRecorder;
use super::channel::{BufferedChunk, InboundMessage};
use super::frame::{
    CMD_FIN, CMD_PSH, DEFAULT_UPLOAD_BATCH_IOVECS, LARGE_UPLOAD_BATCH_IOVECS,
    MAX_FRAME_PAYLOAD_LEN, MAX_UPLOAD_BATCH_IOVECS, SMALL_DATA_FRAME_FLUSH_THRESHOLD,
    SMALL_DOWNLOAD_COALESCE_WAIT, SMALL_PAYLOAD_LEN, SMALL_UPLOAD_BATCH_IOVECS,
    download_coalesce_target, upload_batch_policy,
};
use super::writer::{FrameWriter, write_frame};

pub(super) async fn pump_inbound_to_remote<W>(
    mut pending: Option<BufferedChunk>,
    mut rx: mpsc::Receiver<InboundMessage>,
    mut finished: bool,
    writer: &mut W,
    control: Arc<SessionControl>,
    traffic: Option<TrafficRecorder>,
) -> anyhow::Result<u64>
where
    W: AsyncWrite + Unpin,
{
    let mut chunks: VecDeque<BufferedChunk> = VecDeque::with_capacity(MAX_UPLOAD_BATCH_IOVECS);
    let mut front_offset = 0usize;
    let mut queued_bytes = 0usize;
    let mut total = 0u64;
    loop {
        if control.is_cancelled() {
            return Ok(total);
        }
        if let Some(chunk) = pending.take() {
            queued_bytes += chunk.len();
            chunks.push_back(chunk);
            front_offset = 0;
        }
        let policy = upload_batch_policy_for_chunks(&chunks);
        while queued_bytes < policy.max_bytes && chunks.len() < policy.max_iovecs && !finished {
            match rx.try_recv() {
                Ok(InboundMessage::Data(chunk)) => {
                    if chunks.is_empty()
                        || (queued_bytes + chunk.len() <= policy.max_bytes
                            && chunks.len() < policy.max_iovecs)
                    {
                        queued_bytes += chunk.len();
                        chunks.push_back(chunk);
                    } else {
                        pending = Some(chunk);
                        break;
                    }
                }
                Ok(InboundMessage::Fin) => {
                    finished = true;
                    break;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
            }
        }
        if chunks.is_empty() {
            if finished {
                let _ = writer.shutdown().await;
                return Ok(total);
            }
            match tokio::select! {
                _ = control.cancelled() => return Ok(total),
                message = rx.recv() => message,
            } {
                Some(InboundMessage::Data(chunk)) => {
                    pending = Some(chunk);
                    continue;
                }
                Some(InboundMessage::Fin) | None => {
                    let _ = writer.shutdown().await;
                    return Ok(total);
                }
            }
        }
        let written = tokio::select! {
            _ = control.cancelled() => return Ok(total),
            result = write_chunk_batch(writer, &chunks, front_offset, policy) => result?,
        };
        ensure!(written > 0, "write inbound batch returned zero bytes");
        advance_chunk_batch(&mut chunks, &mut front_offset, written);
        queued_bytes = queued_bytes.saturating_sub(written);
        let transferred = written as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
        if finished && pending.is_none() && chunks.is_empty() {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
    }
}

pub(super) async fn pump_copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    control: Arc<SessionControl>,
    traffic: Option<TrafficRecorder>,
    activity: Option<Arc<ActivityTracker>>,
) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];
    let mut total = 0u64;
    loop {
        if control.is_cancelled() {
            return Ok(total);
        }
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(total),
            read = reader.read(&mut buffer) => read.context("read proxied chunk")?,
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(total),
            result = writer.write_all(&buffer[..read]) => {
                result.context("write proxied chunk")?;
            }
        }
        let transferred = read as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
        if let Some(activity) = activity.as_ref() {
            activity.record();
        }
    }
}

pub(super) async fn pump_remote_to_client<R>(
    reader: &mut R,
    writer: FrameWriter,
    stream_id: u32,
    control: Arc<SessionControl>,
    traffic: Option<TrafficRecorder>,
    activity: Option<Arc<ActivityTracker>>,
) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];
    let mut total = 0u64;
    loop {
        if control.is_cancelled() {
            return Ok(total);
        }
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(total),
            read = reader.read(&mut buffer) => read?,
        };
        if read == 0 {
            write_frame(&writer, CMD_FIN, stream_id, &[]).await?;
            return Ok(total);
        }
        let (read, saw_eof) = match download_coalesce_target(read) {
            Some(target) => coalesce_download_reads(reader, &mut buffer, read, target).await?,
            None => (read, false),
        };
        write_frame(&writer, CMD_PSH, stream_id, &buffer[..read]).await?;
        let transferred = read as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
        if let Some(activity) = activity.as_ref() {
            activity.record();
        }
        if saw_eof {
            write_frame(&writer, CMD_FIN, stream_id, &[]).await?;
            return Ok(total);
        }
    }
}

async fn write_chunk_batch<W>(
    writer: &mut W,
    chunks: &VecDeque<BufferedChunk>,
    front_offset: usize,
    policy: super::frame::UploadBatchPolicy,
) -> anyhow::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    if chunks.is_empty() {
        return Ok(0);
    }
    let Some(front) = chunks.front() else {
        return Ok(0);
    };
    // GNU consistently benefits from bypassing write_vectored for tiny single-chunk uploads.
    // Musl has not shown the same win, so keep it on the regular vectored path there.
    #[cfg(not(target_env = "musl"))]
    if chunks.len() == 1 && front.len().saturating_sub(front_offset) <= SMALL_PAYLOAD_LEN {
        return writer
            .write(&front.bytes()[front_offset..])
            .await
            .context("write inbound chunk");
    }
    if writer.is_write_vectored() {
        match policy.max_iovecs {
            SMALL_UPLOAD_BATCH_IOVECS => {
                return write_chunk_batch_vectored::<_, SMALL_UPLOAD_BATCH_IOVECS>(
                    writer,
                    chunks,
                    front_offset,
                    policy,
                )
                .await;
            }
            DEFAULT_UPLOAD_BATCH_IOVECS => {
                return write_chunk_batch_vectored::<_, DEFAULT_UPLOAD_BATCH_IOVECS>(
                    writer,
                    chunks,
                    front_offset,
                    policy,
                )
                .await;
            }
            LARGE_UPLOAD_BATCH_IOVECS => {
                return write_chunk_batch_vectored::<_, LARGE_UPLOAD_BATCH_IOVECS>(
                    writer,
                    chunks,
                    front_offset,
                    policy,
                )
                .await;
            }
            _ => {
                let mut slices: [IoSlice<'_>; MAX_UPLOAD_BATCH_IOVECS] =
                    std::array::from_fn(|_| IoSlice::new(&[]));
                let count = fill_chunk_batch_slices(chunks, front_offset, &mut slices, policy);
                if count == 0 {
                    return Ok(0);
                }
                return writer
                    .write_vectored(&slices[..count])
                    .await
                    .context("write inbound chunk batch");
            }
        }
    }

    writer
        .write(&front.bytes()[front_offset..])
        .await
        .context("write inbound chunk")
}

async fn write_chunk_batch_vectored<W, const N: usize>(
    writer: &mut W,
    chunks: &VecDeque<BufferedChunk>,
    front_offset: usize,
    policy: super::frame::UploadBatchPolicy,
) -> anyhow::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    let mut slices: [IoSlice<'_>; N] = std::array::from_fn(|_| IoSlice::new(&[]));
    let count = fill_chunk_batch_slices(chunks, front_offset, &mut slices, policy);
    if count == 0 {
        return Ok(0);
    }
    writer
        .write_vectored(&slices[..count])
        .await
        .context("write inbound chunk batch")
}

#[cfg(test)]
pub(super) async fn write_chunk_batch_for_test<W>(
    writer: &mut W,
    chunks: &VecDeque<BufferedChunk>,
    front_offset: usize,
    policy: super::frame::UploadBatchPolicy,
) -> anyhow::Result<usize>
where
    W: AsyncWrite + Unpin,
{
    write_chunk_batch(writer, chunks, front_offset, policy).await
}

fn upload_batch_policy_for_chunks(
    chunks: &VecDeque<BufferedChunk>,
) -> super::frame::UploadBatchPolicy {
    let front_len = chunks.front().map(BufferedChunk::len).unwrap_or_default();
    // Anchor the batch tier to the original leading chunk size. Partial writes can
    // leave a tiny front tail behind; reclassifying the whole batch from that tail
    // alone shrinks large uploads into the small-batch policy on the next write.
    upload_batch_policy(front_len)
}

pub(super) async fn coalesce_download_reads<R>(
    reader: &mut R,
    buffer: &mut [u8],
    mut filled: usize,
    target: usize,
) -> anyhow::Result<(usize, bool)>
where
    R: AsyncRead + Unpin,
{
    let target = target.min(buffer.len());
    let mut saw_eof = false;
    let mut retried_after_yield = false;
    let mut retried_after_wait = false;
    while filled < target {
        match try_read_available(reader, &mut buffer[filled..target]).await? {
            Some(0) => {
                saw_eof = true;
                break;
            }
            Some(read) => {
                filled += read;
                retried_after_yield = false;
                if read >= SMALL_DATA_FRAME_FLUSH_THRESHOLD {
                    break;
                }
            }
            // Under high concurrency the next download chunk often lands on the next scheduler
            // turn instead of being immediately readable. Yield once before giving up so we can
            // coalesce another small slice without blocking on a full read.
            None if !retried_after_yield && filled < SMALL_DATA_FRAME_FLUSH_THRESHOLD => {
                retried_after_yield = true;
                tokio::task::yield_now().await;
            }
            // Lossy or jittery links can deliver the next 1 KiB slice just after the current
            // scheduler turn. Wait briefly once so concurrent small downloads can coalesce past
            // the immediate-flush threshold without turning this into a blocking read loop.
            None if !retried_after_wait && filled < SMALL_DATA_FRAME_FLUSH_THRESHOLD => {
                retried_after_wait = true;
                match wait_for_available_read(
                    reader,
                    &mut buffer[filled..target],
                    SMALL_DOWNLOAD_COALESCE_WAIT,
                )
                .await?
                {
                    Some(0) => {
                        saw_eof = true;
                        break;
                    }
                    Some(read) => {
                        filled += read;
                        retried_after_yield = false;
                        if read >= SMALL_DATA_FRAME_FLUSH_THRESHOLD {
                            break;
                        }
                    }
                    None => break,
                }
            }
            None => break,
        }
    }
    Ok((filled, saw_eof))
}

async fn try_read_available<R>(reader: &mut R, buffer: &mut [u8]) -> std::io::Result<Option<usize>>
where
    R: AsyncRead + Unpin,
{
    poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buffer);
        match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Ready(Ok(None)),
        }
    })
    .await
}

async fn wait_for_available_read<R>(
    reader: &mut R,
    buffer: &mut [u8],
    wait: std::time::Duration,
) -> std::io::Result<Option<usize>>
where
    R: AsyncRead + Unpin,
{
    let delay = tokio::time::sleep(wait);
    tokio::pin!(delay);
    poll_fn(|cx| {
        let mut read_buf = ReadBuf::new(buffer);
        match Pin::new(&mut *reader).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(Some(read_buf.filled().len()))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                if delay.as_mut().poll(cx).is_ready() {
                    Poll::Ready(Ok(None))
                } else {
                    Poll::Pending
                }
            }
        }
    })
    .await
}

fn fill_chunk_batch_slices<'a>(
    chunks: &'a VecDeque<BufferedChunk>,
    front_offset: usize,
    slices: &mut [IoSlice<'a>],
    policy: super::frame::UploadBatchPolicy,
) -> usize {
    let mut count = 0usize;
    let mut remaining = policy.max_bytes;
    for (index, chunk) in chunks.iter().enumerate() {
        if count >= slices.len() || count >= policy.max_iovecs || remaining == 0 {
            break;
        }
        let slice = if index == 0 {
            &chunk.bytes()[front_offset..]
        } else {
            chunk.bytes()
        };
        if slice.is_empty() {
            continue;
        }
        let used = slice.len().min(remaining);
        slices[count] = IoSlice::new(&slice[..used]);
        count += 1;
        remaining -= used;
    }
    count
}

#[cfg(test)]
pub(super) fn chunk_batch_slices(
    chunks: &VecDeque<BufferedChunk>,
    front_offset: usize,
    policy: super::frame::UploadBatchPolicy,
) -> Vec<IoSlice<'_>> {
    let mut slices: [IoSlice<'_>; MAX_UPLOAD_BATCH_IOVECS] =
        std::array::from_fn(|_| IoSlice::new(&[]));
    let count = fill_chunk_batch_slices(chunks, front_offset, &mut slices, policy);
    slices.into_iter().take(count).collect()
}

#[cfg(test)]
pub(super) fn chunk_batch_policy(
    chunks: &VecDeque<BufferedChunk>,
) -> super::frame::UploadBatchPolicy {
    upload_batch_policy_for_chunks(chunks)
}

pub(super) fn advance_chunk_batch(
    chunks: &mut VecDeque<BufferedChunk>,
    front_offset: &mut usize,
    mut written: usize,
) {
    while written > 0 {
        let Some(front) = chunks.front() else {
            *front_offset = 0;
            break;
        };
        let remaining = front.len().saturating_sub(*front_offset);
        if written < remaining {
            *front_offset += written;
            break;
        }
        written -= remaining;
        chunks.pop_front();
        *front_offset = 0;
    }
}
