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
#[cfg(target_env = "musl")]
use super::frame::COMPACT_FRAME_PAYLOAD_THRESHOLD;
use super::frame::{
    CMD_FIN, CMD_PSH, DEFAULT_UPLOAD_BATCH_IOVECS, DEFAULT_UPLOAD_BATCH_SIZE,
    LARGE_UPLOAD_BATCH_IOVECS, MAX_FRAME_PAYLOAD_LEN, MAX_UPLOAD_BATCH_IOVECS,
    SMALL_DATA_FRAME_FLUSH_THRESHOLD, SMALL_DOWNLOAD_COALESCE_WAIT, SMALL_PAYLOAD_LEN,
    SMALL_UPLOAD_BATCH_IOVECS, download_coalesce_target, upload_batch_policy,
};
use super::writer::{FrameWriter, write_frame, write_frame_immediate};
#[cfg(target_env = "musl")]
use super::writer::{write_prefixed_frame, write_prefixed_frame_immediate};

const TINY_UPLOAD_BATCH_IOVECS: usize = 4;
#[cfg(target_env = "musl")]
const INLINE_MUSL_UPLOAD_BATCH_BYTES: usize = 4 * SMALL_PAYLOAD_LEN;
#[cfg(not(target_env = "musl"))]
const INLINE_UPLOAD_BATCH_BYTES: usize = 2 * SMALL_PAYLOAD_LEN;

pub(super) async fn pump_inbound_to_remote<W>(
    mut pending: Option<BufferedChunk>,
    mut pending_front_offset: usize,
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
        if let Some(chunk) = pending.take() {
            let chunk_offset = pending_front_offset.min(chunk.len());
            queued_bytes += chunk.len().saturating_sub(chunk_offset);
            chunks.push_back(chunk);
            front_offset = chunk_offset;
            pending_front_offset = 0;
        }
        let policy = upload_batch_policy_for_chunks(&chunks, front_offset);
        fill_ready_upload_batch(
            &mut rx,
            &mut chunks,
            &mut pending,
            &mut queued_bytes,
            &mut finished,
            policy,
        );
        #[cfg(target_env = "musl")]
        if should_yield_for_upload_batch_fill(
            finished,
            pending.is_none(),
            chunks.len(),
            queued_bytes,
            policy,
        ) {
            // Musl remains the weakest weak-link upload target. Yield once when a fresh batch
            // only has a single underfilled chunk so the immediately-following frame can join
            // the same write without turning this into a blocking wait loop.
            tokio::task::yield_now().await;
            fill_ready_upload_batch(
                &mut rx,
                &mut chunks,
                &mut pending,
                &mut queued_bytes,
                &mut finished,
                policy,
            );
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

#[cfg(target_env = "musl")]
fn should_yield_for_upload_batch_fill(
    finished: bool,
    no_pending_chunk: bool,
    chunk_count: usize,
    queued_bytes: usize,
    policy: super::frame::UploadBatchPolicy,
) -> bool {
    if finished
        || !no_pending_chunk
        || chunk_count != 1
        || queued_bytes == 0
        || queued_bytes >= policy.max_bytes
    {
        return false;
    }

    if policy.max_iovecs == SMALL_UPLOAD_BATCH_IOVECS {
        return queued_bytes <= SMALL_PAYLOAD_LEN;
    }

    false
}

fn fill_ready_upload_batch(
    rx: &mut mpsc::Receiver<InboundMessage>,
    chunks: &mut VecDeque<BufferedChunk>,
    pending: &mut Option<BufferedChunk>,
    queued_bytes: &mut usize,
    finished: &mut bool,
    policy: super::frame::UploadBatchPolicy,
) {
    while *queued_bytes < policy.max_bytes && chunks.len() < policy.max_iovecs && !*finished {
        match rx.try_recv() {
            Ok(InboundMessage::Data(chunk)) => {
                if chunks.is_empty()
                    || (*queued_bytes + chunk.len() <= policy.max_bytes
                        && chunks.len() < policy.max_iovecs)
                {
                    *queued_bytes += chunk.len();
                    chunks.push_back(chunk);
                } else {
                    *pending = Some(chunk);
                    break;
                }
            }
            Ok(InboundMessage::Fin) => {
                *finished = true;
                break;
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                *finished = true;
                break;
            }
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
    prefetched_download: Option<Vec<u8>>,
) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0u8; 7 + MAX_FRAME_PAYLOAD_LEN];
    let mut total = 0u64;
    let mut sent_first_payload = false;
    let mut prefetched_download = prefetched_download;
    loop {
        let read = if let Some(prefetched) = prefetched_download.take() {
            let read = prefetched.len();
            buffer[7..7 + read].copy_from_slice(&prefetched);
            read
        } else {
            tokio::select! {
                _ = control.cancelled() => return Ok(total),
                read = reader.read(&mut buffer[7..]) => read?,
            }
        };
        if read == 0 {
            write_frame(&writer, CMD_FIN, stream_id, &[]).await?;
            return Ok(total);
        }
        let first_payload_fast_path = !sent_first_payload;
        let (read, saw_eof) = if first_payload_fast_path {
            match download_coalesce_target(read) {
                Some(target) => {
                    // Let a tiny first read wait once for the immediately-following body bytes so
                    // HTTP downloads do not split "headers now, first payload next frame" unless
                    // the extra bytes truly are not ready yet.
                    coalesce_download_reads_inner(reader, &mut buffer[7..], read, target, true)
                        .await?
                }
                None => (read, false),
            }
        } else {
            match download_coalesce_target(read) {
                Some(target) => {
                    coalesce_download_reads_inner(reader, &mut buffer[7..], read, target, true)
                        .await?
                }
                None => (read, false),
            }
        };
        if first_payload_fast_path {
            #[cfg(target_env = "musl")]
            if read > COMPACT_FRAME_PAYLOAD_THRESHOLD {
                write_prefixed_frame_immediate(&writer, CMD_PSH, stream_id, &mut buffer, read)
                    .await?;
            } else {
                write_frame_immediate(&writer, CMD_PSH, stream_id, &buffer[7..7 + read]).await?;
            }
            #[cfg(not(target_env = "musl"))]
            write_frame_immediate(&writer, CMD_PSH, stream_id, &buffer[7..7 + read]).await?;
        } else {
            #[cfg(target_env = "musl")]
            if read > COMPACT_FRAME_PAYLOAD_THRESHOLD {
                write_prefixed_frame(&writer, CMD_PSH, stream_id, &mut buffer, read).await?;
            } else {
                write_frame(&writer, CMD_PSH, stream_id, &buffer[7..7 + read]).await?;
            }
            #[cfg(not(target_env = "musl"))]
            write_frame(&writer, CMD_PSH, stream_id, &buffer[7..7 + read]).await?;
        }
        let transferred = read as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
        if let Some(activity) = activity.as_ref() {
            activity.record();
        }
        sent_first_payload = true;
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
        if chunks.len() == 1 {
            // Large single-chunk uploads do not need the tier-sized IoSlice staging path.
            return write_chunk_batch_vectored::<_, 1>(writer, chunks, front_offset, policy).await;
        }
        if chunks.len() > 1 && chunks.len() <= TINY_UPLOAD_BATCH_IOVECS {
            #[cfg(target_env = "musl")]
            let mut buffer = [0u8; INLINE_MUSL_UPLOAD_BATCH_BYTES];
            #[cfg(not(target_env = "musl"))]
            let mut buffer = [0u8; INLINE_UPLOAD_BATCH_BYTES];
            if let Some(total) = fill_chunk_batch_inline(chunks, front_offset, &mut buffer, policy)
            {
                return writer
                    .write(&buffer[..total])
                    .await
                    .context("write inbound chunk batch");
            }
        }
        #[cfg(target_env = "musl")]
        if policy.max_iovecs == SMALL_UPLOAD_BATCH_IOVECS {
            if chunks.len() <= TINY_UPLOAD_BATCH_IOVECS {
                // Musl benefits from keeping tiny small-upload batches off the 80-slot IoSlice
                // staging path while still using write_vectored for single-chunk uploads.
                return write_chunk_batch_vectored::<_, TINY_UPLOAD_BATCH_IOVECS>(
                    writer,
                    chunks,
                    front_offset,
                    policy,
                )
                .await;
            }
        }
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

fn fill_chunk_batch_inline(
    chunks: &VecDeque<BufferedChunk>,
    front_offset: usize,
    buffer: &mut [u8],
    policy: super::frame::UploadBatchPolicy,
) -> Option<usize> {
    let mut total = 0usize;
    let mut remaining = policy.max_bytes;
    for (index, chunk) in chunks.iter().enumerate() {
        if index >= policy.max_iovecs || remaining == 0 {
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
        if total + used > buffer.len() {
            return None;
        }
        buffer[total..total + used].copy_from_slice(&slice[..used]);
        total += used;
        remaining -= used;
    }
    Some(total)
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
    front_offset: usize,
) -> super::frame::UploadBatchPolicy {
    let front_len = chunks
        .front()
        .map(|front| front.len().saturating_sub(front_offset))
        .unwrap_or_default();
    let effective_front_len = if front_len <= SMALL_PAYLOAD_LEN {
        chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| {
                if index == 0 {
                    chunk.len().saturating_sub(front_offset)
                } else {
                    chunk.len()
                }
            })
            .find(|chunk_len| *chunk_len > SMALL_PAYLOAD_LEN)
            .unwrap_or(front_len)
    } else {
        front_len
    };
    let policy = upload_batch_policy(effective_front_len);
    if front_offset > 0 && policy.max_iovecs == LARGE_UPLOAD_BATCH_IOVECS {
        return super::frame::UploadBatchPolicy {
            max_bytes: DEFAULT_UPLOAD_BATCH_SIZE,
            max_iovecs: DEFAULT_UPLOAD_BATCH_IOVECS,
        };
    }
    policy
}

#[cfg(test)]
pub(super) async fn coalesce_download_reads<R>(
    reader: &mut R,
    buffer: &mut [u8],
    filled: usize,
    target: usize,
) -> anyhow::Result<(usize, bool)>
where
    R: AsyncRead + Unpin,
{
    coalesce_download_reads_inner(reader, buffer, filled, target, true).await
}

async fn coalesce_download_reads_inner<R>(
    reader: &mut R,
    buffer: &mut [u8],
    mut filled: usize,
    target: usize,
    allow_deferred_coalesce: bool,
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
            None if allow_deferred_coalesce
                && !retried_after_yield
                && filled < SMALL_DATA_FRAME_FLUSH_THRESHOLD =>
            {
                retried_after_yield = true;
                tokio::task::yield_now().await;
            }
            // Lossy or jittery links can deliver the next 1 KiB slice just after the current
            // scheduler turn. Wait briefly once so concurrent small downloads can coalesce past
            // the immediate-flush threshold without turning this into a blocking read loop.
            None if allow_deferred_coalesce
                && !retried_after_wait
                && filled < SMALL_DATA_FRAME_FLUSH_THRESHOLD =>
            {
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

#[cfg(test)]
pub(super) async fn coalesce_download_reads_without_deferred_wait<R>(
    reader: &mut R,
    buffer: &mut [u8],
    filled: usize,
    target: usize,
) -> anyhow::Result<(usize, bool)>
where
    R: AsyncRead + Unpin,
{
    coalesce_download_reads_inner(reader, buffer, filled, target, false).await
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
    front_offset: usize,
) -> super::frame::UploadBatchPolicy {
    upload_batch_policy_for_chunks(chunks, front_offset)
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
            if let Some(front) = chunks.front_mut() {
                front.release_written(written);
            }
            *front_offset += written;
            break;
        }
        if let Some(front) = chunks.front_mut() {
            front.release_written(remaining);
        }
        written -= remaining;
        chunks.pop_front();
        *front_offset = 0;
    }
}
