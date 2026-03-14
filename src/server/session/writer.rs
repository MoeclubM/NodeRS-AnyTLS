use anyhow::{Context, bail, ensure};
use std::collections::VecDeque;
use std::io::IoSlice;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::sync::{Mutex, oneshot};

use super::TlsStream;
use super::frame::{
    CMD_PSH, COMPACT_FRAME_PAYLOAD_THRESHOLD, MAX_FRAME_PAYLOAD_LEN,
    SMALL_DATA_FRAME_FLUSH_THRESHOLD, should_flush_frame,
};

const MAX_PENDING_COMPACT_FRAMES: usize = 64;

type PendingResultSender = oneshot::Sender<anyhow::Result<()>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompactContentionStrategy {
    Inline,
    Queue,
}

struct PendingCompactFrame {
    buffer: Box<[u8]>,
    needs_flush: bool,
    done: PendingResultSender,
}

#[derive(Clone)]
pub(super) struct FrameWriter {
    inner: Arc<Mutex<WriteHalf<TlsStream>>>,
    pending_compact: Arc<std::sync::Mutex<VecDeque<PendingCompactFrame>>>,
    // Large writes frequently touch this path when no compact frames are queued.
    // Tracking the queue length atomically avoids taking the mutex in that case.
    pending_compact_len: Arc<AtomicUsize>,
}

impl FrameWriter {
    pub(super) fn spawn(writer: WriteHalf<TlsStream>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(writer)),
            pending_compact: Arc::new(std::sync::Mutex::new(VecDeque::new())),
            pending_compact_len: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(super) async fn send(&self, cmd: u8, stream_id: u32, payload: &[u8]) -> anyhow::Result<()> {
        let payload_len = payload.len();
        if payload_len > MAX_FRAME_PAYLOAD_LEN {
            bail!("payload too large: {}", payload_len);
        }
        let header = build_frame_header(cmd, stream_id, payload_len);
        if payload_len <= COMPACT_FRAME_PAYLOAD_THRESHOLD {
            if let Ok(mut writer) = self.inner.try_lock() {
                write_compact_frame(&mut *writer, &header, payload).await?;
                self.flush_after_write(&mut *writer, cmd, payload_len)
                    .await?;
                return Ok(());
            }
            if compact_contention_strategy(cmd, payload_len) == CompactContentionStrategy::Queue {
                return self.enqueue_compact_frame(&header, cmd, payload).await;
            }

            let mut writer = self.inner.lock().await;
            write_compact_frame(&mut *writer, &header, payload).await?;
            return self.flush_after_write(&mut *writer, cmd, payload_len).await;
        }

        let mut writer = self.inner.lock().await;
        write_frame_parts(&mut *writer, &header, payload).await?;
        self.flush_after_write(&mut *writer, cmd, payload_len).await
    }

    async fn enqueue_compact_frame(
        &self,
        header: &[u8; 7],
        cmd: u8,
        payload: &[u8],
    ) -> anyhow::Result<()> {
        let (done_tx, done_rx) = oneshot::channel();
        enqueue_pending_compact_frame(
            &self.pending_compact,
            &self.pending_compact_len,
            PendingCompactFrame {
                buffer: compact_frame_buffer(header, payload).into_boxed_slice(),
                needs_flush: should_flush_frame(cmd, payload.len()),
                done: done_tx,
            },
        )?;

        let mut writer = self.inner.lock().await;
        self.flush_after_write(&mut *writer, cmd, payload.len())
            .await?;
        drop(writer);
        done_rx.await.context("await compact frame completion")??;
        Ok(())
    }

    async fn flush_after_write<W>(
        &self,
        writer: &mut W,
        cmd: u8,
        payload_len: usize,
    ) -> anyhow::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let pending_needs_flush = drain_pending_compact_frames_if_any(
            &self.pending_compact,
            &self.pending_compact_len,
            writer,
        )
        .await?;
        if should_flush_frame(cmd, payload_len) || pending_needs_flush {
            writer.flush().await.context("flush session frame")?;
        }
        Ok(())
    }
}

pub(super) async fn write_frame(
    writer: &FrameWriter,
    cmd: u8,
    stream_id: u32,
    payload: &[u8],
) -> anyhow::Result<()> {
    writer.send(cmd, stream_id, payload).await
}

fn build_frame_header(cmd: u8, stream_id: u32, payload_len: usize) -> [u8; 7] {
    let mut header = [0u8; 7];
    header[0] = cmd;
    header[1..5].copy_from_slice(&stream_id.to_be_bytes());
    header[5..7].copy_from_slice(&(payload_len as u16).to_be_bytes());
    header
}

fn compact_contention_strategy(cmd: u8, payload_len: usize) -> CompactContentionStrategy {
    // Tiny PSH frames already require an immediate flush, so the pending compact queue
    // adds per-frame allocation/notification cost without much batching benefit.
    if cmd == CMD_PSH && payload_len > SMALL_DATA_FRAME_FLUSH_THRESHOLD {
        CompactContentionStrategy::Queue
    } else {
        CompactContentionStrategy::Inline
    }
}

fn enqueue_pending_compact_frame(
    pending: &std::sync::Mutex<VecDeque<PendingCompactFrame>>,
    pending_len: &AtomicUsize,
    frame: PendingCompactFrame,
) -> anyhow::Result<()> {
    let mut guard = pending.lock().expect("pending compact queue poisoned");
    if guard.len() >= MAX_PENDING_COMPACT_FRAMES {
        bail!("pending compact frame queue full");
    }
    guard.push_back(frame);
    pending_len.fetch_add(1, Ordering::Release);
    Ok(())
}

async fn drain_pending_compact_frames_if_any<W>(
    pending: &std::sync::Mutex<VecDeque<PendingCompactFrame>>,
    pending_len: &AtomicUsize,
    writer: &mut W,
) -> anyhow::Result<bool>
where
    W: AsyncWrite + Unpin,
{
    if pending_len.load(Ordering::Acquire) == 0 {
        return Ok(false);
    }
    drain_pending_compact_frames(pending, pending_len, writer).await
}

async fn drain_pending_compact_frames<W>(
    pending: &std::sync::Mutex<VecDeque<PendingCompactFrame>>,
    pending_len: &AtomicUsize,
    writer: &mut W,
) -> anyhow::Result<bool>
where
    W: AsyncWrite + Unpin,
{
    let frames = {
        let mut guard = pending.lock().expect("pending compact queue poisoned");
        guard.drain(..).collect::<Vec<_>>()
    };
    if frames.is_empty() {
        return Ok(false);
    }
    pending_len.fetch_sub(frames.len(), Ordering::AcqRel);
    let needs_flush = frames.iter().any(|frame| frame.needs_flush);
    let write_result = write_compact_frame_batch(writer, &frames).await;
    match write_result {
        Ok(()) => {
            for frame in frames {
                let _ = frame.done.send(Ok(()));
            }
        }
        Err(error) => {
            let message = error.to_string();
            for frame in frames {
                let _ = frame.done.send(Err(anyhow::anyhow!(message.clone())));
            }
            return Err(error);
        }
    }
    Ok(needs_flush)
}

async fn write_compact_frame<W>(
    writer: &mut W,
    header: &[u8; 7],
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 7 + COMPACT_FRAME_PAYLOAD_THRESHOLD];
    buffer[..7].copy_from_slice(header);
    buffer[7..7 + payload.len()].copy_from_slice(payload);
    writer
        .write_all(&buffer[..7 + payload.len()])
        .await
        .context("write compact session frame")
}

fn compact_frame_buffer(header: &[u8; 7], payload: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::with_capacity(7 + payload.len());
    buffer.extend_from_slice(header);
    buffer.extend_from_slice(payload);
    buffer
}

async fn write_compact_frame_batch<W>(
    writer: &mut W,
    frames: &[PendingCompactFrame],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if frames.is_empty() {
        return Ok(());
    }
    if writer.is_write_vectored() {
        let mut buffers: [&[u8]; MAX_PENDING_COMPACT_FRAMES] = std::array::from_fn(|_| &[][..]);
        for (index, frame) in frames.iter().enumerate() {
            buffers[index] = frame.buffer.as_ref();
        }
        return write_frame_buffers(
            writer,
            &buffers[..frames.len()],
            "write pending compact session frame",
        )
        .await;
    }
    for frame in frames {
        writer
            .write_all(&frame.buffer)
            .await
            .context("write pending compact session frame")?;
    }
    Ok(())
}

async fn write_frame_buffers<W>(
    writer: &mut W,
    buffers: &[&[u8]],
    context: &'static str,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut index = 0usize;
    let mut offset = 0usize;
    while index < buffers.len() {
        let written = if writer.is_write_vectored() {
            let mut slices: [IoSlice<'_>; MAX_PENDING_COMPACT_FRAMES] =
                std::array::from_fn(|_| IoSlice::new(&[]));
            let mut count = 0usize;
            slices[count] = IoSlice::new(&buffers[index][offset..]);
            count += 1;
            for buffer in &buffers[index + 1..] {
                if count >= slices.len() {
                    break;
                }
                slices[count] = IoSlice::new(buffer);
                count += 1;
            }
            writer
                .write_vectored(&slices[..count])
                .await
                .context(context)?
        } else {
            writer
                .write(&buffers[index][offset..])
                .await
                .context(context)?
        };
        ensure!(written > 0, "{context} returned zero bytes");
        advance_frame_buffers(buffers, &mut index, &mut offset, written);
    }
    Ok(())
}

fn advance_frame_buffers(
    buffers: &[&[u8]],
    index: &mut usize,
    offset: &mut usize,
    mut written: usize,
) {
    while written > 0 && *index < buffers.len() {
        let remaining = buffers[*index].len() - *offset;
        if written < remaining {
            *offset += written;
            break;
        }
        written -= remaining;
        *index += 1;
        *offset = 0;
    }
}

async fn write_frame_parts<W>(
    writer: &mut W,
    header: &[u8; 7],
    payload: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut header_offset = 0usize;
    let mut payload_offset = 0usize;
    while header_offset < header.len() || payload_offset < payload.len() {
        let written = if writer.is_write_vectored() {
            let mut slices = [IoSlice::new(&[]), IoSlice::new(&[])];
            let mut count = 0usize;
            if header_offset < header.len() {
                slices[count] = IoSlice::new(&header[header_offset..]);
                count += 1;
            }
            if payload_offset < payload.len() {
                slices[count] = IoSlice::new(&payload[payload_offset..]);
                count += 1;
            }
            writer
                .write_vectored(&slices[..count])
                .await
                .context("write session frame")?
        } else if header_offset < header.len() {
            writer
                .write(&header[header_offset..])
                .await
                .context("write session frame header")?
        } else {
            writer
                .write(&payload[payload_offset..])
                .await
                .context("write session frame payload")?
        };
        ensure!(written > 0, "write session frame returned zero bytes");
        if header_offset < header.len() {
            let header_remaining = header.len() - header_offset;
            let header_written = written.min(header_remaining);
            header_offset += header_written;
            payload_offset += written - header_written;
        } else {
            payload_offset += written;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};

    #[derive(Default)]
    struct MockWriter {
        bytes: Vec<u8>,
        flushes: usize,
        write_vectored_calls: usize,
        vectored: bool,
        max_write: usize,
    }

    impl AsyncWrite for MockWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let limit = if self.max_write == 0 {
                buf.len()
            } else {
                self.max_write.min(buf.len())
            };
            self.bytes.extend_from_slice(&buf[..limit]);
            Poll::Ready(Ok(limit))
        }

        fn poll_flush(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.flushes += 1;
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<std::io::Result<()>> {
            self.poll_flush(cx)
        }

        fn is_write_vectored(&self) -> bool {
            self.vectored
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            self.write_vectored_calls += 1;
            let limit = if self.max_write == 0 {
                usize::MAX
            } else {
                self.max_write
            };
            let mut written = 0usize;
            for buffer in bufs {
                if written >= limit {
                    break;
                }
                let take = (limit - written).min(buffer.len());
                self.bytes.extend_from_slice(&buffer[..take]);
                written += take;
                if take < buffer.len() {
                    break;
                }
            }
            Poll::Ready(Ok(written))
        }
    }

    fn pending_compact_frame(len: usize, needs_flush: bool) -> PendingCompactFrame {
        let (done, _rx) = oneshot::channel();
        PendingCompactFrame {
            buffer: vec![7u8; len].into_boxed_slice(),
            needs_flush,
            done,
        }
    }

    #[tokio::test]
    async fn draining_large_pending_frames_does_not_request_flush() {
        let pending =
            std::sync::Mutex::new(VecDeque::from([pending_compact_frame(6 * 1024, false)]));
        let pending_len = AtomicUsize::new(1);
        let mut writer = MockWriter {
            vectored: true,
            ..Default::default()
        };

        let needs_flush = drain_pending_compact_frames(&pending, &pending_len, &mut writer)
            .await
            .expect("drain pending frames");
        assert!(!needs_flush);
        assert_eq!(writer.flushes, 0);
        assert_eq!(writer.bytes.len(), 6 * 1024);
        assert_eq!(writer.write_vectored_calls, 1);
        assert_eq!(pending_len.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn draining_small_pending_frames_requests_flush() {
        let pending = std::sync::Mutex::new(VecDeque::from([pending_compact_frame(1024, true)]));
        let pending_len = AtomicUsize::new(1);
        let mut writer = MockWriter {
            vectored: true,
            ..Default::default()
        };

        let needs_flush = drain_pending_compact_frames(&pending, &pending_len, &mut writer)
            .await
            .expect("drain pending frames");
        assert!(needs_flush);
        assert_eq!(writer.flushes, 0);
        assert_eq!(writer.bytes.len(), 1024);
        assert_eq!(writer.write_vectored_calls, 1);
        assert_eq!(pending_len.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn skipping_drain_when_no_pending_frames_avoids_work() {
        let pending = std::sync::Mutex::new(VecDeque::new());
        let pending_len = AtomicUsize::new(0);
        let mut writer = MockWriter {
            vectored: true,
            ..Default::default()
        };

        let needs_flush = drain_pending_compact_frames_if_any(&pending, &pending_len, &mut writer)
            .await
            .expect("skip empty pending drain");
        assert!(!needs_flush);
        assert_eq!(writer.bytes.len(), 0);
        assert_eq!(writer.write_vectored_calls, 0);
    }

    #[tokio::test]
    async fn batched_frame_buffers_handle_partial_vectored_writes() {
        let mut writer = MockWriter {
            vectored: true,
            max_write: 5,
            ..Default::default()
        };
        let buffers = [b"hello".as_slice(), b"world".as_slice(), b"!".as_slice()];

        write_frame_buffers(&mut writer, &buffers, "write test buffers")
            .await
            .expect("write frame buffers");
        assert_eq!(writer.bytes, b"helloworld!");
        assert!(writer.write_vectored_calls >= 3);
    }

    #[test]
    fn small_flush_bound_psh_frames_stay_inline_under_contention() {
        assert_eq!(
            compact_contention_strategy(CMD_PSH, 1024),
            CompactContentionStrategy::Inline
        );
        assert_eq!(
            compact_contention_strategy(CMD_PSH, SMALL_DATA_FRAME_FLUSH_THRESHOLD),
            CompactContentionStrategy::Inline
        );
    }

    #[test]
    fn larger_psh_frames_still_use_pending_queue_under_contention() {
        assert_eq!(
            compact_contention_strategy(CMD_PSH, SMALL_DATA_FRAME_FLUSH_THRESHOLD + 1),
            CompactContentionStrategy::Queue
        );
        assert_eq!(
            compact_contention_strategy(CMD_PSH, COMPACT_FRAME_PAYLOAD_THRESHOLD),
            CompactContentionStrategy::Queue
        );
    }

    #[test]
    fn control_frames_never_enter_pending_compact_queue() {
        assert_eq!(
            compact_contention_strategy(super::super::frame::CMD_FIN, 0),
            CompactContentionStrategy::Inline
        );
    }
}
