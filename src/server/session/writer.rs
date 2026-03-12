use anyhow::{Context, bail, ensure};
use std::collections::VecDeque;
use std::io::IoSlice;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::sync::{Mutex, oneshot};

use super::TlsStream;
use super::frame::{
    CMD_PSH, COMPACT_FRAME_PAYLOAD_THRESHOLD, MAX_FRAME_PAYLOAD_LEN, should_flush_frame,
};

const MAX_PENDING_COMPACT_FRAMES: usize = 64;

type PendingResultSender = oneshot::Sender<anyhow::Result<()>>;

struct PendingCompactFrame {
    buffer: Box<[u8]>,
    done: PendingResultSender,
}

#[derive(Clone)]
pub(super) struct FrameWriter {
    inner: Arc<Mutex<WriteHalf<TlsStream>>>,
    pending_compact: Arc<std::sync::Mutex<VecDeque<PendingCompactFrame>>>,
}

impl FrameWriter {
    pub(super) fn spawn(writer: WriteHalf<TlsStream>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(writer)),
            pending_compact: Arc::new(std::sync::Mutex::new(VecDeque::new())),
        }
    }

    pub(super) async fn send(&self, cmd: u8, stream_id: u32, payload: &[u8]) -> anyhow::Result<()> {
        if payload.len() > MAX_FRAME_PAYLOAD_LEN {
            bail!("payload too large: {}", payload.len());
        }
        let mut header = [0u8; 7];
        header[0] = cmd;
        header[1..5].copy_from_slice(&stream_id.to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        if cmd == CMD_PSH && payload.len() <= COMPACT_FRAME_PAYLOAD_THRESHOLD {
            if let Ok(mut writer) = self.inner.try_lock() {
                write_compact_frame(&mut *writer, &header, payload).await?;
                drain_pending_compact_frames(&self.pending_compact, &mut *writer).await?;
                if should_flush_frame(cmd, payload.len()) {
                    writer.flush().await.context("flush session frame")?;
                }
                return Ok(());
            }

            let (done_tx, done_rx) = oneshot::channel();
            enqueue_pending_compact_frame(
                &self.pending_compact,
                PendingCompactFrame {
                    buffer: compact_frame_buffer(&header, payload).into_boxed_slice(),
                    done: done_tx,
                },
            )?;

            let mut writer = self.inner.lock().await;
            drain_pending_compact_frames(&self.pending_compact, &mut *writer).await?;
            drop(writer);
            done_rx.await.context("await compact frame completion")??;
            return Ok(());
        }

        let mut writer = self.inner.lock().await;
        if payload.len() <= COMPACT_FRAME_PAYLOAD_THRESHOLD {
            write_compact_frame(&mut *writer, &header, payload).await?;
        } else {
            write_frame_parts(&mut *writer, &header, payload).await?;
        }
        drain_pending_compact_frames(&self.pending_compact, &mut *writer).await?;
        if should_flush_frame(cmd, payload.len()) {
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

fn enqueue_pending_compact_frame(
    pending: &std::sync::Mutex<VecDeque<PendingCompactFrame>>,
    frame: PendingCompactFrame,
) -> anyhow::Result<()> {
    let mut guard = pending.lock().expect("pending compact queue poisoned");
    if guard.len() >= MAX_PENDING_COMPACT_FRAMES {
        bail!("pending compact frame queue full");
    }
    guard.push_back(frame);
    Ok(())
}

async fn drain_pending_compact_frames<W>(
    pending: &std::sync::Mutex<VecDeque<PendingCompactFrame>>,
    writer: &mut W,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let frames = {
        let mut guard = pending.lock().expect("pending compact queue poisoned");
        guard.drain(..).collect::<Vec<_>>()
    };
    if frames.is_empty() {
        return Ok(());
    }
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
    writer
        .flush()
        .await
        .context("flush pending compact session frames")?;
    Ok(())
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
    let mut buffer = vec![0u8; 7 + payload.len()];
    buffer[..7].copy_from_slice(header);
    buffer[7..].copy_from_slice(payload);
    buffer
}

async fn write_compact_frame_batch<W>(
    writer: &mut W,
    frames: &[PendingCompactFrame],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    for frame in frames {
        writer
            .write_all(&frame.buffer)
            .await
            .context("write pending compact session frame")?;
    }
    Ok(())
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
