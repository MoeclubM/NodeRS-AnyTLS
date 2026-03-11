use anyhow::{Context, bail, ensure};
use std::io::IoSlice;
use std::sync::Arc;
use tokio::io::{AsyncWrite, AsyncWriteExt, WriteHalf};
use tokio::sync::Mutex;

use super::TlsStream;
use super::frame::{MAX_FRAME_PAYLOAD_LEN, SMALL_DATA_FRAME_FLUSH_THRESHOLD, should_flush_frame};

#[derive(Clone)]
pub(super) struct FrameWriter {
    inner: Arc<Mutex<WriteHalf<TlsStream>>>,
}

impl FrameWriter {
    pub(super) fn spawn(writer: WriteHalf<TlsStream>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(writer)),
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
        let mut writer = self.inner.lock().await;
        if payload.len() <= SMALL_DATA_FRAME_FLUSH_THRESHOLD {
            let mut buffer = [0u8; 7 + SMALL_DATA_FRAME_FLUSH_THRESHOLD];
            buffer[..7].copy_from_slice(&header);
            buffer[7..7 + payload.len()].copy_from_slice(payload);
            writer
                .write_all(&buffer[..7 + payload.len()])
                .await
                .context("write compact session frame")?;
        } else {
            write_frame_parts(&mut *writer, &header, payload).await?;
        }
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
