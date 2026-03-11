use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{AcquireError, OwnedSemaphorePermit, Semaphore, TryAcquireError, mpsc};

pub(super) enum InboundMessage {
    Data(BufferedChunk),
    Fin,
}

#[derive(Debug)]
pub(super) struct PayloadPool {
    buffers: Mutex<Vec<Vec<u8>>>,
    max_cached: usize,
}

impl PayloadPool {
    pub(super) fn new(max_cached: usize) -> Self {
        Self {
            buffers: Mutex::new(Vec::with_capacity(max_cached)),
            max_cached,
        }
    }

    pub(super) fn take(self: &Arc<Self>, len: usize) -> PayloadBuffer {
        let mut buffers = self.buffers.lock().expect("payload pool lock poisoned");
        let index = buffers.iter().position(|buffer| buffer.capacity() >= len);
        let mut bytes = index
            .map(|index| buffers.swap_remove(index))
            .unwrap_or_default();
        drop(buffers);
        bytes.resize(len, 0);
        PayloadBuffer {
            bytes,
            recycler: Some(self.clone()),
        }
    }

    fn recycle(&self, mut bytes: Vec<u8>) {
        bytes.clear();
        let mut buffers = self.buffers.lock().expect("payload pool lock poisoned");
        if buffers.len() < self.max_cached {
            buffers.push(bytes);
        }
    }
}

#[derive(Debug)]
pub(super) struct PayloadBuffer {
    bytes: Vec<u8>,
    recycler: Option<Arc<PayloadPool>>,
}

impl PayloadBuffer {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            recycler: None,
        }
    }

    pub(super) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }

    pub(super) fn into_vec(mut self) -> Vec<u8> {
        self.recycler = None;
        std::mem::take(&mut self.bytes)
    }
}

impl Drop for PayloadBuffer {
    fn drop(&mut self) {
        if let Some(recycler) = self.recycler.take() {
            recycler.recycle(std::mem::take(&mut self.bytes));
        }
    }
}

pub(super) struct BufferedChunk {
    payload: PayloadBuffer,
    permit: OwnedSemaphorePermit,
}

impl BufferedChunk {
    pub(super) fn new(payload: PayloadBuffer, permit: OwnedSemaphorePermit) -> Self {
        Self { payload, permit }
    }

    pub(super) fn bytes(&self) -> &[u8] {
        self.payload.as_slice()
    }

    pub(super) fn len(&self) -> usize {
        self.payload.len()
    }

    pub(super) fn into_payload(self) -> PayloadBuffer {
        self.payload
    }

    pub(super) fn split_off(self, at: usize) -> Self {
        let bytes = self.payload.into_vec();
        let bytes = bytes[at..].to_vec();
        Self {
            payload: PayloadBuffer::new(bytes),
            permit: self.permit,
        }
    }
}

#[derive(Clone)]
pub(super) struct InboundSender {
    tx: mpsc::Sender<InboundMessage>,
    budget: Arc<Semaphore>,
}

#[derive(Debug)]
pub(super) enum TrySendError {
    Full(PayloadBuffer),
    Closed,
}

impl InboundSender {
    pub(super) fn new(tx: mpsc::Sender<InboundMessage>, budget_bytes: usize) -> Self {
        Self {
            tx,
            budget: Arc::new(Semaphore::new(budget_bytes)),
        }
    }

    pub(super) fn try_send_data(&self, chunk: PayloadBuffer) -> Result<(), TrySendError> {
        let len = chunk.len();
        let permit = match self.budget.clone().try_acquire_many_owned(len as u32) {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => return Err(TrySendError::Full(chunk)),
            Err(TryAcquireError::Closed) => return Err(TrySendError::Closed),
        };
        match self
            .tx
            .try_send(InboundMessage::Data(BufferedChunk::new(chunk, permit)))
        {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(message)) => {
                let InboundMessage::Data(chunk) = message else {
                    return Err(TrySendError::Closed);
                };
                Err(TrySendError::Full(chunk.into_payload()))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => Err(TrySendError::Closed),
        }
    }

    pub(super) async fn send_data(&self, chunk: PayloadBuffer) -> anyhow::Result<()> {
        let permit = self
            .budget
            .clone()
            .acquire_many_owned(chunk.len() as u32)
            .await
            .map_err(map_budget_closed)?;
        self.tx
            .send(InboundMessage::Data(BufferedChunk::new(chunk, permit)))
            .await
            .map_err(|_| anyhow::anyhow!("inbound channel closed before data could be delivered"))
    }

    pub(super) async fn send_fin(&self) -> anyhow::Result<()> {
        self.tx
            .send(InboundMessage::Fin)
            .await
            .map_err(|_| anyhow::anyhow!("inbound channel closed before FIN could be delivered"))
    }
}

fn map_budget_closed(_: AcquireError) -> anyhow::Error {
    anyhow::anyhow!("inbound channel budget closed before data could be delivered")
}

pub(super) struct ChannelReader {
    rx: mpsc::Receiver<InboundMessage>,
    current: Option<BufferedChunk>,
    offset: usize,
    finished: bool,
}

impl ChannelReader {
    pub(super) fn new(rx: mpsc::Receiver<InboundMessage>) -> Self {
        Self {
            rx,
            current: None,
            offset: 0,
            finished: false,
        }
    }

    pub(super) fn into_parts(
        self,
    ) -> (Option<BufferedChunk>, mpsc::Receiver<InboundMessage>, bool) {
        let pending = self.current.and_then(|current| {
            if self.offset < current.len() {
                Some(current.split_off(self.offset))
            } else {
                None
            }
        });
        (pending, self.rx, self.finished)
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut wrote_any = false;
        loop {
            let offset = self.offset;
            if let Some(current) = self.current.as_ref()
                && offset < current.len()
            {
                let remaining = &current.bytes()[offset..];
                let to_copy = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                wrote_any = true;
                let new_offset = offset + to_copy;
                if new_offset >= current.len() {
                    self.current = None;
                    self.offset = 0;
                } else {
                    self.offset = new_offset;
                }
                if buf.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
                continue;
            }

            if self.finished {
                return Poll::Ready(Ok(()));
            }

            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(InboundMessage::Data(chunk))) => {
                    self.current = Some(chunk);
                    self.offset = 0;
                }
                Poll::Ready(Some(InboundMessage::Fin)) | Poll::Ready(None) => {
                    self.finished = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending if wrote_any => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

pub(super) fn bounded_inbound_channel(
    capacity: usize,
    budget_bytes: usize,
) -> (InboundSender, mpsc::Receiver<InboundMessage>) {
    let (tx, rx) = mpsc::channel(capacity);
    (InboundSender::new(tx, budget_bytes), rx)
}

#[cfg(test)]
pub(super) fn test_chunk(bytes: &[u8]) -> BufferedChunk {
    let permit = Arc::new(Semaphore::new(bytes.len().max(1)))
        .try_acquire_many_owned(bytes.len().max(1) as u32)
        .expect("allocate test permit");
    BufferedChunk::new(PayloadBuffer::new(bytes.to_vec()), permit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn sender_enforces_byte_budget() {
        let (sender, mut rx) = bounded_inbound_channel(8, 4);
        assert!(
            sender
                .try_send_data(PayloadBuffer::new(vec![1, 2, 3, 4]))
                .is_ok()
        );
        assert!(matches!(
            sender.try_send_data(PayloadBuffer::new(vec![5])),
            Err(TrySendError::Full(_))
        ));
        let Some(InboundMessage::Data(chunk)) = rx.recv().await else {
            panic!("expected data chunk");
        };
        drop(chunk);
        assert!(sender.try_send_data(PayloadBuffer::new(vec![5])).is_ok());
    }
}
