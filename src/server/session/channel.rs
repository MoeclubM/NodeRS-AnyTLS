use std::mem::MaybeUninit;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{Notify, mpsc};

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
        if bytes.capacity() < len {
            bytes.reserve(len);
        }
        bytes.clear();
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

    pub(super) fn clear(&mut self) {
        self.bytes.clear();
    }

    pub(super) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub(super) fn reserve(&mut self, len: usize) {
        if self.bytes.capacity() < len {
            self.bytes.reserve(len);
        }
    }

    pub(super) fn spare_capacity_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        self.bytes.spare_capacity_mut()
    }

    pub(super) unsafe fn advance_mut(&mut self, len: usize) {
        let new_len = self.bytes.len() + len;
        unsafe {
            self.bytes.set_len(new_len);
        }
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
    permit: ByteBudgetPermit,
}

impl BufferedChunk {
    fn new(payload: PayloadBuffer, permit: ByteBudgetPermit) -> Self {
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
    budget: Arc<ByteBudget>,
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
            budget: Arc::new(ByteBudget::new(budget_bytes)),
        }
    }

    pub(super) fn try_send_data(&self, chunk: PayloadBuffer) -> Result<(), TrySendError> {
        let len = chunk.len();
        let permit = match self.budget.try_acquire(len) {
            Ok(permit) => permit,
            Err(()) => return Err(TrySendError::Full(chunk)),
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
        let Some(permit) = self.budget.acquire(chunk.len(), &self.tx).await else {
            return Err(anyhow::anyhow!(
                "inbound channel closed before data could be delivered"
            ));
        };
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

// `Semaphore` permits showed up hot in upload benchmarks. This keeps the same
// byte-budget semantics with a single atomic counter plus `Notify`.
#[derive(Debug)]
struct ByteBudget {
    limit: usize,
    used: AtomicUsize,
    notify: Notify,
}

impl ByteBudget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
            notify: Notify::new(),
        }
    }

    fn try_acquire(self: &Arc<Self>, len: usize) -> Result<ByteBudgetPermit, ()> {
        loop {
            let used = self.used.load(Ordering::Acquire);
            let Some(next) = used.checked_add(len) else {
                return Err(());
            };
            if next > self.limit {
                return Err(());
            }
            if self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(ByteBudgetPermit {
                    budget: self.clone(),
                    len,
                });
            }
        }
    }

    async fn acquire(
        self: &Arc<Self>,
        len: usize,
        tx: &mpsc::Sender<InboundMessage>,
    ) -> Option<ByteBudgetPermit> {
        loop {
            if let Ok(permit) = self.try_acquire(len) {
                return Some(permit);
            }
            if tx.is_closed() {
                return None;
            }
            let notified = self.notify.notified();
            // Re-check after registering interest so a concurrent release cannot
            // race past us and leave the sender sleeping indefinitely.
            if let Ok(permit) = self.try_acquire(len) {
                return Some(permit);
            }
            if tx.is_closed() {
                return None;
            }
            notified.await;
        }
    }

    fn release(&self, len: usize) {
        if len == 0 {
            return;
        }
        let previous = self.used.fetch_sub(len, Ordering::AcqRel);
        debug_assert!(previous >= len);
        self.notify.notify_one();
    }
}

#[derive(Debug)]
struct ByteBudgetPermit {
    budget: Arc<ByteBudget>,
    len: usize,
}

impl Drop for ByteBudgetPermit {
    fn drop(&mut self) {
        self.budget.release(self.len);
    }
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

    pub(super) fn from_parts(
        current: Option<BufferedChunk>,
        rx: mpsc::Receiver<InboundMessage>,
        finished: bool,
    ) -> Self {
        Self {
            rx,
            current,
            offset: 0,
            finished,
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
    let permit = Arc::new(ByteBudget::new(bytes.len().max(1)))
        .try_acquire(bytes.len().max(1))
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

    #[tokio::test]
    async fn sender_waits_for_budget_release_before_sending() {
        let (sender, mut rx) = bounded_inbound_channel(8, 4);
        sender
            .try_send_data(PayloadBuffer::new(vec![1, 2, 3, 4]))
            .expect("fill budget");

        let sender_clone = sender.clone();
        let send_task =
            tokio::spawn(async move { sender_clone.send_data(PayloadBuffer::new(vec![5])).await });

        tokio::task::yield_now().await;
        assert!(!send_task.is_finished());

        let Some(InboundMessage::Data(chunk)) = rx.recv().await else {
            panic!("expected first data chunk");
        };
        drop(chunk);

        let send_result = send_task.await.expect("join waiting sender");
        assert!(send_result.is_ok());

        let Some(InboundMessage::Data(chunk)) = rx.recv().await else {
            panic!("expected second data chunk");
        };
        assert_eq!(chunk.bytes(), &[5]);
    }

    #[test]
    fn payload_pool_returns_empty_buffer_with_requested_capacity() {
        let pool = Arc::new(PayloadPool::new(1));
        let first = pool.take(128);
        assert_eq!(first.bytes.len(), 0);
        assert!(first.bytes.capacity() >= 128);
        drop(first);

        let reused = pool.take(64);
        assert_eq!(reused.bytes.len(), 0);
        assert!(reused.bytes.capacity() >= 128);
    }

    #[test]
    fn payload_pool_grows_reused_buffer_to_requested_capacity() {
        let pool = Arc::new(PayloadPool::new(2));
        drop(PayloadBuffer {
            bytes: Vec::with_capacity(32760),
            recycler: Some(pool.clone()),
        });

        let reused = pool.take(32768);
        assert_eq!(reused.bytes.len(), 0);
        assert!(reused.bytes.capacity() >= 32768);
    }

    #[test]
    fn payload_buffer_extend_from_slice_appends_bytes() {
        let pool = Arc::new(PayloadPool::new(1));
        let mut buffer = pool.take(8);
        buffer.extend_from_slice(b"hello");
        buffer.extend_from_slice(b"!");
        assert_eq!(buffer.as_slice(), b"hello!");
    }
}
