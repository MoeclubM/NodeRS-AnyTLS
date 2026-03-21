use parking_lot::Mutex;
use std::mem::MaybeUninit;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context as TaskContext, Poll};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{Notify, mpsc};

use super::frame::SMALL_DATA_FRAME_FLUSH_THRESHOLD;

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
        let mut buffers = self.buffers.lock();
        // Hot paths usually recycle the same buffer sizes repeatedly. Reusing the most recent
        // buffer first avoids scanning the whole cache on every small frame, and only falls
        // back to a linear search when that hot buffer is too small for the next payload.
        let mut bytes = buffers.pop().unwrap_or_default();
        if bytes.capacity() < len
            && let Some(index) = buffers.iter().position(|buffer| buffer.capacity() >= len)
        {
            let replacement = buffers.swap_remove(index);
            if bytes.capacity() > 0 {
                buffers.push(bytes);
            }
            bytes = replacement;
        }
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
        let mut buffers = self.buffers.lock();
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

    pub(super) fn release_written(&mut self, len: usize) {
        self.permit.consume(len);
    }

    pub(super) fn split_off(mut self, at: usize) -> Self {
        self.permit.consume(at);
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
    small_budget_cache: Arc<Mutex<SenderBudgetCache>>,
}

#[derive(Debug)]
pub(super) enum TrySendError {
    Full(PayloadBuffer),
    Closed,
}

impl InboundSender {
    pub(super) fn new(tx: mpsc::Sender<InboundMessage>, budget_bytes: usize) -> Self {
        let budget = Arc::new(ByteBudget::new(budget_bytes));
        Self {
            tx,
            budget: budget.clone(),
            small_budget_cache: Arc::new(Mutex::new(SenderBudgetCache::new(budget))),
        }
    }

    pub(super) fn try_send_data(&self, chunk: PayloadBuffer) -> Result<(), TrySendError> {
        let permit = match self.try_reserve_send_budget(chunk.len()) {
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
        let Some(permit) = self.reserve_send_budget(chunk.len()).await else {
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

    fn try_reserve_send_budget(&self, len: usize) -> Result<ByteBudgetPermit, ()> {
        if len == 0 {
            return Ok(ByteBudgetPermit::new(self.budget.clone(), 0));
        }
        if len > SMALL_DATA_FRAME_FLUSH_THRESHOLD {
            self.budget.try_reserve(len)?;
            return Ok(ByteBudgetPermit::new(self.budget.clone(), len));
        }

        let mut cache = self.small_budget_cache.lock();
        if let Err(needed) = cache.try_take(len) {
            let grant = SMALL_DATA_FRAME_FLUSH_THRESHOLD.max(needed);
            if self.budget.try_reserve(grant).is_ok() {
                cache.add_reserved_and_take(grant, len);
            } else {
                self.budget.try_reserve(needed)?;
                cache.add_reserved_and_take(needed, len);
            }
        } else {
            return Ok(ByteBudgetPermit::new(self.budget.clone(), len));
        }
        Ok(ByteBudgetPermit::new(self.budget.clone(), len))
    }

    async fn reserve_send_budget(&self, len: usize) -> Option<ByteBudgetPermit> {
        if len == 0 {
            return Some(ByteBudgetPermit::new(self.budget.clone(), 0));
        }
        if len > SMALL_DATA_FRAME_FLUSH_THRESHOLD {
            self.budget.acquire(len, &self.tx).await?;
            return Some(ByteBudgetPermit::new(self.budget.clone(), len));
        }

        loop {
            let needed = {
                let mut cache = self.small_budget_cache.lock();
                match cache.try_take(len) {
                    Ok(()) => return Some(ByteBudgetPermit::new(self.budget.clone(), len)),
                    Err(needed) => {
                        let grant = SMALL_DATA_FRAME_FLUSH_THRESHOLD.max(needed);
                        if self.budget.try_reserve(grant).is_ok() {
                            cache.add_reserved_and_take(grant, len);
                            return Some(ByteBudgetPermit::new(self.budget.clone(), len));
                        }
                        if grant != needed && self.budget.try_reserve(needed).is_ok() {
                            cache.add_reserved_and_take(needed, len);
                            return Some(ByteBudgetPermit::new(self.budget.clone(), len));
                        }
                        needed
                    }
                }
            };
            self.budget.acquire(needed, &self.tx).await?;
            let mut cache = self.small_budget_cache.lock();
            cache.add_reserved_and_take(needed, len);
            return Some(ByteBudgetPermit::new(self.budget.clone(), len));
        }
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

    fn try_reserve(&self, len: usize) -> Result<(), ()> {
        if len == 0 {
            return Ok(());
        }
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
                return Ok(());
            }
        }
    }

    async fn acquire(&self, len: usize, tx: &mpsc::Sender<InboundMessage>) -> Option<()> {
        if len == 0 {
            return Some(());
        }
        loop {
            if self.try_reserve(len).is_ok() {
                return Some(());
            }
            if tx.is_closed() {
                return None;
            }
            let notified = self.notify.notified();
            // Re-check after registering interest so a concurrent release cannot
            // race past us and leave the sender sleeping indefinitely.
            if self.try_reserve(len).is_ok() {
                return Some(());
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
struct SenderBudgetCache {
    budget: Arc<ByteBudget>,
    reserved: usize,
}

impl SenderBudgetCache {
    fn new(budget: Arc<ByteBudget>) -> Self {
        Self {
            budget,
            reserved: 0,
        }
    }

    fn try_take(&mut self, len: usize) -> Result<(), usize> {
        if self.reserved >= len {
            self.reserved -= len;
            Ok(())
        } else {
            Err(len - self.reserved)
        }
    }

    fn add_reserved_and_take(&mut self, added: usize, len: usize) {
        self.reserved += added;
        debug_assert!(self.reserved >= len);
        self.reserved -= len;
    }
}

impl Drop for SenderBudgetCache {
    fn drop(&mut self) {
        self.budget.release(self.reserved);
    }
}

#[derive(Debug)]
struct ByteBudgetPermit {
    budget: Arc<ByteBudget>,
    len: usize,
}

impl ByteBudgetPermit {
    fn new(budget: Arc<ByteBudget>, len: usize) -> Self {
        Self { budget, len }
    }

    fn consume(&mut self, len: usize) {
        let released = len.min(self.len);
        if released == 0 {
            return;
        }
        self.len -= released;
        self.budget.release(released);
    }
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
    let budget = Arc::new(ByteBudget::new(bytes.len().max(1)));
    budget
        .try_reserve(bytes.len().max(1))
        .expect("allocate test permit");
    let permit = ByteBudgetPermit::new(budget, bytes.len().max(1));
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
    fn sender_reuses_reserved_budget_across_small_chunks() {
        let (sender, _rx) = bounded_inbound_channel(8, SMALL_DATA_FRAME_FLUSH_THRESHOLD);
        sender
            .try_send_data(PayloadBuffer::new(vec![1; 1024]))
            .expect("send first small chunk");
        assert_eq!(
            sender.budget.used.load(Ordering::Acquire),
            SMALL_DATA_FRAME_FLUSH_THRESHOLD
        );

        sender
            .try_send_data(PayloadBuffer::new(vec![2; 1024]))
            .expect("reuse reserved budget");
        assert_eq!(
            sender.budget.used.load(Ordering::Acquire),
            SMALL_DATA_FRAME_FLUSH_THRESHOLD
        );
    }

    #[tokio::test]
    async fn dropping_sender_releases_unused_reserved_budget() {
        let (sender, mut rx) = bounded_inbound_channel(8, SMALL_DATA_FRAME_FLUSH_THRESHOLD);
        let budget = sender.budget.clone();
        sender
            .try_send_data(PayloadBuffer::new(vec![1; 1024]))
            .expect("send first small chunk");
        assert_eq!(
            budget.used.load(Ordering::Acquire),
            SMALL_DATA_FRAME_FLUSH_THRESHOLD
        );

        drop(sender);
        assert_eq!(budget.used.load(Ordering::Acquire), 1024);

        let Some(InboundMessage::Data(chunk)) = rx.recv().await else {
            panic!("expected queued chunk");
        };
        drop(chunk);
        assert_eq!(budget.used.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn split_off_releases_consumed_prefix_budget() {
        let (sender, mut rx) = bounded_inbound_channel(8, 4);
        sender
            .try_send_data(PayloadBuffer::new(vec![1, 2, 3, 4]))
            .expect("send chunk");

        let chunk = match rx.recv().await.expect("receive chunk") {
            InboundMessage::Data(chunk) => chunk,
            InboundMessage::Fin => panic!("unexpected fin"),
        };
        let _remaining = chunk.split_off(1);

        assert!(
            sender.try_send_data(PayloadBuffer::new(vec![5])).is_ok(),
            "split-off prefix bytes should release matching budget"
        );
        assert!(
            sender
                .try_send_data(PayloadBuffer::new(vec![6, 7]))
                .is_err(),
            "only the unread tail budget should remain reserved"
        );
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
    fn payload_pool_scans_older_buffer_when_recent_one_is_too_small() {
        let pool = Arc::new(PayloadPool::new(4));
        {
            let mut buffers = pool.buffers.lock();
            buffers.push(Vec::with_capacity(128));
            buffers.push(Vec::with_capacity(8));
        }

        let reused = pool.take(64);
        assert_eq!(reused.bytes.len(), 0);
        assert!(reused.bytes.capacity() >= 128);

        let buffers = pool.buffers.lock();
        assert_eq!(buffers.len(), 1);
        assert!(buffers[0].capacity() >= 8);
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
