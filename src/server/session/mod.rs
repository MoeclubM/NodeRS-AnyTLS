mod channel;
mod frame;
mod io;
mod writer;

use anyhow::{Context, anyhow, bail};
use rustc_hash::FxHashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use tokio::io::{AsyncReadExt, ReadHalf, split};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{debug, warn};

use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::config::OutboundConfig;
use crate::limiter::SharedRateLimiter;

use super::activity::{ActivityTracker, HEARTBEAT_INTERVAL, SESSION_IDLE_TIMEOUT};
use super::padding::PaddingScheme;
use super::rules::RouteRules;
use super::socksaddr::SocksAddr;
use super::traffic::TrafficRecorder;
use super::transport;
use super::uot;
use channel::{ChannelReader, PayloadBuffer, PayloadPool};
use frame::{
    CMD_ALERT, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
    CMD_SETTINGS, CMD_SYN, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, CMD_WASTE, FrameHeader,
    LARGE_INBOUND_SEGMENT_LEN, MAX_STREAMS_PER_SESSION, STREAM_INBOUND_QUEUE_BYTES,
    STREAM_INBOUND_QUEUE_CAPACITY, inbound_segment_len, is_eof, padding_md5, parse_settings,
};
use io::{pump_copy, pump_inbound_to_remote, pump_remote_to_client};
use writer::{FrameWriter, write_frame};

type TlsStream = tokio_rustls::server::TlsStream<TcpStream>;
const AUTHENTICATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const PAYLOAD_POOL_MAX_CACHED: usize = 512;

pub async fn serve_connection(
    mut stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    padding: PaddingScheme,
    route_rules: RouteRules,
    outbound: OutboundConfig,
) -> anyhow::Result<()> {
    let user = tokio::time::timeout(
        AUTHENTICATION_TIMEOUT,
        authenticate(&mut stream, &accounting),
    )
    .await
    .context("authentication timed out")??;
    let lease = accounting.open_session(&user, source)?;
    let control = lease.control();
    let activity = ActivityTracker::new();
    let (reader, writer) = split(stream);
    let session = Session {
        user: user.clone(),
        lease,
        accounting: accounting.clone(),
        padding,
        route_rules,
        outbound,
        activity,
        reader,
        writer: FrameWriter::spawn(writer),
        state: Arc::new(SessionState::default()),
        payload_pool: Arc::new(PayloadPool::new(PAYLOAD_POOL_MAX_CACHED)),
    };
    let result = session.run().await;
    if control.is_cancelled() {
        return Ok(());
    }
    result
}

async fn authenticate(
    stream: &mut TlsStream,
    accounting: &Accounting,
) -> anyhow::Result<UserEntry> {
    let mut hash = [0u8; 32];
    stream
        .read_exact(&mut hash)
        .await
        .context("read password hash")?;
    let padding_length = stream
        .read_u16()
        .await
        .context("read preface padding length")? as usize;
    if padding_length > 0 {
        let mut discard = vec![0u8; padding_length];
        stream
            .read_exact(&mut discard)
            .await
            .context("read preface padding bytes")?;
    }
    accounting
        .find_user_by_hash(&hash)
        .ok_or_else(|| anyhow!("unknown AnyTLS user"))
}

struct Session {
    user: UserEntry,
    lease: SessionLease,
    accounting: Arc<Accounting>,
    padding: PaddingScheme,
    route_rules: RouteRules,
    outbound: OutboundConfig,
    activity: Arc<ActivityTracker>,
    reader: ReadHalf<TlsStream>,
    writer: FrameWriter,
    state: Arc<SessionState>,
    payload_pool: Arc<PayloadPool>,
}

struct SessionState {
    received_settings: AtomicBool,
    peer_version: AtomicU8,
    streams: RwLock<FxHashMap<u32, StreamState>>,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            received_settings: AtomicBool::new(false),
            peer_version: AtomicU8::new(0),
            streams: RwLock::new(FxHashMap::default()),
        }
    }
}

struct StreamState {
    inbound: Option<channel::InboundSender>,
    task: JoinHandle<()>,
}

#[derive(Clone)]
struct StreamContext {
    writer: FrameWriter,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
    route_rules: RouteRules,
    outbound: OutboundConfig,
    activity: Arc<ActivityTracker>,
    upload_traffic: TrafficRecorder,
    download_traffic: TrafficRecorder,
    send_synack: bool,
}

struct TcpStreamContext {
    writer: FrameWriter,
    stream_id: u32,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
    activity: Arc<ActivityTracker>,
    upload_traffic: TrafficRecorder,
    download_traffic: TrafficRecorder,
}

impl Session {
    async fn run(mut self) -> anyhow::Result<()> {
        let control = self.lease.control();
        let state = self.state.clone();
        let writer = self.writer.clone();
        let activity = self.activity.clone();
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let result = loop {
            let header = tokio::select! {
                biased;
                _ = control.cancelled() => break Err(anyhow!("session cancelled")),
                _ = heartbeat.tick() => {
                    let idle_for = activity.idle_for();
                    if idle_for >= SESSION_IDLE_TIMEOUT {
                        break Err(anyhow!("session idle timeout"));
                    }
                    if idle_for >= HEARTBEAT_INTERVAL && can_send_heartbeat(&state) {
                        write_frame(&writer, CMD_HEART_REQUEST, 0, &[]).await?;
                    }
                    continue;
                }
                header = read_header(&mut self.reader) => match header {
                    Ok(header) => header,
                    Err(error) if is_eof(&error) => break Ok(()),
                    Err(error) => break Err(error),
                }
            };
            self.activity.record();
            match header.cmd {
                CMD_PSH => self.handle_psh(header).await?,
                CMD_SYN => self.handle_syn(header.stream_id).await?,
                CMD_FIN => self.handle_fin(header.stream_id).await,
                CMD_WASTE => self.discard(header.length as usize).await?,
                CMD_SETTINGS => self.handle_settings(header.length as usize).await?,
                CMD_ALERT => self.handle_alert(header.length as usize).await?,
                CMD_HEART_REQUEST => {
                    self.write_frame(CMD_HEART_RESPONSE, header.stream_id, &[])
                        .await?
                }
                CMD_HEART_RESPONSE => {}
                CMD_UPDATE_PADDING_SCHEME => self.discard(header.length as usize).await?,
                CMD_SERVER_SETTINGS => self.discard(header.length as usize).await?,
                CMD_SYNACK => self.discard(header.length as usize).await?,
                other => {
                    warn!(cmd = other, user = %self.user.uuid, "unknown session command ignored");
                    if header.length > 0 {
                        self.discard(header.length as usize).await?;
                    }
                }
            }
        };
        self.shutdown().await;
        result
    }

    async fn shutdown(&self) {
        let streams =
            std::mem::take(&mut *self.state.streams.write().expect("streams lock poisoned"));
        for (_, stream) in streams {
            stream.task.abort();
        }
    }

    async fn handle_psh(&mut self, header: FrameHeader) -> anyhow::Result<()> {
        let mut payload = self.payload_pool.take(header.length as usize);
        self.reader
            .read_exact(payload.as_mut_slice())
            .await
            .context("read PSH payload")?;

        let inbound = {
            let streams = self.state.streams.read().expect("streams lock poisoned");
            streams
                .get(&header.stream_id)
                .and_then(|stream| stream.inbound.clone())
        };
        if let Some(inbound) = inbound
            && let Err(error) = self.forward_inbound_payload(inbound, payload).await
        {
            debug!(
                stream_id = header.stream_id,
                user = %self.user.uuid,
                %error,
                "dropping stream after inbound forwarding failure"
            );
            self.drop_stream(header.stream_id).await;
        }
        Ok(())
    }

    async fn handle_syn(&self, stream_id: u32) -> anyhow::Result<()> {
        let received_settings = self.state.received_settings.load(Ordering::Relaxed);
        let peer_version = self.state.peer_version.load(Ordering::Relaxed);
        if !received_settings {
            self.write_frame(CMD_ALERT, 0, b"client did not send its settings")
                .await?;
            bail!("AnyTLS client did not send settings before SYN")
        }
        let stream_gate = {
            let streams = self.state.streams.read().expect("streams lock poisoned");
            (
                streams.contains_key(&stream_id),
                streams.len() >= MAX_STREAMS_PER_SESSION,
            )
        };
        if stream_gate.0 {
            return Ok(());
        }
        if stream_gate.1 {
            let error = format!("too many concurrent streams: limit={MAX_STREAMS_PER_SESSION}");
            if peer_version >= 2 {
                self.write_frame(CMD_SYNACK, stream_id, error.as_bytes())
                    .await?;
            }
            return Ok(());
        }

        let (inbound_tx, inbound_rx) = channel::bounded_inbound_channel(
            STREAM_INBOUND_QUEUE_CAPACITY,
            STREAM_INBOUND_QUEUE_BYTES,
        );

        let writer = self.writer.clone();
        let accounting = self.accounting.clone();
        let user = self.user.clone();
        let control = self.lease.control();
        let context = StreamContext {
            writer: writer.clone(),
            control: control.clone(),
            limiter: None,
            route_rules: self.route_rules.clone(),
            outbound: self.outbound.clone(),
            activity: self.activity.clone(),
            upload_traffic: TrafficRecorder::upload(accounting.clone(), user.id),
            download_traffic: TrafficRecorder::download(accounting, user.id),
            send_synack: peer_version >= 2,
        };
        let state = self.state.clone();
        let task = tokio::spawn(async move {
            let outcome =
                handle_stream(stream_id, ChannelReader::new(inbound_rx), user, context).await;

            let _ = state
                .streams
                .write()
                .expect("streams lock poisoned")
                .remove(&stream_id);

            if let Err(error) = outcome {
                warn!(%error, stream_id, "AnyTLS stream handler failed");
            }
        });

        self.state
            .streams
            .write()
            .expect("streams lock poisoned")
            .insert(
                stream_id,
                StreamState {
                    inbound: Some(inbound_tx),
                    task,
                },
            );
        Ok(())
    }

    async fn handle_fin(&self, stream_id: u32) {
        let inbound = {
            let mut streams = self.state.streams.write().expect("streams lock poisoned");
            streams
                .get_mut(&stream_id)
                .and_then(|stream| stream.inbound.take())
        };
        if let Some(inbound) = inbound {
            let _ = inbound.send_fin().await;
        }
    }

    async fn drop_stream(&self, stream_id: u32) {
        let stream = self
            .state
            .streams
            .write()
            .expect("streams lock poisoned")
            .remove(&stream_id);
        if let Some(stream) = stream {
            stream.task.abort();
            let _ = self.write_frame(CMD_FIN, stream_id, &[]).await;
        }
    }

    async fn handle_settings(&mut self, length: usize) -> anyhow::Result<()> {
        let mut bytes = vec![0u8; length];
        self.reader
            .read_exact(&mut bytes)
            .await
            .context("read settings frame")?;
        let settings = parse_settings(&bytes);
        self.state.received_settings.store(true, Ordering::Relaxed);
        self.state.peer_version.store(
            settings
                .get("v")
                .and_then(|value| value.parse::<u8>().ok())
                .unwrap_or_default(),
            Ordering::Relaxed,
        );

        let md5_mismatch = settings
            .get("padding-md5")
            .map(|value| value != &padding_md5(self.padding.raw_lines()))
            .unwrap_or(false);
        if md5_mismatch {
            self.write_frame(
                CMD_UPDATE_PADDING_SCHEME,
                0,
                self.padding.raw_lines().join("\n").as_bytes(),
            )
            .await?;
        }
        if settings
            .get("v")
            .and_then(|value| value.parse::<u8>().ok())
            .unwrap_or_default()
            >= 2
        {
            self.write_frame(CMD_SERVER_SETTINGS, 0, b"v=2").await?;
        }
        Ok(())
    }

    async fn handle_alert(&mut self, length: usize) -> anyhow::Result<()> {
        let mut bytes = vec![0u8; length];
        self.reader
            .read_exact(&mut bytes)
            .await
            .context("read alert frame")?;
        bail!("peer alert: {}", String::from_utf8_lossy(&bytes))
    }

    async fn discard(&mut self, length: usize) -> anyhow::Result<()> {
        if length == 0 {
            return Ok(());
        }
        let mut discard = vec![0u8; length];
        self.reader
            .read_exact(&mut discard)
            .await
            .context("discard frame payload")?;
        Ok(())
    }

    async fn write_frame(&self, cmd: u8, stream_id: u32, payload: &[u8]) -> anyhow::Result<()> {
        write_frame(&self.writer, cmd, stream_id, payload).await
    }

    async fn forward_inbound_payload(
        &self,
        inbound: channel::InboundSender,
        payload: PayloadBuffer,
    ) -> anyhow::Result<()> {
        if payload.len() <= LARGE_INBOUND_SEGMENT_LEN {
            return self.forward_inbound_segment(&inbound, payload).await;
        }

        let segment_len = inbound_segment_len(payload.len());
        let payload = payload.into_vec();
        for segment in payload.chunks(segment_len) {
            self.forward_inbound_segment(&inbound, PayloadBuffer::new(segment.to_vec()))
                .await?;
        }
        Ok(())
    }

    async fn forward_inbound_segment(
        &self,
        inbound: &channel::InboundSender,
        payload: PayloadBuffer,
    ) -> anyhow::Result<()> {
        match inbound.try_send_data(payload) {
            Ok(()) | Err(channel::TrySendError::Closed) => Ok(()),
            Err(channel::TrySendError::Full(payload)) => {
                let control = self.lease.control();
                tokio::select! {
                    _ = control.cancelled() => Ok(()),
                    result = inbound.send_data(payload) => result,
                }
            }
        }
    }
}

fn can_send_heartbeat(state: &Arc<SessionState>) -> bool {
    state.received_settings.load(Ordering::Relaxed)
}

async fn read_header(reader: &mut ReadHalf<TlsStream>) -> anyhow::Result<FrameHeader> {
    let mut header = [0u8; 7];
    reader
        .read_exact(&mut header)
        .await
        .context("read frame header")?;
    Ok(FrameHeader {
        cmd: header[0],
        stream_id: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        length: u16::from_be_bytes([header[5], header[6]]),
    })
}

async fn handle_stream(
    stream_id: u32,
    mut app_side: ChannelReader,
    user: UserEntry,
    context: StreamContext,
) -> anyhow::Result<()> {
    if context.control.is_cancelled() {
        return Err(anyhow!("session cancelled before stream setup"));
    }
    let destination = match SocksAddr::read_from(&mut app_side)
        .await
        .context("read target address")
    {
        Ok(destination) => destination,
        Err(error) => return Err(error),
    };
    if let Some(version) = uot::version_for(&destination) {
        let request = match uot::read_request(&mut app_side, version).await {
            Ok(request) => request,
            Err(error) => return Err(error),
        };
        let prepared = uot::prepare(request, &context.route_rules, &context.outbound).await;
        let result = async {
            match prepared {
                Ok(prepared) => {
                    if context.send_synack {
                        write_frame(&context.writer, CMD_SYNACK, stream_id, &[]).await?;
                    }
                    let (session_side, app_bridge_side) = tokio::io::duplex(256 * 1024);
                    let (mut session_reader, mut session_writer) = split(session_side);
                    let bridge_control = context.control.clone();
                    let bridge_task = tokio::spawn(async move {
                        pump_copy(
                            &mut app_side,
                            &mut session_writer,
                            bridge_control,
                            None,
                            None,
                            None,
                        )
                        .await
                    });
                    let writer = context.writer.clone();
                    let pump_control = context.control.clone();
                    let pump_activity = context.activity.clone();
                    let outbound_task = tokio::spawn(async move {
                        pump_remote_to_client(
                            &mut session_reader,
                            writer,
                            stream_id,
                            pump_control,
                            None,
                            None,
                            Some(pump_activity),
                        )
                        .await
                    });
                    prepared
                        .run(
                            app_bridge_side,
                            context.control,
                            context.limiter,
                            context.upload_traffic,
                            context.download_traffic,
                        )
                        .await?;
                    bridge_task.abort();
                    outbound_task.abort();
                    debug!(stream_id, user = %user.uuid, version = ?version, "UOT stream closed");
                    Ok(())
                }
                Err(error) => {
                    if context.send_synack {
                        write_frame(
                            &context.writer,
                            CMD_SYNACK,
                            stream_id,
                            error.to_string().as_bytes(),
                        )
                        .await?;
                    }
                    Err(error)
                }
            }
        }
        .await;
        return result;
    }

    if context.route_rules.is_blocked(&destination, "tcp") {
        let error = anyhow!("destination blocked by Xboard route rules: {destination}");
        let result = async {
            if context.send_synack {
                write_frame(
                    &context.writer,
                    CMD_SYNACK,
                    stream_id,
                    error.to_string().as_bytes(),
                )
                .await?;
            }
            Err(error)
        }
        .await;
        return result;
    }

    let mut remote =
        transport::connect_tcp_destination(&destination, &context.route_rules, &context.outbound)
            .await
            .with_context(|| format!("connect remote destination {destination}"));

    let result = async {
        match remote.as_mut() {
            Ok(stream) => {
                if context.send_synack {
                    write_frame(&context.writer, CMD_SYNACK, stream_id, &[]).await?;
                }
                let tcp_context = TcpStreamContext {
                    writer: context.writer.clone(),
                    stream_id,
                    control: context.control,
                    limiter: context.limiter,
                    activity: context.activity,
                    upload_traffic: context.upload_traffic,
                    download_traffic: context.download_traffic,
                };
                handle_tcp_stream(app_side, stream, tcp_context).await
            }
            Err(error) => {
                if context.send_synack {
                    write_frame(
                        &context.writer,
                        CMD_SYNACK,
                        stream_id,
                        error.to_string().as_bytes(),
                    )
                    .await?;
                }
                Err(anyhow!(error.to_string()))
            }
        }
    }
    .await;

    result.map(|(uploaded, downloaded)| {
        debug!(stream_id, user = %user.uuid, destination = %destination, uploaded, downloaded, "stream closed");
    })
}

async fn handle_tcp_stream(
    app_side: ChannelReader,
    stream: &mut TcpStream,
    context: TcpStreamContext,
) -> anyhow::Result<(u64, u64)> {
    let (mut read_b, mut write_b) = stream.split();
    let (pending, inbound_rx, inbound_finished) = app_side.into_parts();
    let upload = pump_inbound_to_remote(
        pending,
        inbound_rx,
        inbound_finished,
        &mut write_b,
        context.control.clone(),
        Some(context.upload_traffic),
    );
    let download = pump_remote_to_client(
        &mut read_b,
        context.writer,
        context.stream_id,
        context.control,
        context.limiter,
        Some(context.download_traffic),
        Some(context.activity),
    );
    tokio::try_join!(upload, download)
}

#[cfg(test)]
mod tests {
    use super::channel::{ChannelReader, InboundMessage, test_chunk};
    use super::frame::{
        CMD_PSH, CMD_SYNACK, MAX_FRAME_PAYLOAD_LEN, PayloadTier, download_coalesce_target,
        parse_settings, payload_tier, should_flush_frame, upload_batch_policy,
    };
    use super::io::{advance_chunk_batch, chunk_batch_slices, coalesce_download_reads, pump_copy};
    use crate::accounting::{Accounting, SessionControl};
    use crate::server::traffic::TrafficRecorder;
    use std::collections::VecDeque as TestVecDeque;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use std::time::Duration;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
    use tokio::sync::mpsc;
    struct SegmentedReader {
        segments: TestVecDeque<Vec<u8>>,
    }

    impl SegmentedReader {
        fn new(segments: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                segments: segments.into_iter().collect(),
            }
        }
    }

    impl AsyncRead for SegmentedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let Some(segment) = self.segments.pop_front() else {
                return Poll::Pending;
            };
            let to_copy = segment.len().min(buf.remaining());
            buf.put_slice(&segment[..to_copy]);
            if to_copy < segment.len() {
                self.segments.push_front(segment[to_copy..].to_vec());
            }
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn parses_settings_lines() {
        let settings = parse_settings(b"v=2\nclient=test");
        assert_eq!(settings.get("v"), Some(&"2".to_string()));
        assert_eq!(settings.get("client"), Some(&"test".to_string()));
    }

    #[test]
    fn flushes_control_and_small_payload_frames() {
        assert!(should_flush_frame(CMD_SYNACK, 0));
        assert!(should_flush_frame(CMD_PSH, 1024));
        assert!(!should_flush_frame(CMD_PSH, 8192));
    }

    #[test]
    fn classifies_payload_tiers() {
        assert_eq!(payload_tier(512), PayloadTier::Small);
        assert_eq!(payload_tier(8 * 1024), PayloadTier::Medium);
        assert_eq!(payload_tier(32 * 1024), PayloadTier::Large);
    }

    #[test]
    fn derives_size_specific_batch_and_download_policies() {
        let small = upload_batch_policy(512);
        let medium = upload_batch_policy(8 * 1024);
        let large = upload_batch_policy(32 * 1024);
        assert!(small.max_iovecs > medium.max_iovecs);
        assert!(large.max_iovecs < medium.max_iovecs);
        assert!(large.max_bytes > medium.max_bytes);
        assert!(download_coalesce_target(1024).is_some());
        assert!(download_coalesce_target(8 * 1024).is_none());
        assert!(download_coalesce_target(32 * 1024).is_none());
    }

    #[test]
    fn caps_frame_payload_to_protocol_limit() {
        assert_eq!(MAX_FRAME_PAYLOAD_LEN, u16::MAX as usize);
    }

    #[tokio::test]
    async fn pump_copy_records_traffic_before_stream_close() {
        let accounting = Accounting::new();
        let control = SessionControl::new();
        let (mut source_reader, mut source_writer) = tokio::io::duplex(64);
        let (mut sink_writer, mut sink_reader) = tokio::io::duplex(64);

        let task = tokio::spawn({
            let control = control.clone();
            let accounting = accounting.clone();
            async move {
                pump_copy(
                    &mut source_reader,
                    &mut sink_writer,
                    control,
                    None,
                    Some(TrafficRecorder::upload(accounting, 7)),
                    None,
                )
                .await
            }
        });
        source_writer
            .write_all(b"hello")
            .await
            .expect("write source");
        let mut buf = [0u8; 5];
        sink_reader.read_exact(&mut buf).await.expect("read sink");
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(accounting.snapshot_traffic(0).remove(&7), Some([5, 0]));

        drop(source_writer);
        let transferred = task.await.expect("join pump").expect("pump succeeds");
        assert_eq!(transferred, 5);
    }

    #[tokio::test]
    async fn channel_reader_coalesces_multiple_chunks() {
        let (tx, rx) = mpsc::channel(4);
        tx.send(InboundMessage::Data(test_chunk(b"hello")))
            .await
            .expect("send first chunk");
        tx.send(InboundMessage::Data(test_chunk(b"world")))
            .await
            .expect("send second chunk");
        drop(tx);

        let mut reader = ChannelReader::new(rx);
        let mut buf = [0u8; 10];
        reader
            .read_exact(&mut buf)
            .await
            .expect("read combined chunk");
        assert_eq!(&buf, b"helloworld");
    }

    #[tokio::test]
    async fn coalesces_immediately_available_download_reads() {
        let mut reader = SegmentedReader::new([vec![1u8; 1024], vec![2u8; 1024]]);
        let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];

        let first = reader
            .read(&mut buffer[..1024])
            .await
            .expect("read first chunk");
        assert_eq!(first, 1024);

        let (filled, saw_eof) = coalesce_download_reads(&mut reader, &mut buffer, first, 2048)
            .await
            .expect("coalesce available reads");
        assert_eq!(filled, 2048);
        assert!(!saw_eof);
        assert!(buffer[..1024].iter().all(|byte| *byte == 1));
        assert!(buffer[1024..2048].iter().all(|byte| *byte == 2));
    }

    #[test]
    fn advance_chunk_batch_handles_partial_write() {
        let mut chunks =
            std::collections::VecDeque::from([test_chunk(b"hello"), test_chunk(b"world")]);
        let mut front_offset = 0;
        advance_chunk_batch(&mut chunks, &mut front_offset, 7);
        assert_eq!(chunks.len(), 1);
        assert_eq!(front_offset, 2);
        assert_eq!(chunks.front().expect("remaining chunk").bytes(), b"world");
    }

    #[test]
    fn chunk_batch_slices_respects_front_offset() {
        let chunks = std::collections::VecDeque::from([test_chunk(b"hello"), test_chunk(b"world")]);
        let slices = chunk_batch_slices(&chunks, 2, upload_batch_policy(5));
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0].len(), 3);
        assert_eq!(slices[1].len(), 5);
    }
}
