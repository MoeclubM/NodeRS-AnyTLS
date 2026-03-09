use anyhow::{Context, anyhow, bail};
use md5::{Digest as Md5Digest, Md5};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf, split,
};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};

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

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_ALERT: u8 = 5;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;
const MAX_FRAME_PAYLOAD_LEN: usize = u16::MAX as usize;
const SMALL_DATA_FRAME_FLUSH_THRESHOLD: usize = 4 * 1024;

type TlsStream = tokio_rustls::server::TlsStream<TcpStream>;

pub async fn serve_connection(
    mut stream: TlsStream,
    source: SocketAddr,
    accounting: Arc<Accounting>,
    padding: PaddingScheme,
    route_rules: RouteRules,
    outbound: OutboundConfig,
) -> anyhow::Result<()> {
    let user = authenticate(&mut stream, &accounting).await?;
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
        reader: Mutex::new(reader),
        writer: FrameWriter::spawn(writer),
        state: Arc::new(Mutex::new(SessionState::default())),
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
    reader: Mutex<ReadHalf<TlsStream>>,
    writer: FrameWriter,
    state: Arc<Mutex<SessionState>>,
}

#[derive(Default)]
struct SessionState {
    received_settings: bool,
    peer_version: u8,
    streams: HashMap<u32, StreamState>,
}

struct StreamState {
    inbound: Option<mpsc::Sender<InboundMessage>>,
    task: JoinHandle<()>,
}

#[derive(Clone)]
struct FrameWriter {
    inner: Arc<Mutex<WriteHalf<TlsStream>>>,
}

enum InboundMessage {
    Data(Vec<u8>),
    Fin,
}

struct ChannelReader {
    rx: mpsc::Receiver<InboundMessage>,
    current: Vec<u8>,
    offset: usize,
    finished: bool,
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

impl FrameWriter {
    fn spawn(writer: WriteHalf<TlsStream>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(writer)),
        }
    }

    async fn send(&self, cmd: u8, stream_id: u32, payload: &[u8]) -> anyhow::Result<()> {
        if payload.len() > MAX_FRAME_PAYLOAD_LEN {
            bail!("payload too large: {}", payload.len());
        }
        let mut header = [0u8; 7];
        header[0] = cmd;
        header[1..5].copy_from_slice(&stream_id.to_be_bytes());
        header[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let mut writer = self.inner.lock().await;
        writer
            .write_all(&header)
            .await
            .context("write session frame header")?;
        if !payload.is_empty() {
            writer
                .write_all(payload)
                .await
                .context("write session frame payload")?;
        }
        if should_flush_frame(cmd, payload.len()) {
            writer.flush().await.context("flush session frame")?;
        }
        Ok(())
    }
}

impl ChannelReader {
    fn new(rx: mpsc::Receiver<InboundMessage>) -> Self {
        Self {
            rx,
            current: Vec::new(),
            offset: 0,
            finished: false,
        }
    }
}

impl AsyncRead for ChannelReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if self.offset < self.current.len() {
                let remaining = &self.current[self.offset..];
                let to_copy = remaining.len().min(buf.remaining());
                buf.put_slice(&remaining[..to_copy]);
                self.offset += to_copy;
                if self.offset >= self.current.len() {
                    self.current.clear();
                    self.offset = 0;
                }
                return Poll::Ready(Ok(()));
            }

            if self.finished {
                return Poll::Ready(Ok(()));
            }

            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(InboundMessage::Data(chunk))) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                Poll::Ready(Some(InboundMessage::Fin)) | Poll::Ready(None) => {
                    self.finished = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl Session {
    async fn run(self) -> anyhow::Result<()> {
        let control = self.lease.control();
        let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
        heartbeat.set_missed_tick_behavior(MissedTickBehavior::Delay);
        heartbeat.tick().await;
        let result = loop {
            let header = tokio::select! {
                biased;
                _ = control.cancelled() => break Err(anyhow!("session cancelled")),
                _ = heartbeat.tick() => {
                    let idle_for = self.activity.idle_for();
                    if idle_for >= SESSION_IDLE_TIMEOUT {
                        break Err(anyhow!("session idle timeout"));
                    }
                    if idle_for >= HEARTBEAT_INTERVAL && self.can_send_heartbeat().await {
                        self.write_frame(CMD_HEART_REQUEST, 0, &[]).await?;
                    }
                    continue;
                }
                header = self.read_header() => match header {
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

    async fn can_send_heartbeat(&self) -> bool {
        self.state.lock().await.received_settings
    }

    async fn shutdown(&self) {
        let streams = {
            let mut state = self.state.lock().await;
            std::mem::take(&mut state.streams)
        };
        for (_, stream) in streams {
            stream.task.abort();
        }
    }

    async fn handle_psh(&self, header: FrameHeader) -> anyhow::Result<()> {
        let mut payload = vec![0u8; header.length as usize];
        self.reader
            .lock()
            .await
            .read_exact(&mut payload)
            .await
            .context("read PSH payload")?;

        let inbound = {
            let state = self.state.lock().await;
            state
                .streams
                .get(&header.stream_id)
                .and_then(|stream| stream.inbound.clone())
        };
        if let Some(inbound) = inbound {
            let _ = inbound.send(InboundMessage::Data(payload)).await;
        }
        Ok(())
    }

    async fn handle_syn(&self, stream_id: u32) -> anyhow::Result<()> {
        let peer_version = {
            let state = self.state.lock().await;
            if !state.received_settings {
                drop(state);
                self.write_frame(CMD_ALERT, 0, b"client did not send its settings")
                    .await?;
                bail!("AnyTLS client did not send settings before SYN")
            }
            if state.streams.contains_key(&stream_id) {
                return Ok(());
            }
            state.peer_version
        };

        let (inbound_tx, inbound_rx) = mpsc::channel(256);

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

            let _ = state.lock().await.streams.remove(&stream_id);

            if let Err(error) = outcome {
                warn!(%error, stream_id, "AnyTLS stream handler failed");
            }
        });

        self.state.lock().await.streams.insert(
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
            let mut state = self.state.lock().await;
            state
                .streams
                .get_mut(&stream_id)
                .and_then(|stream| stream.inbound.take())
        };
        if let Some(inbound) = inbound {
            let _ = inbound.send(InboundMessage::Fin).await;
        }
    }

    async fn handle_settings(&self, length: usize) -> anyhow::Result<()> {
        let mut bytes = vec![0u8; length];
        self.reader
            .lock()
            .await
            .read_exact(&mut bytes)
            .await
            .context("read settings frame")?;
        let settings = parse_settings(&bytes);
        let mut state = self.state.lock().await;
        state.received_settings = true;
        state.peer_version = settings
            .get("v")
            .and_then(|value| value.parse::<u8>().ok())
            .unwrap_or_default();
        drop(state);

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

    async fn handle_alert(&self, length: usize) -> anyhow::Result<()> {
        let mut bytes = vec![0u8; length];
        self.reader
            .lock()
            .await
            .read_exact(&mut bytes)
            .await
            .context("read alert frame")?;
        bail!("peer alert: {}", String::from_utf8_lossy(&bytes))
    }

    async fn discard(&self, length: usize) -> anyhow::Result<()> {
        if length == 0 {
            return Ok(());
        }
        let mut discard = vec![0u8; length];
        self.reader
            .lock()
            .await
            .read_exact(&mut discard)
            .await
            .context("discard frame payload")?;
        Ok(())
    }

    async fn read_header(&self) -> anyhow::Result<FrameHeader> {
        let mut header = [0u8; 7];
        self.reader
            .lock()
            .await
            .read_exact(&mut header)
            .await
            .context("read frame header")?;
        Ok(FrameHeader {
            cmd: header[0],
            stream_id: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
            length: u16::from_be_bytes([header[5], header[6]]),
        })
    }

    async fn write_frame(&self, cmd: u8, stream_id: u32, payload: &[u8]) -> anyhow::Result<()> {
        write_frame(&self.writer, cmd, stream_id, payload).await
    }
}

#[derive(Debug, Clone, Copy)]
struct FrameHeader {
    cmd: u8,
    stream_id: u32,
    length: u16,
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
                    info!(stream_id, user = %user.uuid, version = ?version, "UOT stream closed");
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
        info!(stream_id, user = %user.uuid, destination = %destination, uploaded, downloaded, "stream closed");
    })
}

async fn handle_tcp_stream(
    mut app_side: ChannelReader,
    stream: &mut TcpStream,
    context: TcpStreamContext,
) -> anyhow::Result<(u64, u64)> {
    let (mut read_b, mut write_b) = stream.split();
    let upload = pump_copy(
        &mut app_side,
        &mut write_b,
        context.control.clone(),
        None,
        Some(context.upload_traffic),
        None,
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

async fn pump_copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
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
        let chunk_len = limiter
            .as_ref()
            .map(|limiter| limiter.chunk_size(buffer.len()))
            .unwrap_or(buffer.len());
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(total),
            read = reader.read(&mut buffer[..chunk_len]) => read.context("read throttled chunk")?,
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        tokio::select! {
            _ = control.cancelled() => return Ok(total),
            result = writer.write_all(&buffer[..read]) => {
                result.context("write throttled chunk")?;
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
        if let Some(limiter) = &limiter {
            tokio::select! {
                _ = control.cancelled() => return Ok(total),
                _ = limiter.consume(read) => {}
            }
        }
    }
}

async fn pump_remote_to_client<R>(
    reader: &mut R,
    writer: FrameWriter,
    stream_id: u32,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
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
        let chunk_len = limiter
            .as_ref()
            .map(|limiter| limiter.chunk_size(buffer.len()))
            .unwrap_or(buffer.len());
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(total),
            read = reader.read(&mut buffer[..chunk_len]) => read?,
        };
        if read == 0 {
            write_frame(&writer, CMD_FIN, stream_id, &[]).await?;
            return Ok(total);
        }
        write_frame(&writer, CMD_PSH, stream_id, &buffer[..read]).await?;
        let transferred = read as u64;
        total += transferred;
        if let Some(traffic) = traffic.as_ref() {
            traffic.record(transferred);
        }
        if let Some(activity) = activity.as_ref() {
            activity.record();
        }
        if let Some(limiter) = &limiter {
            tokio::select! {
                _ = control.cancelled() => return Ok(total),
                _ = limiter.consume(read) => {}
            }
        }
    }
}

async fn write_frame(
    writer: &FrameWriter,
    cmd: u8,
    stream_id: u32,
    payload: &[u8],
) -> anyhow::Result<()> {
    writer.send(cmd, stream_id, payload).await
}

fn should_flush_frame(_cmd: u8, _payload_len: usize) -> bool {
    !matches!(_cmd, CMD_PSH) || _payload_len <= SMALL_DATA_FRAME_FLUSH_THRESHOLD
}

fn parse_settings(bytes: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn padding_md5(lines: &[String]) -> String {
    let mut hasher = Md5::new();
    hasher.update(lines.join("\n").as_bytes());
    hex::encode(hasher.finalize())
}

fn is_eof(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::UnexpectedEof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
}
