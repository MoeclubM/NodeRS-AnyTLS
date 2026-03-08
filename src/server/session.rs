use anyhow::{Context, anyhow, bail};
use md5::{Digest as Md5Digest, Md5};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf, split,
};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::accounting::{Accounting, SessionControl, SessionLease, UserEntry};
use crate::config::OutboundConfig;
use crate::limiter::SharedRateLimiter;

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
    let (reader, writer) = split(stream);
    let session = Session {
        user: user.clone(),
        lease,
        accounting: accounting.clone(),
        padding,
        route_rules,
        outbound,
        reader: Mutex::new(reader),
        writer: Arc::new(Mutex::new(writer)),
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
    reader: Mutex<ReadHalf<TlsStream>>,
    writer: Arc<Mutex<WriteHalf<TlsStream>>>,
    state: Arc<Mutex<SessionState>>,
}

#[derive(Default)]
struct SessionState {
    received_settings: bool,
    peer_version: u8,
    streams: HashMap<u32, StreamState>,
}

struct StreamState {
    inbound: Arc<Mutex<WriteHalf<DuplexStream>>>,
    outbound_task: JoinHandle<()>,
}

struct StreamOutcome {
    established: bool,
    result: anyhow::Result<()>,
}

#[derive(Clone)]
struct StreamContext {
    writer: Arc<Mutex<WriteHalf<TlsStream>>>,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
    route_rules: RouteRules,
    outbound: OutboundConfig,
    upload_traffic: TrafficRecorder,
    download_traffic: TrafficRecorder,
    send_synack: bool,
}

impl Session {
    async fn run(self) -> anyhow::Result<()> {
        let control = self.lease.control();
        let result = loop {
            let header = tokio::select! {
                biased;
                _ = control.cancelled() => break Err(anyhow!("session cancelled")),
                header = self.read_header() => match header {
                    Ok(header) => header,
                    Err(error) if is_eof(&error) => break Ok(()),
                    Err(error) => break Err(error),
                }
            };
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
        let streams = {
            let mut state = self.state.lock().await;
            std::mem::take(&mut state.streams)
        };
        for (_, stream) in streams {
            stream.outbound_task.abort();
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
                .map(|stream| stream.inbound.clone())
        };
        if let Some(inbound) = inbound {
            inbound
                .lock()
                .await
                .write_all(&payload)
                .await
                .context("forward PSH payload")?;
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

        let (session_side, app_side) = tokio::io::duplex(64 * 1024);
        let (session_reader, session_writer) = split(session_side);
        let inbound = Arc::new(Mutex::new(session_writer));
        let writer = self.writer.clone();
        let control = self.lease.control();
        let outbound_task = tokio::spawn(async move {
            if let Err(error) =
                pump_remote_to_client(session_reader, writer, stream_id, control).await
            {
                debug!(%error, stream_id, "stream outbound pump finished with error");
            }
        });

        self.state.lock().await.streams.insert(
            stream_id,
            StreamState {
                inbound,
                outbound_task,
            },
        );

        let writer = self.writer.clone();
        let accounting = self.accounting.clone();
        let user = self.user.clone();
        let control = self.lease.control();
        let context = StreamContext {
            writer: writer.clone(),
            control: control.clone(),
            limiter: self.lease.limiter(),
            route_rules: self.route_rules.clone(),
            outbound: self.outbound.clone(),
            upload_traffic: TrafficRecorder::upload(accounting.clone(), user.id),
            download_traffic: TrafficRecorder::download(accounting, user.id),
            send_synack: peer_version >= 2,
        };
        let state = self.state.clone();
        tokio::spawn(async move {
            let outcome = handle_stream(stream_id, app_side, user, context).await;

            if let Some(stream_state) = state.lock().await.streams.remove(&stream_id)
                && !outcome.established
                && !stream_state.outbound_task.is_finished()
            {
                stream_state.outbound_task.abort();
            }

            if let Err(error) = outcome.result {
                warn!(%error, stream_id, "AnyTLS stream handler failed");
            }
        });
        Ok(())
    }

    async fn handle_fin(&self, stream_id: u32) {
        if let Some(state) = self.state.lock().await.streams.remove(&stream_id) {
            state.outbound_task.abort();
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
    mut app_side: DuplexStream,
    user: UserEntry,
    context: StreamContext,
) -> StreamOutcome {
    if context.control.is_cancelled() {
        return StreamOutcome {
            established: false,
            result: Err(anyhow!("session cancelled before stream setup")),
        };
    }
    let destination = match SocksAddr::read_from(&mut app_side)
        .await
        .context("read target address")
    {
        Ok(destination) => destination,
        Err(error) => {
            return StreamOutcome {
                established: false,
                result: Err(error),
            };
        }
    };
    if let Some(version) = uot::version_for(&destination) {
        let request = match uot::read_request(&mut app_side, version).await {
            Ok(request) => request,
            Err(error) => {
                return StreamOutcome {
                    established: false,
                    result: Err(error),
                };
            }
        };
        let prepared = uot::prepare(request, &context.route_rules, &context.outbound).await;
        let established = prepared.is_ok();
        let result = async {
            match prepared {
                Ok(prepared) => {
                    if context.send_synack {
                        write_frame(&context.writer, CMD_SYNACK, stream_id, &[]).await?;
                    }
                    prepared
                        .run(
                            app_side,
                            context.control,
                            context.limiter,
                            context.upload_traffic,
                            context.download_traffic,
                        )
                        .await?;
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
        return StreamOutcome {
            established,
            result,
        };
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
        return StreamOutcome {
            established: false,
            result,
        };
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
                handle_tcp_stream(
                    app_side,
                    stream,
                    context.control,
                    context.limiter,
                    context.upload_traffic,
                    context.download_traffic,
                )
                .await
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

    StreamOutcome {
        established: remote.is_ok(),
        result: result.map(|(uploaded, downloaded)| {
            info!(stream_id, user = %user.uuid, destination = %destination, uploaded, downloaded, "stream closed");
        }),
    }
}

async fn handle_tcp_stream(
    app_side: DuplexStream,
    stream: &mut TcpStream,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
    upload_traffic: TrafficRecorder,
    download_traffic: TrafficRecorder,
) -> anyhow::Result<(u64, u64)> {
    let (mut read_a, mut write_a) = tokio::io::split(app_side);
    let (mut read_b, mut write_b) = stream.split();
    let upload = pump_copy(
        &mut read_a,
        &mut write_b,
        control.clone(),
        limiter.clone(),
        Some(upload_traffic),
    );
    let download = pump_copy(
        &mut read_b,
        &mut write_a,
        control,
        limiter,
        Some(download_traffic),
    );
    tokio::try_join!(upload, download)
}

async fn pump_copy<R, W>(
    reader: &mut R,
    writer: &mut W,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
    traffic: Option<TrafficRecorder>,
) -> anyhow::Result<u64>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 16 * 1024];
    let mut total = 0u64;
    loop {
        if control.is_cancelled() {
            return Ok(total);
        }
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(total),
            read = reader.read(&mut buffer) => read.context("read throttled chunk")?,
        };
        if read == 0 {
            let _ = writer.shutdown().await;
            return Ok(total);
        }
        if let Some(limiter) = &limiter {
            limiter.consume(read).await;
            if control.is_cancelled() {
                return Ok(total);
            }
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
    }
}

async fn pump_remote_to_client(
    mut session_reader: ReadHalf<DuplexStream>,
    writer: Arc<Mutex<WriteHalf<TlsStream>>>,
    stream_id: u32,
    control: Arc<SessionControl>,
) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        if control.is_cancelled() {
            return Ok(());
        }
        let read = tokio::select! {
            _ = control.cancelled() => return Ok(()),
            read = session_reader.read(&mut buffer) => read?,
        };
        if read == 0 {
            write_frame(&writer, CMD_FIN, stream_id, &[]).await?;
            return Ok(());
        }
        write_frame(&writer, CMD_PSH, stream_id, &buffer[..read]).await?;
    }
}

async fn write_frame(
    writer: &Arc<Mutex<WriteHalf<TlsStream>>>,
    cmd: u8,
    stream_id: u32,
    payload: &[u8],
) -> anyhow::Result<()> {
    if payload.len() > u16::MAX as usize {
        bail!("payload too large: {}", payload.len());
    }
    let mut frame = Vec::with_capacity(7 + payload.len());
    frame.push(cmd);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    let mut writer = writer.lock().await;
    writer
        .write_all(&frame)
        .await
        .context("write session frame")?;
    writer.flush().await.context("flush session frame")?;
    Ok(())
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
