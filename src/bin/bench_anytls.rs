use anyhow::{Context, bail, ensure};
use md5::{Digest as Md5Digest, Md5};
use rand::RngExt;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf, split};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsConnector;

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

const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
const MAX_FRAME_PAYLOAD_LEN: usize = u16::MAX as usize;
const DEFAULT_PADDING_SCHEME: &[&str] = &[
    "stop=8",
    "0=30-30",
    "1=100-400",
    "2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000",
    "3=9-9,500-1000",
    "4=500-1000",
    "5=500-1000",
    "6=500-1000",
    "7=500-1000",
];
const DEFAULT_CHUNK_SIZE: usize = 32 * 1024;
const DEFAULT_UDP_CHUNK_SIZE: usize = 1200;
const DEFAULT_DURATION_SECONDS: u64 = 10;
const DEFAULT_IDLE_SECONDS: u64 = 35;
const DEFAULT_PARALLEL: usize = 1;
const DEFAULT_SCENARIO_PARALLEL: usize = 8;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const SYNACK_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);

type ClientTlsStream = tokio_rustls::client::TlsStream<TcpStream>;
type SharedWriter = Arc<Mutex<WriteHalf<ClientTlsStream>>>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum BenchMode {
    Upload,
    Download,
    UdpUpload,
    UdpDownload,
    Idle,
}

impl BenchMode {
    fn label(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::UdpUpload => "udp-upload",
            Self::UdpDownload => "udp-download",
            Self::Idle => "idle",
        }
    }

    fn is_udp(self) -> bool {
        matches!(self, Self::UdpUpload | Self::UdpDownload)
    }
}

#[derive(Clone)]
struct ClientOptions {
    server: SocketAddr,
    sni: String,
    users: Vec<String>,
    target: SocksTarget,
    mode: BenchMode,
    duration: Duration,
    parallel: usize,
    chunk_size: usize,
    insecure: bool,
}

impl ClientOptions {
    fn user_for(&self, worker_id: usize) -> &str {
        let index = worker_id % self.users.len();
        &self.users[index]
    }
}

#[derive(Clone)]
struct ScenarioOptions {
    server: SocketAddr,
    sni: String,
    users: Vec<String>,
    tcp_upload_target: Option<SocksTarget>,
    tcp_download_target: Option<SocksTarget>,
    udp_upload_target: Option<SocksTarget>,
    udp_download_target: Option<SocksTarget>,
    duration: Duration,
    idle_duration: Duration,
    parallel: usize,
    chunk_size: usize,
    udp_chunk_size: usize,
    insecure: bool,
    suite: ScenarioSuite,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScenarioSuite {
    All,
    Tcp,
    Udp,
    Idle,
}

impl ScenarioSuite {
    fn includes_tcp(self) -> bool {
        matches!(self, Self::All | Self::Tcp)
    }

    fn includes_udp(self) -> bool {
        matches!(self, Self::All | Self::Udp)
    }

    fn includes_idle(self) -> bool {
        matches!(self, Self::All | Self::Idle)
    }
}

#[derive(Clone, Copy)]
struct ImpairmentProfile {
    latency: Duration,
    jitter: Duration,
    loss_rate: f64,
    stall_rate: f64,
    stall: Duration,
}

#[derive(Clone)]
enum Command {
    Sink {
        listen: SocketAddr,
    },
    Source {
        listen: SocketAddr,
        chunk_size: usize,
    },
    UdpSink {
        listen: SocketAddr,
    },
    UdpSource {
        listen: SocketAddr,
        payload_size: usize,
    },
    TcpProxy {
        listen: SocketAddr,
        upstream: SocketAddr,
        impairment: ImpairmentProfile,
    },
    UdpProxy {
        listen: SocketAddr,
        upstream: SocketAddr,
        impairment: ImpairmentProfile,
    },
    Client(ClientOptions),
    Scenario(ScenarioOptions),
}

#[derive(Clone)]
enum SocksTarget {
    Ip(SocketAddr),
    Domain(String, u16),
}

#[derive(Default)]
struct WorkerResult {
    uploaded: u64,
    downloaded: u64,
    connect_ms: Option<u64>,
    handshake_ms: Option<u64>,
    synack_ms: Option<u64>,
    first_byte_ms: Option<u64>,
}

struct BenchSummary {
    mode: BenchMode,
    parallel: usize,
    duration: Duration,
    users: usize,
    uploaded: u64,
    downloaded: u64,
    connect_ms: Option<f64>,
    handshake_ms: Option<f64>,
    synack_ms: Option<f64>,
    first_byte_ms: Option<f64>,
}

impl BenchSummary {
    fn print(&self) {
        let elapsed = self.duration.as_secs_f64().max(0.001);
        println!(
            "mode={} parallel={} users={} duration={}s uploaded={} MiB ({:.2} Mbps) downloaded={} MiB ({:.2} Mbps)",
            self.mode.label(),
            self.parallel,
            self.users,
            self.duration.as_secs(),
            mib(self.uploaded),
            mbps(self.uploaded, elapsed),
            mib(self.downloaded),
            mbps(self.downloaded, elapsed),
        );
        if let Some(value) = self.connect_ms {
            println!("avg tcp connect: {:.2} ms", value);
        }
        if let Some(value) = self.handshake_ms {
            println!("avg tls handshake: {:.2} ms", value);
        }
        if let Some(value) = self.synack_ms {
            println!("avg stream synack: {:.2} ms", value);
        }
        if let Some(value) = self.first_byte_ms {
            println!("avg first byte: {:.2} ms", value);
        }
    }
}

struct SessionState {
    stream_id: u32,
    syn_sent_at: StdMutex<Instant>,
    synack_ok: AtomicBool,
    finished: AtomicBool,
    upload_bytes: AtomicU64,
    download_bytes: AtomicU64,
    synack_ms: AtomicU64,
    first_byte_ms: AtomicU64,
    error: Mutex<Option<String>>,
    synack_notify: Notify,
    finish_notify: Notify,
}

impl SessionState {
    fn new(stream_id: u32) -> Arc<Self> {
        Arc::new(Self {
            stream_id,
            syn_sent_at: StdMutex::new(Instant::now()),
            synack_ok: AtomicBool::new(false),
            finished: AtomicBool::new(false),
            upload_bytes: AtomicU64::new(0),
            download_bytes: AtomicU64::new(0),
            synack_ms: AtomicU64::new(0),
            first_byte_ms: AtomicU64::new(0),
            error: Mutex::new(None),
            synack_notify: Notify::new(),
            finish_notify: Notify::new(),
        })
    }

    async fn set_error(&self, error: impl Into<String>) {
        let mut guard = self.error.lock().await;
        if guard.is_none() {
            *guard = Some(error.into());
        }
        self.finished.store(true, Ordering::SeqCst);
        self.synack_notify.notify_waiters();
        self.finish_notify.notify_waiters();
    }

    async fn current_error(&self) -> Option<String> {
        self.error.lock().await.clone()
    }

    fn is_finished(&self) -> bool {
        self.finished.load(Ordering::SeqCst)
    }

    fn set_synack_ok(&self) {
        self.synack_ok.store(true, Ordering::SeqCst);
        let elapsed = self
            .syn_sent_at
            .lock()
            .expect("syn timestamp lock poisoned")
            .elapsed()
            .as_millis() as u64;
        self.synack_ms.store(elapsed.max(1), Ordering::SeqCst);
        self.synack_notify.notify_waiters();
    }

    fn record_upload(&self, bytes: usize) {
        if bytes > 0 {
            self.upload_bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        }
    }

    fn record_download(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        self.download_bytes
            .fetch_add(bytes as u64, Ordering::Relaxed);
        if self.first_byte_ms.load(Ordering::Relaxed) == 0 {
            let elapsed = self
                .syn_sent_at
                .lock()
                .expect("syn timestamp lock poisoned")
                .elapsed()
                .as_millis() as u64;
            let _ = self.first_byte_ms.compare_exchange(
                0,
                elapsed.max(1),
                Ordering::SeqCst,
                Ordering::SeqCst,
            );
        }
    }

    fn finish(&self) {
        self.finished.store(true, Ordering::SeqCst);
        self.finish_notify.notify_waiters();
    }
}

struct InsecureVerifier;

impl std::fmt::Debug for InsecureVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("InsecureVerifier")
    }
}

impl ServerCertVerifier for InsecureVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let command = parse_args(env::args().skip(1).collect())?;
    match command {
        Command::Sink { listen } => run_sink(listen).await,
        Command::Source { listen, chunk_size } => run_source(listen, chunk_size).await,
        Command::UdpSink { listen } => run_udp_sink(listen).await,
        Command::UdpSource {
            listen,
            payload_size,
        } => run_udp_source(listen, payload_size).await,
        Command::TcpProxy {
            listen,
            upstream,
            impairment,
        } => run_tcp_proxy(listen, upstream, impairment).await,
        Command::UdpProxy {
            listen,
            upstream,
            impairment,
        } => run_udp_proxy(listen, upstream, impairment).await,
        Command::Client(options) => {
            let summary = run_client(options).await?;
            summary.print();
            Ok(())
        }
        Command::Scenario(options) => run_scenarios(options).await,
    }
}

async fn run_sink(listen: SocketAddr) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind sink on {listen}"))?;
    println!("sink listening on {}", listener.local_addr()?);
    loop {
        let (mut stream, peer) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 64 * 1024];
            loop {
                match stream.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(error) => {
                        eprintln!("sink connection {peer} error: {error}");
                        break;
                    }
                }
            }
        });
    }
}

async fn run_source(listen: SocketAddr, chunk_size: usize) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind source on {listen}"))?;
    println!("source listening on {}", listener.local_addr()?);
    loop {
        let (mut stream, peer) = listener.accept().await?;
        let _ = stream.set_nodelay(true);
        let buffer = vec![0u8; chunk_size.clamp(1024, MAX_FRAME_PAYLOAD_LEN)];
        tokio::spawn(async move {
            loop {
                if let Err(error) = stream.write_all(&buffer).await {
                    if error.kind() != std::io::ErrorKind::BrokenPipe {
                        eprintln!("source connection {peer} error: {error}");
                    }
                    break;
                }
            }
        });
    }
}

async fn run_udp_sink(listen: SocketAddr) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(listen)
        .await
        .with_context(|| format!("bind udp sink on {listen}"))?;
    println!("udp-sink listening on {}", socket.local_addr()?);
    let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];
    loop {
        let (_, _) = socket.recv_from(&mut buffer).await?;
    }
}

async fn run_udp_source(listen: SocketAddr, payload_size: usize) -> anyhow::Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(listen)
            .await
            .with_context(|| format!("bind udp source on {listen}"))?,
    );
    println!("udp-source listening on {}", socket.local_addr()?);
    let peers = Arc::new(Mutex::new(HashSet::new()));
    let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];
    let payload = Arc::new(vec![0u8; payload_size.clamp(64, 1400)]);
    loop {
        let (_, peer) = socket.recv_from(&mut buffer).await?;
        let mut guard = peers.lock().await;
        if !guard.insert(peer) {
            continue;
        }
        drop(guard);
        let socket = socket.clone();
        let peers = peers.clone();
        let payload = payload.clone();
        tokio::spawn(async move {
            loop {
                if let Err(error) = socket.send_to(&payload, peer).await {
                    eprintln!("udp-source to {peer} error: {error}");
                    break;
                }
            }
            peers.lock().await.remove(&peer);
        });
    }
}

async fn run_tcp_proxy(
    listen: SocketAddr,
    upstream: SocketAddr,
    impairment: ImpairmentProfile,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind tcp proxy on {listen}"))?;
    println!(
        "tcp-proxy listening on {} -> {}",
        listener.local_addr()?,
        upstream
    );
    loop {
        let (inbound, peer) = listener.accept().await?;
        let _ = inbound.set_nodelay(true);
        tokio::spawn(async move {
            match TcpStream::connect(upstream).await {
                Ok(outbound) => {
                    let _ = outbound.set_nodelay(true);
                    let (mut inbound_r, mut inbound_w) = inbound.into_split();
                    let (mut outbound_r, mut outbound_w) = outbound.into_split();
                    let upload = tokio::spawn(async move {
                        proxy_tcp_half(&mut inbound_r, &mut outbound_w, impairment).await
                    });
                    let download = tokio::spawn(async move {
                        proxy_tcp_half(&mut outbound_r, &mut inbound_w, impairment).await
                    });
                    let _ = tokio::join!(upload, download);
                }
                Err(error) => eprintln!("tcp-proxy connect {peer} -> {upstream} failed: {error}"),
            }
        });
    }
}

async fn proxy_tcp_half<R, W>(
    reader: &mut R,
    writer: &mut W,
    impairment: ImpairmentProfile,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            return Ok(());
        }
        if let Some(delay) = tcp_forward_delay(impairment) {
            sleep(delay).await;
        }
        writer.write_all(&buffer[..read]).await?;
        if read <= 4 * 1024 {
            writer.flush().await?;
        }
    }
}

async fn run_udp_proxy(
    listen: SocketAddr,
    upstream: SocketAddr,
    impairment: ImpairmentProfile,
) -> anyhow::Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(listen)
            .await
            .with_context(|| format!("bind udp proxy on {listen}"))?,
    );
    println!(
        "udp-proxy listening on {} -> {}",
        socket.local_addr()?,
        upstream
    );
    let sessions = Arc::new(Mutex::new(
        HashMap::<SocketAddr, mpsc::Sender<Vec<u8>>>::new(),
    ));
    let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];
    loop {
        let (size, client) = socket.recv_from(&mut buffer).await?;
        let payload = buffer[..size].to_vec();
        let tx = {
            let mut sessions_guard = sessions.lock().await;
            if let Some(tx) = sessions_guard.get(&client) {
                tx.clone()
            } else {
                let (tx, rx) = mpsc::channel::<Vec<u8>>(256);
                sessions_guard.insert(client, tx.clone());
                tokio::spawn(run_udp_proxy_session(
                    socket.clone(),
                    upstream,
                    client,
                    rx,
                    impairment,
                    sessions.clone(),
                ));
                tx
            }
        };
        if tx.send(payload).await.is_err() {
            sessions.lock().await.remove(&client);
        }
    }
}

async fn run_udp_proxy_session(
    listen_socket: Arc<UdpSocket>,
    upstream: SocketAddr,
    client: SocketAddr,
    mut client_rx: mpsc::Receiver<Vec<u8>>,
    impairment: ImpairmentProfile,
    sessions: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
) -> anyhow::Result<()> {
    let upstream_socket = bind_udp_proxy_upstream_socket(upstream).await?;
    upstream_socket
        .connect(upstream)
        .await
        .with_context(|| format!("connect udp proxy upstream {upstream}"))?;

    let upstream_socket = Arc::new(upstream_socket);
    let upload = {
        let upstream_socket = upstream_socket.clone();
        tokio::spawn(async move {
            while let Some(payload) = client_rx.recv().await {
                if should_drop_datagram(impairment) {
                    continue;
                }
                if let Some(delay) = network_delay(impairment) {
                    sleep(delay).await;
                }
                upstream_socket.send(&payload).await?;
            }
            Ok::<(), anyhow::Error>(())
        })
    };

    let download = {
        let upstream_socket = upstream_socket.clone();
        let listen_socket = listen_socket.clone();
        tokio::spawn(async move {
            let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD_LEN];
            loop {
                let size = upstream_socket.recv(&mut buffer).await?;
                if should_drop_datagram(impairment) {
                    continue;
                }
                if let Some(delay) = network_delay(impairment) {
                    sleep(delay).await;
                }
                listen_socket.send_to(&buffer[..size], client).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), anyhow::Error>(())
        })
    };

    let _ = tokio::select! {
        result = upload => result.context("join udp proxy upload")?,
        result = download => result.context("join udp proxy download")?,
    };
    sessions.lock().await.remove(&client);
    Ok(())
}

async fn bind_udp_proxy_upstream_socket(upstream: SocketAddr) -> anyhow::Result<UdpSocket> {
    let bind_addr = if upstream.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    };
    UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("bind udp proxy upstream socket on {bind_addr}"))
}

fn network_delay(impairment: ImpairmentProfile) -> Option<Duration> {
    let base = impairment.latency.as_millis() as i64;
    let jitter = impairment.jitter.as_millis() as i64;
    let jitter_offset = if jitter > 0 {
        let mut rng = rand::rng();
        rng.random_range(-jitter..=jitter)
    } else {
        0
    };
    let delay_ms = (base + jitter_offset).max(0) as u64;
    if delay_ms == 0 {
        None
    } else {
        Some(Duration::from_millis(delay_ms))
    }
}

fn should_drop_datagram(impairment: ImpairmentProfile) -> bool {
    impairment.loss_rate > 0.0 && rand::rng().random_bool(impairment.loss_rate)
}

fn tcp_forward_delay(impairment: ImpairmentProfile) -> Option<Duration> {
    let mut delay = network_delay(impairment).unwrap_or_default();
    if impairment.stall_rate > 0.0 && rand::rng().random_bool(impairment.stall_rate) {
        delay += impairment.stall;
    }
    if delay.is_zero() { None } else { Some(delay) }
}

async fn run_client(options: ClientOptions) -> anyhow::Result<BenchSummary> {
    let mut tasks = Vec::with_capacity(options.parallel);
    for worker_id in 0..options.parallel {
        let options = options.clone();
        tasks.push(tokio::spawn(
            async move { run_worker(worker_id, options).await },
        ));
    }

    let mut summary = WorkerResult::default();
    let mut synack_values = Vec::new();
    let mut first_byte_values = Vec::new();
    let mut connect_values = Vec::new();
    let mut handshake_values = Vec::new();

    for task in tasks {
        let result = task.await.context("join benchmark worker")??;
        summary.uploaded += result.uploaded;
        summary.downloaded += result.downloaded;
        if let Some(value) = result.synack_ms {
            synack_values.push(value);
        }
        if let Some(value) = result.first_byte_ms {
            first_byte_values.push(value);
        }
        if let Some(value) = result.connect_ms {
            connect_values.push(value);
        }
        if let Some(value) = result.handshake_ms {
            handshake_values.push(value);
        }
    }

    Ok(BenchSummary {
        mode: options.mode,
        parallel: options.parallel,
        duration: options.duration,
        users: options.users.len(),
        uploaded: summary.uploaded,
        downloaded: summary.downloaded,
        connect_ms: average_ms(&connect_values),
        handshake_ms: average_ms(&handshake_values),
        synack_ms: average_ms(&synack_values),
        first_byte_ms: average_ms(&first_byte_values),
    })
}

async fn run_scenarios(options: ScenarioOptions) -> anyhow::Result<()> {
    let mut cases = Vec::new();
    if options.suite.includes_tcp()
        && let Some(target) = options.tcp_upload_target.clone()
    {
        cases.push((
            "tcp-upload-single",
            build_client_options(
                &options,
                BenchMode::Upload,
                target.clone(),
                1,
                options.chunk_size,
            ),
        ));
        cases.push((
            "tcp-upload-multi-user",
            build_client_options(
                &options,
                BenchMode::Upload,
                target,
                options.parallel,
                options.chunk_size,
            ),
        ));
    }
    if options.suite.includes_tcp()
        && let Some(target) = options.tcp_download_target.clone()
    {
        cases.push((
            "tcp-download-single",
            build_client_options(
                &options,
                BenchMode::Download,
                target.clone(),
                1,
                options.chunk_size,
            ),
        ));
        cases.push((
            "tcp-download-multi-user",
            build_client_options(
                &options,
                BenchMode::Download,
                target.clone(),
                options.parallel,
                options.chunk_size,
            ),
        ));
    }
    if options.suite.includes_idle()
        && let Some(target) = options
            .tcp_upload_target
            .clone()
            .or_else(|| options.tcp_download_target.clone())
    {
        let mut idle_case = build_client_options(
            &options,
            BenchMode::Idle,
            target,
            options.parallel.clamp(1, 4),
            1024,
        );
        idle_case.duration = options.idle_duration;
        cases.push(("long-idle-keepalive", idle_case));
    }
    if options.suite.includes_udp()
        && let Some(target) = options.udp_upload_target.clone()
    {
        cases.push((
            "udp-upload-multi-user",
            build_client_options(
                &options,
                BenchMode::UdpUpload,
                target,
                options.parallel,
                options.udp_chunk_size,
            ),
        ));
    }
    if options.suite.includes_udp()
        && let Some(target) = options.udp_download_target.clone()
    {
        cases.push((
            "udp-download-multi-user",
            build_client_options(
                &options,
                BenchMode::UdpDownload,
                target,
                options.parallel,
                options.udp_chunk_size,
            ),
        ));
    }

    ensure!(!cases.is_empty(), "no scenarios enabled");
    for (name, case) in cases {
        println!("== scenario: {name} ==");
        let summary = run_client(case).await?;
        summary.print();
    }
    Ok(())
}

fn build_client_options(
    options: &ScenarioOptions,
    mode: BenchMode,
    target: SocksTarget,
    parallel: usize,
    chunk_size: usize,
) -> ClientOptions {
    ClientOptions {
        server: options.server,
        sni: options.sni.clone(),
        users: options.users.clone(),
        target,
        mode,
        duration: options.duration,
        parallel: parallel.max(1),
        chunk_size,
        insecure: options.insecure,
    }
}

async fn run_worker(worker_id: usize, options: ClientOptions) -> anyhow::Result<WorkerResult> {
    let user = options.user_for(worker_id).to_string();
    let tcp_started = Instant::now();
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(options.server))
        .await
        .context("connect to AnyTLS server timed out")??;
    let _ = stream.set_nodelay(true);
    let connect_ms = tcp_started.elapsed().as_millis() as u64;

    let tls_started = Instant::now();
    let connector = TlsConnector::from(build_client_config(options.insecure));
    let server_name = ServerName::try_from(options.sni.clone())
        .map_err(|_| anyhow::anyhow!("invalid SNI {}", options.sni))?;
    let tls_stream = connector
        .connect(server_name, stream)
        .await
        .context("TLS connect to AnyTLS server")?;
    let handshake_ms = tls_started.elapsed().as_millis() as u64;

    let (reader, writer) = split(tls_stream);
    let writer = Arc::new(Mutex::new(writer));

    send_auth_preface(&writer, &user).await?;
    send_settings(&writer).await?;

    let stream_id = worker_id as u32 + 1;
    let state = SessionState::new(stream_id);
    let (payload_tx, mut payload_rx) = if matches!(options.mode, BenchMode::UdpDownload) {
        let (tx, rx) = mpsc::channel(256);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let reader_state = state.clone();
    let reader_writer = writer.clone();
    let reader_task =
        tokio::spawn(
            async move { read_loop(reader, reader_writer, reader_state, payload_tx).await },
        );

    let syn_target = if options.mode.is_udp() {
        SocksTarget::Domain(UOT_MAGIC_ADDRESS.to_string(), 443)
    } else {
        options.target.clone()
    };
    let syn_payload = encode_target(&syn_target)?;
    *state
        .syn_sent_at
        .lock()
        .expect("syn timestamp lock poisoned") = Instant::now();
    write_frame(&writer, CMD_SYN, stream_id, &[]).await?;
    write_frame(&writer, CMD_PSH, stream_id, &syn_payload).await?;

    if options.mode.is_udp() {
        let request = encode_uot_request(&options.target)?;
        write_frame(&writer, CMD_PSH, stream_id, &request).await?;
        state.record_upload(request.len());
    }

    wait_for_synack(state.clone()).await?;

    match options.mode {
        BenchMode::Upload => {
            let payload = vec![0u8; options.chunk_size.clamp(1024, MAX_FRAME_PAYLOAD_LEN)];
            run_upload_loop(&writer, state.clone(), stream_id, payload, options.duration).await?;
        }
        BenchMode::Download => {
            wait_for_duration_or_finish(options.duration, state.clone()).await;
        }
        BenchMode::UdpUpload => {
            let payload = vec![0u8; options.chunk_size.clamp(64, 1400)];
            run_udp_upload_loop(&writer, state.clone(), stream_id, payload, options.duration)
                .await?;
        }
        BenchMode::UdpDownload => {
            let trigger = encode_uot_connected_packet(&[0u8; 1])?;
            write_frame(&writer, CMD_PSH, stream_id, &trigger).await?;
            state.record_upload(trigger.len());
            wait_for_udp_download(
                options.duration,
                state.clone(),
                payload_rx
                    .take()
                    .ok_or_else(|| anyhow::anyhow!("missing UDP payload channel"))?,
            )
            .await;
        }
        BenchMode::Idle => {
            wait_for_duration_or_finish(options.duration, state.clone()).await;
        }
    }

    let _ = write_frame(&writer, CMD_FIN, stream_id, &[]).await;
    match tokio::time::timeout(Duration::from_secs(2), reader_task).await {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(error))) => return Err(error.context("read loop failed")),
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => {
            if let Some(error) = state.current_error().await {
                bail!(error);
            }
        }
    }

    if let Some(error) = state.current_error().await {
        bail!(error);
    }

    Ok(WorkerResult {
        uploaded: state.upload_bytes.load(Ordering::Relaxed),
        downloaded: state.download_bytes.load(Ordering::Relaxed),
        connect_ms: Some(connect_ms),
        handshake_ms: Some(handshake_ms),
        synack_ms: non_zero_metric(state.synack_ms.load(Ordering::Relaxed)),
        first_byte_ms: non_zero_metric(state.first_byte_ms.load(Ordering::Relaxed)),
    })
}

async fn run_upload_loop(
    writer: &SharedWriter,
    state: Arc<SessionState>,
    stream_id: u32,
    payload: Vec<u8>,
    duration: Duration,
) -> anyhow::Result<()> {
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if state.is_finished() {
            break;
        }
        if let Some(error) = state.current_error().await {
            bail!(error);
        }
        if !write_frame_until_finish(writer, state.clone(), CMD_PSH, stream_id, &payload).await? {
            break;
        }
        state.record_upload(payload.len());
    }
    Ok(())
}

async fn run_udp_upload_loop(
    writer: &SharedWriter,
    state: Arc<SessionState>,
    stream_id: u32,
    payload: Vec<u8>,
    duration: Duration,
) -> anyhow::Result<()> {
    let packet = encode_uot_connected_packet(&payload)?;
    let deadline = Instant::now() + duration;
    while Instant::now() < deadline {
        if state.is_finished() {
            break;
        }
        if let Some(error) = state.current_error().await {
            bail!(error);
        }
        if !write_frame_until_finish(writer, state.clone(), CMD_PSH, stream_id, &packet).await? {
            break;
        }
        state.record_upload(packet.len());
    }
    Ok(())
}

async fn write_frame_until_finish(
    writer: &SharedWriter,
    state: Arc<SessionState>,
    cmd: u8,
    stream_id: u32,
    payload: &[u8],
) -> anyhow::Result<bool> {
    if state.is_finished() {
        return Ok(false);
    }
    tokio::select! {
        _ = state.finish_notify.notified() => Ok(false),
        result = write_frame(writer, cmd, stream_id, payload) => {
            result?;
            Ok(true)
        }
    }
}

async fn wait_for_udp_download(
    duration: Duration,
    state: Arc<SessionState>,
    mut payloads: mpsc::Receiver<Vec<u8>>,
) {
    let deadline = Instant::now() + duration;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return;
        }
        tokio::select! {
            _ = sleep(remaining) => return,
            _ = state.finish_notify.notified() => return,
            payload = payloads.recv() => {
                if payload.is_none() {
                    return;
                }
            }
        }
    }
}

async fn wait_for_duration_or_finish(duration: Duration, state: Arc<SessionState>) {
    tokio::select! {
        _ = sleep(duration) => {}
        _ = state.finish_notify.notified() => {}
    }
}

fn build_client_config(insecure: bool) -> Arc<ClientConfig> {
    let mut config = if insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureVerifier))
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth()
    };
    config.alpn_protocols.clear();
    Arc::new(config)
}

async fn send_auth_preface(writer: &SharedWriter, user: &str) -> anyhow::Result<()> {
    let password_hash: [u8; 32] = Sha256::digest(user.as_bytes()).into();
    let mut guard = writer.lock().await;
    guard
        .write_all(&password_hash)
        .await
        .context("write AnyTLS password hash")?;
    guard
        .write_all(&0u16.to_be_bytes())
        .await
        .context("write AnyTLS preface padding length")?;
    guard.flush().await.context("flush AnyTLS preface")?;
    Ok(())
}

async fn send_settings(writer: &SharedWriter) -> anyhow::Result<()> {
    let lines = DEFAULT_PADDING_SCHEME.join("\n");
    let padding_md5 = hex::encode(Md5::digest(lines.as_bytes()));
    let settings = format!("v=2\nclient=noders-anytls-bench/0.1\npadding-md5={padding_md5}");
    write_frame(writer, CMD_SETTINGS, 0, settings.as_bytes()).await
}

async fn read_loop(
    mut reader: ReadHalf<ClientTlsStream>,
    writer: SharedWriter,
    state: Arc<SessionState>,
    payload_tx: Option<mpsc::Sender<Vec<u8>>>,
) -> anyhow::Result<()> {
    loop {
        let mut header = [0u8; 7];
        if let Err(error) = reader.read_exact(&mut header).await {
            if error.kind() == std::io::ErrorKind::UnexpectedEof {
                if state.is_finished() {
                    state.finish();
                    return Ok(());
                }
                state
                    .set_error("unexpected EOF while reading AnyTLS header")
                    .await;
                return Err(error.into());
            }
            state
                .set_error(format!("read AnyTLS header: {error}"))
                .await;
            return Err(error.into());
        }
        let cmd = header[0];
        let stream_id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
        let length = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut payload = vec![0u8; length];
        if length > 0
            && let Err(error) = reader.read_exact(&mut payload).await
        {
            state
                .set_error(format!("read AnyTLS payload: {error}"))
                .await;
            return Err(error).context("read AnyTLS payload");
        }
        match cmd {
            CMD_PSH if stream_id == state.stream_id => {
                state.record_download(length);
                if let Some(tx) = &payload_tx
                    && tx.send(payload).await.is_err()
                {
                    return Ok(());
                }
            }
            CMD_FIN if stream_id == state.stream_id => {
                state.finish();
                return Ok(());
            }
            CMD_SYNACK if stream_id == state.stream_id => {
                if payload.is_empty() {
                    state.set_synack_ok();
                } else {
                    state
                        .set_error(format!(
                            "stream open failed: {}",
                            String::from_utf8_lossy(&payload)
                        ))
                        .await;
                    return Ok(());
                }
            }
            CMD_HEART_REQUEST => {
                write_frame(&writer, CMD_HEART_RESPONSE, stream_id, &[]).await?;
            }
            CMD_HEART_RESPONSE | CMD_SERVER_SETTINGS | CMD_UPDATE_PADDING_SCHEME | CMD_SETTINGS => {
            }
            CMD_ALERT => {
                state
                    .set_error(format!(
                        "server alert: {}",
                        String::from_utf8_lossy(&payload)
                    ))
                    .await;
                return Ok(());
            }
            _ => {}
        }
    }
}

async fn wait_for_synack(state: Arc<SessionState>) -> anyhow::Result<()> {
    timeout(SYNACK_TIMEOUT, async {
        loop {
            if state.synack_ok.load(Ordering::SeqCst) {
                return Ok(());
            }
            if let Some(error) = state.error.lock().await.clone() {
                bail!(error);
            }
            state.synack_notify.notified().await;
        }
    })
    .await
    .context("wait for SYNACK timed out")?
}

async fn write_frame(
    writer: &SharedWriter,
    cmd: u8,
    stream_id: u32,
    payload: &[u8],
) -> anyhow::Result<()> {
    ensure!(payload.len() <= MAX_FRAME_PAYLOAD_LEN, "payload too large");
    let mut frame = Vec::with_capacity(7 + payload.len());
    frame.push(cmd);
    frame.extend_from_slice(&stream_id.to_be_bytes());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    let mut guard = writer.lock().await;
    timeout(WRITE_TIMEOUT, guard.write_all(&frame))
        .await
        .context("write AnyTLS frame timed out")?
        .context("write AnyTLS frame")?;
    if cmd != CMD_PSH || payload.len() <= 4 * 1024 {
        timeout(WRITE_TIMEOUT, guard.flush())
            .await
            .context("flush AnyTLS frame timed out")?
            .context("flush AnyTLS frame")?;
    }
    Ok(())
}

fn encode_target(target: &SocksTarget) -> anyhow::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    match target {
        SocksTarget::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                encoded.push(0x01);
                encoded.extend_from_slice(&ip.octets());
                encoded.extend_from_slice(&addr.port().to_be_bytes());
            }
            IpAddr::V6(ip) => {
                encoded.push(0x04);
                encoded.extend_from_slice(&ip.octets());
                encoded.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
        SocksTarget::Domain(host, port) => {
            ensure!(host.len() <= u8::MAX as usize, "domain too long");
            encoded.push(0x03);
            encoded.push(host.len() as u8);
            encoded.extend_from_slice(host.as_bytes());
            encoded.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(encoded)
}

fn encode_uot_request(target: &SocksTarget) -> anyhow::Result<Vec<u8>> {
    let mut encoded = Vec::with_capacity(32);
    encoded.push(1);
    encoded.extend_from_slice(&encode_target(target)?);
    Ok(encoded)
}

fn encode_uot_connected_packet(payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    ensure!(payload.len() <= u16::MAX as usize, "UDP payload too large");
    let mut encoded = Vec::with_capacity(2 + payload.len());
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn parse_args(args: Vec<String>) -> anyhow::Result<Command> {
    let mut args = args.into_iter();
    let Some(command) = args.next() else {
        bail!(
            "usage: bench_anytls <sink|source|udp-sink|udp-source|tcp-proxy|udp-proxy|client|scenario> ..."
        );
    };
    match command.as_str() {
        "sink" => {
            let args = args.collect::<Vec<_>>();
            let listen = find_flag_value(&args, "--listen")?;
            Ok(Command::Sink {
                listen: SocketAddr::from_str(&listen)
                    .with_context(|| format!("parse --listen {listen}"))?,
            })
        }
        "source" => {
            let args = args.collect::<Vec<_>>();
            let listen = find_flag_value(&args, "--listen")?;
            let chunk_size =
                find_optional_usize(&args, "--chunk-size")?.unwrap_or(DEFAULT_CHUNK_SIZE);
            Ok(Command::Source {
                listen: SocketAddr::from_str(&listen)
                    .with_context(|| format!("parse --listen {listen}"))?,
                chunk_size,
            })
        }
        "udp-sink" => {
            let args = args.collect::<Vec<_>>();
            let listen = find_flag_value(&args, "--listen")?;
            Ok(Command::UdpSink {
                listen: SocketAddr::from_str(&listen)
                    .with_context(|| format!("parse --listen {listen}"))?,
            })
        }
        "udp-source" => {
            let args = args.collect::<Vec<_>>();
            let listen = find_flag_value(&args, "--listen")?;
            let payload_size =
                find_optional_usize(&args, "--payload-size")?.unwrap_or(DEFAULT_UDP_CHUNK_SIZE);
            Ok(Command::UdpSource {
                listen: SocketAddr::from_str(&listen)
                    .with_context(|| format!("parse --listen {listen}"))?,
                payload_size,
            })
        }
        "tcp-proxy" => {
            let args = args.collect::<Vec<_>>();
            let listen = find_flag_value(&args, "--listen")?;
            let upstream = find_flag_value(&args, "--upstream")?;
            Ok(Command::TcpProxy {
                listen: SocketAddr::from_str(&listen)
                    .with_context(|| format!("parse --listen {listen}"))?,
                upstream: SocketAddr::from_str(&upstream)
                    .with_context(|| format!("parse --upstream {upstream}"))?,
                impairment: ImpairmentProfile {
                    latency: Duration::from_millis(
                        find_optional_u64(&args, "--latency-ms")?.unwrap_or(0),
                    ),
                    jitter: Duration::from_millis(
                        find_optional_u64(&args, "--jitter-ms")?.unwrap_or(0),
                    ),
                    loss_rate: 0.0,
                    stall_rate: find_optional_f64(&args, "--stall-rate")?.unwrap_or(0.0),
                    stall: Duration::from_millis(
                        find_optional_u64(&args, "--stall-ms")?.unwrap_or(0),
                    ),
                },
            })
        }
        "udp-proxy" => {
            let args = args.collect::<Vec<_>>();
            let listen = find_flag_value(&args, "--listen")?;
            let upstream = find_flag_value(&args, "--upstream")?;
            Ok(Command::UdpProxy {
                listen: SocketAddr::from_str(&listen)
                    .with_context(|| format!("parse --listen {listen}"))?,
                upstream: SocketAddr::from_str(&upstream)
                    .with_context(|| format!("parse --upstream {upstream}"))?,
                impairment: ImpairmentProfile {
                    latency: Duration::from_millis(
                        find_optional_u64(&args, "--latency-ms")?.unwrap_or(0),
                    ),
                    jitter: Duration::from_millis(
                        find_optional_u64(&args, "--jitter-ms")?.unwrap_or(0),
                    ),
                    loss_rate: find_optional_f64(&args, "--loss-rate")?.unwrap_or(0.0),
                    stall_rate: 0.0,
                    stall: Duration::ZERO,
                },
            })
        }
        "client" => parse_client_args(args.collect()).map(Command::Client),
        "scenario" => parse_scenario_args(args.collect()).map(Command::Scenario),
        other => bail!("unknown bench subcommand {other}"),
    }
}

fn parse_client_args(args: Vec<String>) -> anyhow::Result<ClientOptions> {
    let mut server = None;
    let mut sni = None;
    let mut users: Vec<String> = Vec::new();
    let mut target = None;
    let mut mode = None;
    let mut duration = DEFAULT_DURATION_SECONDS;
    let mut parallel = DEFAULT_PARALLEL;
    let mut chunk_size = DEFAULT_CHUNK_SIZE;
    let mut insecure = false;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--server" => server = Some(next_value(&mut iter, "--server")?),
            "--sni" => sni = Some(next_value(&mut iter, "--sni")?),
            "--user" => users.push(next_value(&mut iter, "--user")?),
            "--users" => users.extend(parse_users(&next_value(&mut iter, "--users")?)?),
            "--target" => target = Some(parse_target(&next_value(&mut iter, "--target")?)?),
            "--mode" => {
                mode = Some(match next_value(&mut iter, "--mode")?.as_str() {
                    "upload" => BenchMode::Upload,
                    "download" => BenchMode::Download,
                    "udp-upload" => BenchMode::UdpUpload,
                    "udp-download" => BenchMode::UdpDownload,
                    "idle" => BenchMode::Idle,
                    other => bail!("unsupported mode {other}"),
                })
            }
            "--seconds" => duration = next_value(&mut iter, "--seconds")?.parse::<u64>()?,
            "--parallel" | "--connections" => {
                parallel = next_value(&mut iter, "--parallel/--connections")?.parse::<usize>()?;
            }
            "--chunk-size" => {
                chunk_size = next_value(&mut iter, "--chunk-size")?.parse::<usize>()?
            }
            "--insecure" => insecure = true,
            other => bail!("unsupported flag {other}"),
        }
    }

    let server = server.ok_or_else(|| anyhow::anyhow!("missing --server"))?;
    if users.is_empty() {
        bail!("missing --user or --users");
    }
    let mode = mode.ok_or_else(|| anyhow::anyhow!("missing --mode"))?;
    Ok(ClientOptions {
        server: SocketAddr::from_str(&server)
            .with_context(|| format!("parse --server {server}"))?,
        sni: sni.ok_or_else(|| anyhow::anyhow!("missing --sni"))?,
        users,
        target: target.ok_or_else(|| anyhow::anyhow!("missing --target"))?,
        mode,
        duration: Duration::from_secs(duration.max(1)),
        parallel: parallel.max(1),
        chunk_size: normalize_chunk_size(mode, chunk_size),
        insecure,
    })
}

fn parse_scenario_args(args: Vec<String>) -> anyhow::Result<ScenarioOptions> {
    let mut server = None;
    let mut sni = None;
    let mut users: Vec<String> = Vec::new();
    let mut tcp_upload_target = None;
    let mut tcp_download_target = None;
    let mut udp_upload_target = None;
    let mut udp_download_target = None;
    let mut duration = DEFAULT_DURATION_SECONDS;
    let mut idle_duration = DEFAULT_IDLE_SECONDS;
    let mut parallel = DEFAULT_SCENARIO_PARALLEL;
    let mut chunk_size = DEFAULT_CHUNK_SIZE;
    let mut udp_chunk_size = DEFAULT_UDP_CHUNK_SIZE;
    let mut insecure = false;
    let mut suite = ScenarioSuite::All;

    let mut iter = args.into_iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--server" => server = Some(next_value(&mut iter, "--server")?),
            "--sni" => sni = Some(next_value(&mut iter, "--sni")?),
            "--user" => users.push(next_value(&mut iter, "--user")?),
            "--users" => users.extend(parse_users(&next_value(&mut iter, "--users")?)?),
            "--tcp-upload-target" => {
                tcp_upload_target = Some(parse_target(&next_value(
                    &mut iter,
                    "--tcp-upload-target",
                )?)?)
            }
            "--tcp-download-target" => {
                tcp_download_target = Some(parse_target(&next_value(
                    &mut iter,
                    "--tcp-download-target",
                )?)?)
            }
            "--udp-upload-target" => {
                udp_upload_target = Some(parse_target(&next_value(
                    &mut iter,
                    "--udp-upload-target",
                )?)?)
            }
            "--udp-download-target" => {
                udp_download_target = Some(parse_target(&next_value(
                    &mut iter,
                    "--udp-download-target",
                )?)?)
            }
            "--seconds" => duration = next_value(&mut iter, "--seconds")?.parse::<u64>()?,
            "--idle-seconds" => {
                idle_duration = next_value(&mut iter, "--idle-seconds")?.parse::<u64>()?
            }
            "--parallel" | "--connections" => {
                parallel = next_value(&mut iter, "--parallel/--connections")?.parse::<usize>()?;
            }
            "--chunk-size" => {
                chunk_size = next_value(&mut iter, "--chunk-size")?.parse::<usize>()?
            }
            "--udp-chunk-size" => {
                udp_chunk_size = next_value(&mut iter, "--udp-chunk-size")?.parse::<usize>()?
            }
            "--suite" => {
                suite = match next_value(&mut iter, "--suite")?.as_str() {
                    "all" => ScenarioSuite::All,
                    "tcp" => ScenarioSuite::Tcp,
                    "udp" => ScenarioSuite::Udp,
                    "idle" => ScenarioSuite::Idle,
                    other => bail!("unsupported scenario suite {other}"),
                }
            }
            "--insecure" => insecure = true,
            other => bail!("unsupported flag {other}"),
        }
    }

    let server = server.ok_or_else(|| anyhow::anyhow!("missing --server"))?;
    if users.is_empty() {
        bail!("missing --user or --users");
    }
    Ok(ScenarioOptions {
        server: SocketAddr::from_str(&server)
            .with_context(|| format!("parse --server {server}"))?,
        sni: sni.ok_or_else(|| anyhow::anyhow!("missing --sni"))?,
        users,
        tcp_upload_target,
        tcp_download_target,
        udp_upload_target,
        udp_download_target,
        duration: Duration::from_secs(duration.max(1)),
        idle_duration: Duration::from_secs(idle_duration.max(5)),
        parallel: parallel.max(1),
        chunk_size: normalize_chunk_size(BenchMode::Upload, chunk_size),
        udp_chunk_size: normalize_chunk_size(BenchMode::UdpUpload, udp_chunk_size),
        insecure,
        suite,
    })
}

fn normalize_chunk_size(mode: BenchMode, chunk_size: usize) -> usize {
    if mode.is_udp() {
        chunk_size.clamp(64, 1400)
    } else {
        chunk_size.clamp(1024, MAX_FRAME_PAYLOAD_LEN)
    }
}

fn parse_users(value: &str) -> anyhow::Result<Vec<String>> {
    let users = value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    ensure!(!users.is_empty(), "user list must not be empty");
    Ok(users)
}

fn find_flag_value(args: &[String], flag: &str) -> anyhow::Result<String> {
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .ok_or_else(|| anyhow::anyhow!("missing {flag}"))?;
    args.get(index + 1)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))
}

fn find_optional_usize(args: &[String], flag: &str) -> anyhow::Result<Option<usize>> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };
    Ok(Some(
        args.get(index + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?
            .parse::<usize>()?,
    ))
}

fn find_optional_u64(args: &[String], flag: &str) -> anyhow::Result<Option<u64>> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };
    Ok(Some(
        args.get(index + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?
            .parse::<u64>()?,
    ))
}

fn find_optional_f64(args: &[String], flag: &str) -> anyhow::Result<Option<f64>> {
    let Some(index) = args.iter().position(|arg| arg == flag) else {
        return Ok(None);
    };
    Ok(Some(
        args.get(index + 1)
            .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))?
            .parse::<f64>()?,
    ))
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> anyhow::Result<String> {
    args.next()
        .ok_or_else(|| anyhow::anyhow!("missing value for {flag}"))
}

fn parse_target(value: &str) -> anyhow::Result<SocksTarget> {
    if let Ok(addr) = SocketAddr::from_str(value) {
        return Ok(SocksTarget::Ip(addr));
    }

    let (host, port) = if let Some(host) = value.strip_prefix('[') {
        let (host, port) = host
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("invalid target {value}"))?;
        let port = port
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("invalid target {value}"))?
            .parse::<u16>()?;
        (host.to_string(), port)
    } else if let Some((host, port)) = value.rsplit_once(':') {
        (host.to_string(), port.parse::<u16>()?)
    } else {
        bail!("invalid target {value}");
    };
    ensure!(!host.is_empty(), "target host must not be empty");
    Ok(SocksTarget::Domain(host, port))
}

fn mib(bytes: u64) -> u64 {
    bytes / 1024 / 1024
}

fn mbps(bytes: u64, seconds: f64) -> f64 {
    (bytes as f64 * 8.0 / 1_000_000.0) / seconds
}

fn average_ms(values: &[u64]) -> Option<f64> {
    if values.is_empty() {
        None
    } else {
        Some(values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64)
    }
}

fn non_zero_metric(value: u64) -> Option<u64> {
    if value == 0 { None } else { Some(value) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_users_csv() {
        let parsed = parse_users("u1,u2, u3 ").expect("users");
        assert_eq!(parsed, vec!["u1", "u2", "u3"]);
    }

    #[test]
    fn parse_client_args_accepts_multiple_users() {
        let parsed = parse_client_args(vec![
            "--server".into(),
            "127.0.0.1:443".into(),
            "--sni".into(),
            "example.com".into(),
            "--users".into(),
            "u1,u2".into(),
            "--target".into(),
            "127.0.0.1:80".into(),
            "--mode".into(),
            "udp-download".into(),
        ])
        .expect("parse client");
        assert_eq!(parsed.users, vec!["u1", "u2"]);
        assert!(matches!(parsed.mode, BenchMode::UdpDownload));
        assert_eq!(parsed.chunk_size, 1400);
    }

    #[test]
    fn encode_uot_request_marks_connect_mode() {
        let encoded = encode_uot_request(&SocksTarget::Domain("example.com".into(), 53))
            .expect("encode request");
        assert_eq!(encoded[0], 1);
        assert_eq!(encoded[1], 0x03);
    }

    #[test]
    fn parse_scenario_args_builds_targets() {
        let parsed = parse_scenario_args(vec![
            "--server".into(),
            "127.0.0.1:443".into(),
            "--sni".into(),
            "example.com".into(),
            "--user".into(),
            "u1".into(),
            "--tcp-upload-target".into(),
            "127.0.0.1:80".into(),
            "--udp-download-target".into(),
            "127.0.0.1:53".into(),
        ])
        .expect("parse scenario");
        assert!(parsed.tcp_upload_target.is_some());
        assert!(parsed.udp_download_target.is_some());
        assert_eq!(parsed.parallel, DEFAULT_SCENARIO_PARALLEL);
    }
}
