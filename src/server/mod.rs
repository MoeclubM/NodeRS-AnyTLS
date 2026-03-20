mod activity;
mod dns;
mod padding;
mod rules;
mod session;
mod socksaddr;
mod tls;
mod traffic;
mod transport;
mod uot;

use anyhow::Context;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, RwLock};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Duration, timeout};
use tracing::{error, info, warn};

use crate::accounting::Accounting;
use crate::config::{AppConfig, OutboundConfig};
use crate::panel::{NodeConfigResponse, RouteConfig};

use self::padding::PaddingScheme;
use self::rules::RouteRules;

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub padding_scheme: Vec<String>,
    pub routes: Vec<RouteConfig>,
}

impl EffectiveNodeConfig {
    pub fn from_remote(listen_ip: &str, remote: &NodeConfigResponse) -> Self {
        Self {
            listen_ip: listen_ip.to_string(),
            server_port: remote.server_port,
            padding_scheme: if remote.padding_scheme.is_empty() {
                PaddingScheme::default_lines()
            } else {
                remote.padding_scheme.clone()
            },
            routes: remote.routes.clone(),
        }
    }
}

pub struct ServerController {
    tls_config: Arc<RwLock<Arc<rustls::ServerConfig>>>,
    tls_materials: AsyncMutex<tls::LoadedTlsMaterials>,
    accounting: Arc<Accounting>,
    outbound: OutboundConfig,
    padding_scheme: Arc<RwLock<PaddingScheme>>,
    route_rules: Arc<RwLock<RouteRules>>,
    inner: Mutex<Option<RunningServer>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::panel::NodeConfigResponse;

    #[test]
    fn fills_default_padding_from_remote_config() {
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            server_port: 443,
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            base_config: None,
        };
        let effective = EffectiveNodeConfig::from_remote("::", &remote);
        assert_eq!(effective.listen_ip, "::");
        assert_eq!(effective.padding_scheme, PaddingScheme::default_lines());
    }

    #[test]
    fn wildcard_listen_generates_dual_stack_specs() {
        let specs = listener_specs("0.0.0.0", 443).expect("listener specs");
        assert_eq!(specs.len(), 2);
        assert!(specs.iter().any(|spec| spec.bind_addr.is_ipv4()));
        assert!(specs.iter().any(|spec| spec.bind_addr.is_ipv6()));
    }
}

struct RunningServer {
    listen_ip: String,
    server_port: u16,
    handle: JoinHandle<()>,
}

impl ServerController {
    pub async fn new(config: &AppConfig, accounting: Arc<Accounting>) -> anyhow::Result<Self> {
        let tls_materials = tls::load_tls_materials(&config.tls.cert_path, &config.tls.key_path)
            .await
            .context("load TLS materials")?;
        let tls_config = tls_materials.server_config();
        Ok(Self {
            tls_config: Arc::new(RwLock::new(tls_config)),
            tls_materials: AsyncMutex::new(tls_materials),
            accounting,
            outbound: config.outbound.clone(),
            padding_scheme: Arc::new(RwLock::new(PaddingScheme::default())),
            route_rules: Arc::new(RwLock::new(RouteRules::default())),
            inner: Mutex::new(None),
        })
    }

    pub async fn apply_config(&self, config: EffectiveNodeConfig) -> anyhow::Result<()> {
        let padding = if config.padding_scheme.is_empty() {
            PaddingScheme::default()
        } else {
            PaddingScheme::from_lines(&config.padding_scheme)?
        };
        let route_rules =
            RouteRules::from_routes(&config.routes).context("compile Xboard routes")?;
        *self
            .padding_scheme
            .write()
            .expect("padding scheme lock poisoned") = padding;
        *self.route_rules.write().expect("route rules lock poisoned") = route_rules;

        let old = {
            let mut guard = self.inner.lock().expect("server controller poisoned");
            let should_restart = guard.as_ref().is_none_or(|running| {
                running.listen_ip != config.listen_ip || running.server_port != config.server_port
            });
            if !should_restart {
                return Ok(());
            }
            guard.take()
        };

        if let Some(old) = old {
            old.handle.abort();
        }

        let listeners = bind_listeners(&config.listen_ip, config.server_port)?;
        let bind_addrs = listeners
            .iter()
            .filter_map(|listener| listener.local_addr().ok())
            .map(|addr| addr.to_string())
            .collect::<Vec<_>>();
        let tls_config = self.tls_config.clone();
        let accounting = self.accounting.clone();
        let outbound = self.outbound.clone();
        let padding_scheme = self.padding_scheme.clone();
        let route_rules = self.route_rules.clone();
        let handle = tokio::spawn(async move {
            info!(listen = ?bind_addrs, "AnyTLS listeners started");
            let mut accept_loops = JoinSet::new();
            for listener in listeners {
                let tls_config = tls_config.clone();
                let accounting = accounting.clone();
                let outbound = outbound.clone();
                let padding_scheme = padding_scheme.clone();
                let route_rules = route_rules.clone();
                accept_loops.spawn(async move {
                    accept_loop(
                        listener,
                        tls_config,
                        accounting,
                        outbound,
                        padding_scheme,
                        route_rules,
                    )
                    .await;
                });
            }

            while let Some(result) = accept_loops.join_next().await {
                match result {
                    Ok(()) => warn!("AnyTLS accept loop exited unexpectedly"),
                    Err(error) if error.is_cancelled() => break,
                    Err(error) => error!(%error, "AnyTLS accept loop crashed"),
                }
            }
        });

        let mut guard = self.inner.lock().expect("server controller poisoned");
        *guard = Some(RunningServer {
            listen_ip: config.listen_ip,
            server_port: config.server_port,
            handle,
        });
        Ok(())
    }

    pub async fn refresh_tls(&self) -> anyhow::Result<()> {
        let mut tls_materials = self.tls_materials.lock().await;
        if let Some(reloaded) = tls::reload_if_changed(&mut tls_materials).await? {
            *self.tls_config.write().expect("tls config lock poisoned") = reloaded;
            info!("TLS materials reloaded from disk");
        }
        Ok(())
    }
}

async fn accept_loop(
    listener: TcpListener,
    tls_config: Arc<RwLock<Arc<rustls::ServerConfig>>>,
    accounting: Arc<Accounting>,
    outbound: OutboundConfig,
    padding_scheme: Arc<RwLock<PaddingScheme>>,
    route_rules: Arc<RwLock<RouteRules>>,
) {
    let listen = listener
        .local_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    loop {
        let (stream, source) = match listener.accept().await {
            Ok(value) => value,
            Err(error) => {
                error!(%error, listen = %listen, "accept connection failed");
                continue;
            }
        };
        configure_tcp_stream(&stream);
        let acceptor = {
            let tls_config = tls_config.read().expect("tls config lock poisoned").clone();
            tokio_rustls::TlsAcceptor::from(tls_config)
        };
        let accounting = accounting.clone();
        let outbound = outbound.clone();
        let padding_scheme = padding_scheme.clone();
        let route_rules = route_rules.clone();
        tokio::spawn(async move {
            let tls_stream = match timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    warn!(%error, %source, "TLS handshake failed");
                    return;
                }
                Err(_) => {
                    warn!(%source, "TLS handshake timed out");
                    return;
                }
            };
            let padding = padding_scheme
                .read()
                .expect("padding scheme lock poisoned")
                .clone();
            let route_rules = route_rules
                .read()
                .expect("route rules lock poisoned")
                .clone();
            if let Err(error) = session::serve_connection(
                tls_stream,
                source,
                accounting,
                padding,
                route_rules,
                outbound,
            )
            .await
            {
                warn!(%error, %source, "session terminated with error");
            }
        });
    }
}

pub(super) fn configure_tcp_stream(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
    let keepalive = TcpKeepalive::new().with_time(TCP_KEEPALIVE_IDLE);
    let socket = SockRef::from(stream);
    let _ = socket.set_tcp_keepalive(&keepalive);
}

fn bind_listeners(listen_ip: &str, port: u16) -> anyhow::Result<Vec<TcpListener>> {
    let specs = listener_specs(listen_ip, port)?;
    let mut listeners = Vec::new();
    for spec in specs {
        match bind_listener(spec.bind_addr, spec.only_v6) {
            Ok(listener) => listeners.push(listener),
            Err(error) if spec.optional => {
                warn!(%error, listen = %spec.bind_addr, "optional listener bind failed")
            }
            Err(error) => return Err(error),
        }
    }
    if listeners.is_empty() {
        anyhow::bail!("no AnyTLS listeners could be started");
    }
    Ok(listeners)
}

fn bind_listener(bind_addr: SocketAddr, only_v6: bool) -> anyhow::Result<TcpListener> {
    let domain = if bind_addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))
        .with_context(|| format!("create listener socket for {bind_addr}"))?;
    socket.set_reuse_address(true).ok();
    if bind_addr.is_ipv6() {
        socket
            .set_only_v6(only_v6)
            .with_context(|| format!("set IPv6-only mode for {bind_addr}"))?;
    }
    socket
        .bind(&bind_addr.into())
        .with_context(|| format!("bind {bind_addr}"))?;
    socket
        .listen(1024)
        .with_context(|| format!("listen on {bind_addr}"))?;
    socket
        .set_nonblocking(true)
        .with_context(|| format!("set nonblocking on {bind_addr}"))?;
    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener).with_context(|| format!("adopt listener {bind_addr}"))
}

#[derive(Clone, Copy)]
struct ListenerSpec {
    bind_addr: SocketAddr,
    only_v6: bool,
    optional: bool,
}

fn listener_specs(listen_ip: &str, port: u16) -> anyhow::Result<Vec<ListenerSpec>> {
    let listen_ip = listen_ip.trim();
    if listen_ip.is_empty() || listen_ip == "0.0.0.0" || listen_ip == "::" || listen_ip == "[::]" {
        return Ok(vec![
            ListenerSpec {
                bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
                only_v6: false,
                optional: false,
            },
            ListenerSpec {
                bind_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
                only_v6: true,
                optional: true,
            },
        ]);
    }

    let bind_ip = listen_ip
        .parse::<IpAddr>()
        .with_context(|| format!("parse listen_ip {listen_ip}"))?;
    Ok(vec![ListenerSpec {
        bind_addr: SocketAddr::new(bind_ip, port),
        only_v6: bind_ip.is_ipv6(),
        optional: false,
    }])
}
