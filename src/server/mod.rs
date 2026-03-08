mod dns;
mod padding;
mod rules;
mod session;
mod socksaddr;
mod tls;

use anyhow::Context;
use std::sync::{Arc, Mutex, RwLock};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::accounting::Accounting;
use crate::config::AppConfig;
use crate::panel::{NodeConfigResponse, RouteConfig};

use self::padding::PaddingScheme;
use self::rules::RouteRules;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveNodeConfig {
    pub listen_ip: String,
    pub server_port: u16,
    pub server_name: String,
    pub padding_scheme: Vec<String>,
    pub routes: Vec<RouteConfig>,
}

impl EffectiveNodeConfig {
    pub fn from_remote(local: &AppConfig, remote: &NodeConfigResponse) -> Self {
        let local_server_name = local.tls.server_name.trim();
        Self {
            listen_ip: local.node.listen_ip.clone(),
            server_port: remote.server_port,
            server_name: if local_server_name.is_empty() {
                remote.server_name.clone()
            } else {
                local_server_name.to_string()
            },
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
    padding_scheme: Arc<RwLock<PaddingScheme>>,
    route_rules: Arc<RwLock<RouteRules>>,
    inner: Mutex<Option<RunningServer>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        AppConfig, LogConfig, NodeConfig, PanelConfig, ReportConfig, SyncConfig, TlsConfig,
    };
    use crate::panel::NodeConfigResponse;
    use std::path::PathBuf;

    fn app_config(server_name: &str) -> AppConfig {
        AppConfig {
            panel: PanelConfig {
                url: "https://panel.example.com".to_string(),
                token: "token".to_string(),
                node_id: 1,
                node_type: "anytls".to_string(),
                timeout_seconds: 15,
            },
            node: NodeConfig {
                listen_ip: "0.0.0.0".to_string(),
                node_type: "anytls".to_string(),
            },
            tls: TlsConfig {
                cert_path: PathBuf::from("cert.pem"),
                key_path: PathBuf::from("key.pem"),
                server_name: server_name.to_string(),
                reload_interval_seconds: 60,
                acme: None,
            },
            sync: SyncConfig::default(),
            report: ReportConfig::default(),
            log: LogConfig::default(),
        }
    }

    #[test]
    fn prefers_local_tls_server_name() {
        let local = app_config("local.example.com");
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            server_port: 443,
            server_name: "remote.example.com".to_string(),
            padding_scheme: vec!["stop=1".to_string(), "0=1-1".to_string()],
            routes: Vec::new(),
            base_config: None,
        };
        let effective = EffectiveNodeConfig::from_remote(&local, &remote);
        assert_eq!(effective.server_name, "local.example.com");
    }

    #[test]
    fn falls_back_to_remote_server_name_and_default_padding() {
        let local = app_config("");
        let remote = NodeConfigResponse {
            protocol: "anytls".to_string(),
            server_port: 443,
            server_name: "remote.example.com".to_string(),
            padding_scheme: Vec::new(),
            routes: Vec::new(),
            base_config: None,
        };
        let effective = EffectiveNodeConfig::from_remote(&local, &remote);
        assert_eq!(effective.server_name, "remote.example.com");
        assert_eq!(effective.padding_scheme, PaddingScheme::default_lines());
    }
}

struct RunningServer {
    config: EffectiveNodeConfig,
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
                running.config.listen_ip != config.listen_ip
                    || running.config.server_port != config.server_port
            });
            if !should_restart {
                return Ok(());
            }
            guard.take()
        };

        if let Some(old) = old {
            old.handle.abort();
        }

        let bind_addr = format!("{}:{}", config.listen_ip, config.server_port);
        let listener = TcpListener::bind(&bind_addr)
            .await
            .with_context(|| format!("bind {bind_addr}"))?;
        let tls_config = self.tls_config.clone();
        let accounting = self.accounting.clone();
        let padding_scheme = self.padding_scheme.clone();
        let route_rules = self.route_rules.clone();
        let handle = tokio::spawn(async move {
            info!(listen = %bind_addr, "AnyTLS listener started");
            loop {
                let (stream, source) = match listener.accept().await {
                    Ok(value) => value,
                    Err(error) => {
                        error!(%error, "accept connection failed");
                        continue;
                    }
                };
                let acceptor = {
                    let tls_config = tls_config.read().expect("tls config lock poisoned").clone();
                    tokio_rustls::TlsAcceptor::from(tls_config)
                };
                let accounting = accounting.clone();
                let padding_scheme = padding_scheme.clone();
                let route_rules = route_rules.clone();
                tokio::spawn(async move {
                    let tls_stream = match acceptor.accept(stream).await {
                        Ok(stream) => stream,
                        Err(error) => {
                            warn!(%error, %source, "TLS handshake failed");
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
                    )
                    .await
                    {
                        warn!(%error, %source, "session terminated with error");
                    }
                });
            }
        });

        let mut guard = self.inner.lock().expect("server controller poisoned");
        *guard = Some(RunningServer { config, handle });
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
