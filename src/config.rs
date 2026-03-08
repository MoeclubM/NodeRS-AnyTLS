use anyhow::Context;
use serde::Deserialize;
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub panel: PanelConfig,
    pub node: NodeConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub sync: SyncConfig,
    #[serde(default)]
    pub report: ReportConfig,
    #[serde(default)]
    pub log: LogConfig,
}

impl AppConfig {
    pub async fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = fs::read_to_string(path).await?;
        let mut config: Self = toml::from_str(&raw).context("parse TOML config")?;
        let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
        if config.node.node_type.is_empty() {
            config.node.node_type = "anytls".to_string();
        }
        resolve_path(base_dir, &mut config.tls.cert_path);
        resolve_path(base_dir, &mut config.tls.key_path);
        if let Some(acme) = &mut config.tls.acme {
            resolve_path(base_dir, &mut acme.account_key_path);
        }
        Ok(config)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct PanelConfig {
    pub url: String,
    pub token: String,
    pub node_id: i64,
    #[serde(default = "default_node_type")]
    pub node_type: String,
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_listen_ip")]
    pub listen_ip: String,
    #[serde(default = "default_node_type")]
    pub node_type: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    #[serde(default)]
    pub server_name: String,
    #[serde(default = "default_tls_reload_interval_seconds")]
    pub reload_interval_seconds: u64,
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AcmeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_acme_directory_url")]
    pub directory_url: String,
    #[serde(default)]
    pub email: String,
    pub domain: String,
    #[serde(default = "default_acme_challenge_listen")]
    pub challenge_listen: String,
    #[serde(default = "default_acme_check_interval_seconds")]
    pub check_interval_seconds: u64,
    #[serde(default = "default_acme_renew_before_days")]
    pub renew_before_days: u64,
    #[serde(default = "default_acme_account_key_path")]
    pub account_key_path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SyncConfig {
    #[serde(default = "default_pull_interval_seconds")]
    pub pull_interval_seconds: u64,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            pull_interval_seconds: default_pull_interval_seconds(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReportConfig {
    #[serde(default = "default_push_interval_seconds")]
    pub push_interval_seconds: u64,
    #[serde(default = "default_status_interval_seconds")]
    pub status_interval_seconds: u64,
    #[serde(default)]
    pub min_traffic_bytes: u64,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            push_interval_seconds: default_push_interval_seconds(),
            status_interval_seconds: default_status_interval_seconds(),
            min_traffic_bytes: 0,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_node_type() -> String {
    "anytls".to_string()
}

fn default_timeout_seconds() -> u64 {
    15
}

fn default_listen_ip() -> String {
    "0.0.0.0".to_string()
}

fn default_pull_interval_seconds() -> u64 {
    60
}

fn default_push_interval_seconds() -> u64 {
    60
}

fn default_status_interval_seconds() -> u64 {
    60
}

fn default_tls_reload_interval_seconds() -> u64 {
    60
}

fn default_acme_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

fn default_acme_challenge_listen() -> String {
    "0.0.0.0:80".to_string()
}

fn default_acme_check_interval_seconds() -> u64 {
    60 * 60 * 24
}

fn default_acme_renew_before_days() -> u64 {
    30
}

fn default_acme_account_key_path() -> PathBuf {
    PathBuf::from("acme-account.pem")
}

fn default_log_level() -> String {
    "info".to_string()
}

fn resolve_path(base_dir: &Path, path: &mut PathBuf) {
    if path.is_relative() {
        *path = base_dir.join(&*path);
    }
}
