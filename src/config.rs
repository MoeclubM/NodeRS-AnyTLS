use anyhow::Context;
use serde::{Deserialize, Deserializer};
use std::path::{Path, PathBuf};
use tokio::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub panel: PanelConfig,
    pub node: NodeConfig,
    pub tls: TlsConfig,
    #[serde(default)]
    pub outbound: OutboundConfig,
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
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NodeConfig {
    #[serde(default = "default_listen_ip")]
    pub listen_ip: String,
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

#[derive(Debug, Clone, Deserialize, Default)]
pub struct OutboundConfig {
    #[serde(default)]
    pub dns_resolver: DnsResolver,
    #[serde(default)]
    pub ip_strategy: IpStrategy,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum DnsResolver {
    #[default]
    System,
    Custom(String),
}

impl DnsResolver {
    pub fn nameserver(&self) -> Option<&str> {
        match self {
            Self::System => None,
            Self::Custom(server) => Some(server.as_str()),
        }
    }
}

impl<'de> Deserialize<'de> for DnsResolver {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?.unwrap_or_default();
        let value = value.trim();
        if value.is_empty() || value.eq_ignore_ascii_case("system") {
            Ok(Self::System)
        } else {
            Ok(Self::Custom(value.to_string()))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum IpStrategy {
    #[default]
    System,
    #[serde(alias = "ipv4_prefer", alias = "ipv4_first")]
    PreferIpv4,
    #[serde(alias = "ipv6_prefer", alias = "ipv6_first")]
    PreferIpv6,
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
pub struct ReportConfig {
    #[serde(default = "default_status_interval_seconds")]
    pub status_interval_seconds: u64,
    #[serde(default)]
    pub min_traffic_bytes: u64,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
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

fn default_timeout_seconds() -> u64 {
    15
}

fn default_listen_ip() -> String {
    "::".to_string()
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
    "[::]:80".to_string()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_outbound_defaults_and_aliases() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(default)]
            outbound: OutboundConfig,
        }

        let parsed: Wrapper = toml::from_str(
            r#"
                [outbound]
                dns_resolver = "1.1.1.1"
                ip_strategy = "ipv6_first"
            "#,
        )
        .expect("parse outbound config");

        assert_eq!(
            parsed.outbound.dns_resolver,
            DnsResolver::Custom("1.1.1.1".to_string())
        );
        assert_eq!(parsed.outbound.ip_strategy, IpStrategy::PreferIpv6);

        let defaulted: Wrapper = toml::from_str("").expect("parse defaults");
        assert_eq!(defaulted.outbound.dns_resolver, DnsResolver::System);
        assert_eq!(defaulted.outbound.ip_strategy, IpStrategy::System);
    }
}
