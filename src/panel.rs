use anyhow::{Context, bail};
use reqwest::{Client, StatusCode};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::time::Duration;

use crate::config::PanelConfig;

#[derive(Clone)]
pub struct PanelClient {
    client: Client,
    base_url: String,
    token: String,
    node_id: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchState<T> {
    Modified(T, Option<String>),
    NotModified,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct NodeConfigResponse {
    pub protocol: String,
    pub server_port: u16,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub server_name: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub padding_scheme: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub base_config: Option<BaseConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RouteMatch {
    String(String),
    Strings(Vec<String>),
}

impl RouteMatch {
    pub fn items(&self) -> Vec<String> {
        let raw = match self {
            Self::String(text) => text.split(',').map(ToString::to_string).collect(),
            Self::Strings(items) => items.clone(),
        };
        raw.into_iter()
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RouteConfig {
    pub id: i64,
    #[serde(default, rename = "match")]
    pub match_value: Option<RouteMatch>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub action: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub action_value: String,
}

impl RouteConfig {
    pub fn match_items(&self) -> Vec<String> {
        self.match_value
            .as_ref()
            .map(RouteMatch::items)
            .unwrap_or_default()
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct BaseConfig {
    pub push_interval: Option<serde_json::Value>,
    pub pull_interval: Option<serde_json::Value>,
}

impl BaseConfig {
    pub fn push_interval_seconds(&self) -> Option<u64> {
        value_to_u64(self.push_interval.as_ref())
    }

    pub fn pull_interval_seconds(&self) -> Option<u64> {
        value_to_u64(self.pull_interval.as_ref())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct UsersResponse {
    pub users: Vec<PanelUser>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct PanelUser {
    pub id: i64,
    pub uuid: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub speed_limit: i64,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub device_limit: i64,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct AliveListResponse {
    #[serde(default)]
    pub alive: HashMap<String, i64>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct StatusPayload {
    pub cpu: f64,
    pub mem: MemoryStat,
    pub swap: MemoryStat,
    pub disk: MemoryStat,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct MemoryStat {
    pub total: u64,
    pub used: u64,
}

impl PanelClient {
    pub fn new(config: &PanelConfig) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds))
            .build()
            .context("build panel HTTP client")?;
        Ok(Self {
            client,
            base_url: config.url.trim_end_matches('/').to_string(),
            token: config.token.clone(),
            node_id: config.node_id,
        })
    }

    pub async fn fetch_node_config(
        &self,
        etag: Option<&str>,
    ) -> anyhow::Result<FetchState<NodeConfigResponse>> {
        self.fetch_etag("/api/v1/server/UniProxy/config", etag)
            .await
    }

    pub async fn fetch_users(
        &self,
        etag: Option<&str>,
    ) -> anyhow::Result<FetchState<UsersResponse>> {
        self.fetch_etag("/api/v1/server/UniProxy/user", etag).await
    }

    pub async fn fetch_alive_list(&self) -> anyhow::Result<AliveListResponse> {
        let response = self
            .client
            .get(self.url("/api/v1/server/UniProxy/alivelist"))
            .query(&self.query())
            .send()
            .await
            .context("request Xboard alive list")?;
        self.ensure_success(response.status(), "fetch alive list")?;
        response.json().await.context("decode alive list")
    }

    pub async fn report_traffic(&self, traffic: HashMap<i64, [u64; 2]>) -> anyhow::Result<()> {
        if traffic.is_empty() {
            return Ok(());
        }
        let response = self
            .client
            .post(self.url("/api/v1/server/UniProxy/push"))
            .query(&self.query())
            .json(&traffic)
            .send()
            .await
            .context("report traffic")?;
        self.ensure_success(response.status(), "report traffic")
    }

    pub async fn report_alive(&self, alive: HashMap<i64, Vec<String>>) -> anyhow::Result<()> {
        let response = self
            .client
            .post(self.url("/api/v1/server/UniProxy/alive"))
            .query(&self.query())
            .json(&alive)
            .send()
            .await
            .context("report alive")?;
        self.ensure_success(response.status(), "report alive")
    }

    pub async fn report_status(&self, payload: &StatusPayload) -> anyhow::Result<()> {
        let response = self
            .client
            .post(self.url("/api/v1/server/UniProxy/status"))
            .query(&self.query())
            .json(payload)
            .send()
            .await
            .context("report status")?;
        self.ensure_success(response.status(), "report status")
    }

    async fn fetch_etag<T>(&self, path: &str, etag: Option<&str>) -> anyhow::Result<FetchState<T>>
    where
        T: for<'de> Deserialize<'de>,
    {
        let mut request = self.client.get(self.url(path)).query(&self.query());
        if let Some(etag) = etag {
            request = request.header("If-None-Match", etag);
        }
        let response = request
            .send()
            .await
            .with_context(|| format!("request {path}"))?;
        if response.status() == StatusCode::NOT_MODIFIED {
            return Ok(FetchState::NotModified);
        }
        self.ensure_success(response.status(), path)?;
        let new_etag = response
            .headers()
            .get("ETag")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let decoded = response
            .json::<T>()
            .await
            .with_context(|| format!("decode {path} response"))?;
        Ok(FetchState::Modified(decoded, new_etag))
    }

    fn ensure_success(&self, status: StatusCode, action: &str) -> anyhow::Result<()> {
        if status.is_success() {
            Ok(())
        } else {
            bail!("Xboard {action} failed with status {status}")
        }
    }

    fn query(&self) -> [(&str, String); 3] {
        [
            ("token", self.token.clone()),
            ("node_id", self.node_id.to_string()),
            ("node_type", "anytls".to_string()),
        ]
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }
}

fn value_to_u64(value: Option<&serde_json::Value>) -> Option<u64> {
    match value? {
        serde_json::Value::Number(number) => number.as_u64(),
        serde_json::Value::String(text) => text.parse().ok(),
        _ => None,
    }
}

fn deserialize_default_on_null<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_base_config_numbers() {
        let cfg = BaseConfig {
            push_interval: Some(serde_json::json!(120)),
            pull_interval: Some(serde_json::json!("30")),
        };
        assert_eq!(cfg.push_interval_seconds(), Some(120));
        assert_eq!(cfg.pull_interval_seconds(), Some(30));
    }

    #[test]
    fn parses_route_match_from_string() {
        let route: RouteConfig = serde_json::from_value(serde_json::json!({
            "id": 1,
            "match": r" protocol:tcp , regexp:^example\.com$ ",
            "action": "block",
            "action_value": ""
        }))
        .expect("parse route");
        assert_eq!(
            route.match_items(),
            vec![
                "protocol:tcp".to_string(),
                r"regexp:^example\.com$".to_string()
            ]
        );
    }

    #[test]
    fn parses_route_match_from_array() {
        let route: RouteConfig = serde_json::from_value(serde_json::json!({
            "id": 2,
            "match": [r"regexp:^example\.org$", "protocol:udp"],
            "action": "block",
            "action_value": ""
        }))
        .expect("parse route");
        assert_eq!(
            route.match_items(),
            vec![
                r"regexp:^example\.org$".to_string(),
                "protocol:udp".to_string()
            ]
        );
    }

    #[test]
    fn accepts_nulls_in_node_config_response() {
        let config: NodeConfigResponse = serde_json::from_value(serde_json::json!({
            "protocol": "anytls",
            "server_port": 443,
            "server_name": null,
            "padding_scheme": null,
            "routes": null,
            "base_config": {
                "push_interval": 60,
                "pull_interval": 60
            }
        }))
        .expect("parse config");
        assert_eq!(config.server_name, "");
        assert!(config.padding_scheme.is_empty());
        assert!(config.routes.is_empty());
    }

    #[test]
    fn accepts_nulls_in_route_and_user_defaults() {
        let route: RouteConfig = serde_json::from_value(serde_json::json!({
            "id": 9,
            "match": null,
            "action": null,
            "action_value": null
        }))
        .expect("parse route");
        assert_eq!(route.action, "");
        assert_eq!(route.action_value, "");

        let user: PanelUser = serde_json::from_value(serde_json::json!({
            "id": 1,
            "uuid": "test-user",
            "speed_limit": null,
            "device_limit": null
        }))
        .expect("parse user");
        assert_eq!(user.speed_limit, 0);
        assert_eq!(user.device_limit, 0);
    }
}
