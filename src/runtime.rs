use anyhow::Context;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{Duration, MissedTickBehavior};
use tracing::{debug, error, info, warn};

use crate::accounting::Accounting;
use crate::acme;
use crate::config::AppConfig;
use crate::panel::{FetchState, NodeConfigResponse, PanelClient};
use crate::server::{EffectiveNodeConfig, ServerController};
use crate::status;

const DEFAULT_PANEL_PULL_INTERVAL_SECONDS: u64 = 60;
const DEFAULT_PANEL_PUSH_INTERVAL_SECONDS: u64 = 60;

pub async fn run(config: AppConfig) -> anyhow::Result<()> {
    if let Some(acme_config) = config.tls.acme.as_ref()
        && acme_config.enabled
        && acme::ensure_certificate(acme_config, &config.tls.cert_path, &config.tls.key_path)
            .await?
    {
        info!(domain = %acme_config.domain, "ACME certificate issued or renewed before startup");
    }

    let panel = Arc::new(PanelClient::new(&config.panel)?);
    let accounting = Accounting::new();
    let server = Arc::new(ServerController::new(&config, accounting.clone()).await?);

    let mut config_etag = None;
    let mut user_etag = None;

    let initial = panel.fetch_node_config(config_etag.as_deref()).await?;
    let remote = match initial {
        FetchState::Modified(remote, etag) => {
            config_etag = etag;
            remote
        }
        FetchState::NotModified => unreachable!("initial config fetch cannot be 304"),
    };
    apply_remote_config(&config, &server, &remote).await?;

    match panel.fetch_alive_list().await {
        Ok(alive_list) => accounting.set_external_alive_counts(&alive_list.alive),
        Err(error) => warn!(%error, "initial alive list fetch failed"),
    }

    let initial_users = panel.fetch_users(user_etag.as_deref()).await?;
    if let FetchState::Modified(users, etag) = initial_users {
        accounting.replace_users(&users.users);
        user_etag = etag;
    }

    let pull_interval = Arc::new(AtomicU64::new(pull_interval_seconds(&remote)));
    let push_interval = Arc::new(AtomicU64::new(push_interval_seconds(&remote)));

    let sync_panel = panel.clone();
    let sync_server = server.clone();
    let sync_accounting = accounting.clone();
    let sync_config = config.clone();
    let sync_pull_interval = pull_interval.clone();
    let sync_push_interval = push_interval.clone();
    tokio::spawn(async move {
        let mut config_etag = config_etag;
        let mut user_etag = user_etag;
        loop {
            tokio::time::sleep(Duration::from_secs(
                sync_pull_interval.load(Ordering::Relaxed).max(5),
            ))
            .await;
            match sync_panel.fetch_node_config(config_etag.as_deref()).await {
                Ok(FetchState::Modified(remote, etag)) => {
                    config_etag = etag;
                    sync_pull_interval.store(pull_interval_seconds(&remote), Ordering::Relaxed);
                    sync_push_interval.store(push_interval_seconds(&remote), Ordering::Relaxed);
                    if let Err(error) =
                        apply_remote_config(&sync_config, &sync_server, &remote).await
                    {
                        error!(%error, "apply remote config failed");
                    }
                }
                Ok(FetchState::NotModified) => {}
                Err(error) => warn!(%error, "config sync failed"),
            }

            match sync_panel.fetch_users(user_etag.as_deref()).await {
                Ok(FetchState::Modified(users, etag)) => {
                    user_etag = etag;
                    sync_accounting.replace_users(&users.users);
                    debug!(count = users.users.len(), "users updated");
                }
                Ok(FetchState::NotModified) => {}
                Err(error) => warn!(%error, "user sync failed"),
            }

            match sync_panel.fetch_alive_list().await {
                Ok(alive_list) => {
                    let alive_count = alive_list.alive.len();
                    sync_accounting.set_external_alive_counts(&alive_list.alive);
                    if alive_count > 0 {
                        debug!(alive_count, "panel alive list fetched");
                    }
                }
                Err(error) => warn!(%error, "alive list fetch failed"),
            }
        }
    });

    let tls_server = server.clone();
    let tls_reload_interval = config.tls.reload_interval_seconds.max(5);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(tls_reload_interval));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(error) = tls_server.refresh_tls().await {
                warn!(%error, "TLS material refresh failed");
            }
        }
    });

    if let Some(acme_config) = config.tls.acme.clone().filter(|acme| acme.enabled) {
        let acme_server = server.clone();
        let cert_path = config.tls.cert_path.clone();
        let key_path = config.tls.key_path.clone();
        let acme_interval = acme_config.check_interval_seconds.max(60);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(acme_interval));
            ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                match acme::ensure_certificate(&acme_config, &cert_path, &key_path).await {
                    Ok(true) => {
                        info!(domain = %acme_config.domain, "ACME certificate renewed");
                        if let Err(error) = acme_server.refresh_tls().await {
                            warn!(%error, "refresh TLS after ACME renewal failed");
                        }
                    }
                    Ok(false) => {}
                    Err(error) => warn!(%error, "ACME renewal check failed"),
                }
            }
        });
    }

    let report_panel = panel.clone();
    let report_accounting = accounting.clone();
    let min_traffic_bytes = config.report.min_traffic_bytes;
    let report_push_interval = push_interval.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(
                report_push_interval.load(Ordering::Relaxed).max(5),
            ))
            .await;
            let traffic = report_accounting.snapshot_traffic(min_traffic_bytes);
            if let Err(error) = report_panel.report_traffic(traffic.clone()).await {
                report_accounting.restore_traffic(&traffic);
                warn!(%error, "traffic report failed");
            }
            let alive = report_accounting.snapshot_alive();
            if let Err(error) = report_panel.report_alive(alive).await {
                warn!(%error, "alive report failed");
            }
        }
    });

    let status_panel = panel.clone();
    let status_interval = config.report.status_interval_seconds.max(5);
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(status_interval));
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let payload = status::collect_status();
            if let Err(error) = status_panel.report_status(&payload).await {
                warn!(%error, "status report failed");
            }
        }
    });

    info!("NodeRS-AnyTLS is running; press Ctrl+C to stop");
    tokio::signal::ctrl_c().await.context("wait for Ctrl+C")?;
    Ok(())
}

async fn apply_remote_config(
    app_config: &AppConfig,
    server: &ServerController,
    remote: &NodeConfigResponse,
) -> anyhow::Result<()> {
    if remote.protocol != "anytls" {
        anyhow::bail!("unsupported remote protocol {}", remote.protocol);
    }
    let effective = EffectiveNodeConfig::from_remote(app_config, remote);
    server.apply_config(effective).await
}

fn pull_interval_seconds(remote: &NodeConfigResponse) -> u64 {
    remote
        .base_config
        .as_ref()
        .and_then(|base| base.pull_interval_seconds())
        .unwrap_or(DEFAULT_PANEL_PULL_INTERVAL_SECONDS)
        .max(5)
}

fn push_interval_seconds(remote: &NodeConfigResponse) -> u64 {
    remote
        .base_config
        .as_ref()
        .and_then(|base| base.push_interval_seconds())
        .unwrap_or(DEFAULT_PANEL_PUSH_INTERVAL_SECONDS)
        .max(5)
}
