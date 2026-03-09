use anyhow::{Context, bail};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use crate::config::{IpStrategy, OutboundConfig};

use super::configure_tcp_stream;
use super::dns;
use super::rules::RouteRules;
use super::socksaddr::SocksAddr;

const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn connect_tcp_destination(
    destination: &SocksAddr,
    route_rules: &RouteRules,
    outbound: &OutboundConfig,
) -> anyhow::Result<TcpStream> {
    match destination {
        SocksAddr::Ip(addr) => connect_target(*addr)
            .await
            .context("connect IP destination"),
        SocksAddr::Domain(host, port) => {
            let resolved = resolve_destination(destination, route_rules, outbound)
                .await
                .with_context(|| format!("resolve {host}:{port}"))?;
            let mut last_error = None;
            let mut attempts = JoinSet::new();
            for (target, delay) in dial_plan(&resolved, outbound.ip_strategy) {
                attempts.spawn(async move {
                    if !delay.is_zero() {
                        sleep(delay).await;
                    }
                    connect_target(target)
                        .await
                        .map_err(|error| (target, error))
                });
            }
            while let Some(result) = attempts.join_next().await {
                match result {
                    Ok(Ok(stream)) => {
                        attempts.abort_all();
                        return Ok(stream);
                    }
                    Ok(Err((target, error))) => last_error = Some((target, error)),
                    Err(error) => {
                        last_error = Some((
                            SocketAddr::from(([0, 0, 0, 0], *port)),
                            std::io::Error::other(format!("dial task failed: {error}")),
                        ));
                    }
                }
            }
            if let Some((target, error)) = last_error {
                return Err(error).with_context(|| format!("connect {host}:{port} via {target}"));
            }
            bail!("no addresses resolved for {host}:{port}")
        }
    }
}

pub async fn resolve_destination(
    destination: &SocksAddr,
    route_rules: &RouteRules,
    outbound: &OutboundConfig,
) -> anyhow::Result<Vec<SocketAddr>> {
    match destination {
        SocksAddr::Ip(addr) => Ok(vec![*addr]),
        SocksAddr::Domain(host, port) => {
            let dns_server = route_rules.dns_server_for(host);
            let resolved = dns::resolve_domain(host, dns_server, outbound)
                .await
                .with_context(|| format!("resolve {host}:{port}"))?;
            if resolved.is_empty() {
                bail!("no addresses resolved for {host}:{port}");
            }
            Ok(resolved
                .into_iter()
                .map(|ip| SocketAddr::new(ip, *port))
                .collect())
        }
    }
}

async fn connect_target(target: SocketAddr) -> std::io::Result<TcpStream> {
    let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "connect timed out"))??;
    configure_tcp_stream(&stream);
    Ok(stream)
}

fn dial_plan(resolved: &[SocketAddr], ip_strategy: IpStrategy) -> Vec<(SocketAddr, Duration)> {
    if resolved.is_empty() {
        return Vec::new();
    }

    match ip_strategy {
        IpStrategy::System => resolved
            .iter()
            .copied()
            .map(|addr| (addr, Duration::ZERO))
            .collect(),
        IpStrategy::PreferIpv4 | IpStrategy::PreferIpv6 => {
            let (preferred, fallback): (Vec<_>, Vec<_>) = resolved
                .iter()
                .copied()
                .partition(|addr| prefers_family(*addr, ip_strategy));
            if preferred.is_empty() || fallback.is_empty() {
                return resolved
                    .iter()
                    .copied()
                    .map(|addr| (addr, Duration::ZERO))
                    .collect();
            }

            preferred
                .into_iter()
                .map(|addr| (addr, Duration::ZERO))
                .chain(
                    fallback
                        .into_iter()
                        .map(|addr| (addr, HAPPY_EYEBALLS_DELAY)),
                )
                .collect()
        }
    }
}

fn prefers_family(addr: SocketAddr, ip_strategy: IpStrategy) -> bool {
    match ip_strategy {
        IpStrategy::PreferIpv4 => addr.is_ipv4(),
        IpStrategy::PreferIpv6 => addr.is_ipv6(),
        IpStrategy::System => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefer_ipv6_dials_ipv4_after_fallback_delay() {
        let plan = dial_plan(
            &[
                SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 443)),
                SocketAddr::from(([127, 0, 0, 1], 443)),
            ],
            IpStrategy::PreferIpv6,
        );
        assert_eq!(plan[0].1, Duration::ZERO);
        assert_eq!(plan[1].1, HAPPY_EYEBALLS_DELAY);
        assert!(plan[0].0.is_ipv6());
        assert!(plan[1].0.is_ipv4());
    }

    #[test]
    fn system_strategy_keeps_parallel_attempts() {
        let plan = dial_plan(
            &[
                SocketAddr::from(([127, 0, 0, 1], 80)),
                SocketAddr::from(([127, 0, 0, 2], 80)),
            ],
            IpStrategy::System,
        );
        assert!(plan.iter().all(|(_, delay)| delay.is_zero()));
    }
}
