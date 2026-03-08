use anyhow::{Context, bail};
use std::net::SocketAddr;
use tokio::net::TcpStream;

use crate::config::OutboundConfig;

use super::dns;
use super::rules::RouteRules;
use super::socksaddr::SocksAddr;

pub async fn connect_tcp_destination(
    destination: &SocksAddr,
    route_rules: &RouteRules,
    outbound: &OutboundConfig,
) -> anyhow::Result<TcpStream> {
    match destination {
        SocksAddr::Ip(addr) => TcpStream::connect(addr)
            .await
            .context("connect IP destination"),
        SocksAddr::Domain(host, port) => {
            let resolved = resolve_destination(destination, route_rules, outbound)
                .await
                .with_context(|| format!("resolve {host}:{port}"))?;
            let mut last_error = None;
            for target in resolved {
                match TcpStream::connect(target).await {
                    Ok(stream) => return Ok(stream),
                    Err(error) => last_error = Some((target, error)),
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
