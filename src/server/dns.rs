use anyhow::{Context, bail, ensure};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::{UdpSocket, lookup_host};
use tokio::time::timeout;

use crate::config::{IpStrategy, OutboundConfig};

const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_CACHE_TTL: Duration = Duration::from_secs(30);
const DNS_CACHE_MAX_ENTRIES: usize = 1024;
static NEXT_QUERY_ID: AtomicU16 = AtomicU16::new(1);
static DNS_CACHE: OnceLock<Mutex<HashMap<DnsCacheKey, DnsCacheEntry>>> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecordType {
    A = 1,
    Aaaa = 28,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DnsCacheKey {
    host: String,
    nameserver: Option<String>,
    ip_strategy: IpStrategy,
}

#[derive(Debug, Clone)]
struct DnsCacheEntry {
    resolved: Vec<IpAddr>,
    expires_at: Instant,
}

pub async fn resolve_domain(
    host: &str,
    route_nameserver: Option<&str>,
    outbound: &OutboundConfig,
) -> anyhow::Result<Vec<IpAddr>> {
    let nameserver = route_nameserver
        .filter(|value| !value.trim().is_empty())
        .or_else(|| outbound.dns_resolver.nameserver());
    let cache_key = DnsCacheKey {
        host: host.trim().trim_end_matches('.').to_ascii_lowercase(),
        nameserver: nameserver.map(|value| value.trim().to_ascii_lowercase()),
        ip_strategy: outbound.ip_strategy,
    };
    if let Some(cached) = lookup_cached(&cache_key) {
        return Ok(cached);
    }

    let resolved = if let Some(nameserver) = nameserver {
        resolve_with_nameserver(host, nameserver, outbound.ip_strategy).await?
    } else {
        let mut resolved = lookup_host((host, 0))
            .await
            .with_context(|| format!("resolve {host} via system DNS"))?
            .map(|addr| addr.ip())
            .collect::<Vec<_>>();
        reorder_ips(&mut resolved, outbound.ip_strategy);
        dedup_ips(&mut resolved);
        if resolved.is_empty() {
            bail!("no addresses resolved for {host}")
        }
        resolved
    };

    store_cached(cache_key, &resolved);
    Ok(resolved)
}

async fn resolve_with_nameserver(
    host: &str,
    nameserver: &str,
    ip_strategy: IpStrategy,
) -> anyhow::Result<Vec<IpAddr>> {
    let (ipv4, ipv6) = tokio::join!(
        resolve_with_server(host, nameserver, RecordType::A),
        resolve_with_server(host, nameserver, RecordType::Aaaa)
    );

    let mut resolved = Vec::new();
    match ip_strategy {
        IpStrategy::PreferIpv6 => {
            append_query_result(&mut resolved, ipv6.as_ref());
            append_query_result(&mut resolved, ipv4.as_ref());
        }
        IpStrategy::System | IpStrategy::PreferIpv4 => {
            append_query_result(&mut resolved, ipv4.as_ref());
            append_query_result(&mut resolved, ipv6.as_ref());
        }
    }
    dedup_ips(&mut resolved);

    if !resolved.is_empty() {
        return Ok(resolved);
    }

    match (ipv4, ipv6) {
        (Err(error), _) => Err(error),
        (_, Err(error)) => Err(error),
        _ => bail!("no DNS answers for {host} from nameserver {nameserver}"),
    }
}

fn append_query_result(target: &mut Vec<IpAddr>, result: Result<&Vec<IpAddr>, &anyhow::Error>) {
    if let Ok(records) = result {
        target.extend(records.iter().copied());
    }
}

fn reorder_ips(resolved: &mut [IpAddr], ip_strategy: IpStrategy) {
    match ip_strategy {
        IpStrategy::System => {}
        IpStrategy::PreferIpv4 => {
            resolved.sort_by_key(|ip| if ip.is_ipv4() { 0 } else { 1 });
        }
        IpStrategy::PreferIpv6 => {
            resolved.sort_by_key(|ip| if ip.is_ipv6() { 0 } else { 1 });
        }
    }
}

fn dedup_ips(resolved: &mut Vec<IpAddr>) {
    let mut seen = HashSet::new();
    resolved.retain(|ip| seen.insert(*ip));
}

fn lookup_cached(key: &DnsCacheKey) -> Option<Vec<IpAddr>> {
    let cache = DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().expect("DNS cache lock poisoned");
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);
    cache.get(key).map(|entry| entry.resolved.clone())
}

fn store_cached(key: DnsCacheKey, resolved: &[IpAddr]) {
    let cache = DNS_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().expect("DNS cache lock poisoned");
    let now = Instant::now();
    cache.retain(|_, entry| entry.expires_at > now);
    if cache.len() >= DNS_CACHE_MAX_ENTRIES {
        cache.clear();
    }
    cache.insert(
        key,
        DnsCacheEntry {
            resolved: resolved.to_vec(),
            expires_at: now + DNS_CACHE_TTL,
        },
    );
}

async fn resolve_with_server(
    host: &str,
    nameserver: &str,
    record_type: RecordType,
) -> anyhow::Result<Vec<IpAddr>> {
    let servers = resolve_nameserver_endpoints(nameserver).await?;
    let mut last_error = None;
    for server in servers {
        match query_server(server, host, record_type).await {
            Ok(records) if !records.is_empty() => return Ok(records),
            Ok(_) => {}
            Err(error) => last_error = Some(error),
        }
    }
    if let Some(error) = last_error {
        return Err(error);
    }
    Ok(Vec::new())
}

async fn resolve_nameserver_endpoints(spec: &str) -> anyhow::Result<Vec<SocketAddr>> {
    let (host, port) = parse_nameserver_spec(spec)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    let resolved = lookup_host((host.as_str(), port))
        .await
        .with_context(|| format!("resolve nameserver {spec}"))?
        .collect::<Vec<_>>();
    if resolved.is_empty() {
        bail!("no addresses resolved for nameserver {spec}")
    }
    Ok(resolved)
}

fn parse_nameserver_spec(spec: &str) -> anyhow::Result<(String, u16)> {
    let spec = spec.trim().trim_end_matches('/');
    ensure!(!spec.is_empty(), "empty nameserver specification");

    let spec = if let Some(rest) = spec.strip_prefix("udp://") {
        rest
    } else if let Some(rest) = spec.strip_prefix("dns://") {
        rest
    } else if spec.contains("://") {
        bail!("unsupported DNS scheme in {spec}")
    } else {
        spec
    };

    if let Ok(ip) = spec.parse::<IpAddr>() {
        return Ok((ip.to_string(), 53));
    }

    if let Ok(addr) = spec.parse::<SocketAddr>() {
        return Ok((addr.ip().to_string(), addr.port()));
    }

    if let Some(host) = spec.strip_prefix('[') {
        let (host, port) = host
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("invalid bracketed nameserver {spec}"))?;
        if port.is_empty() {
            return Ok((host.to_string(), 53));
        }
        let port = port
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("invalid bracketed nameserver {spec}"))?
            .parse::<u16>()?;
        return Ok((host.to_string(), port));
    }

    if let Some((host, port)) = spec.rsplit_once(':')
        && !host.contains(':')
    {
        return Ok((host.to_string(), port.parse::<u16>()?));
    }

    Ok((spec.to_string(), 53))
}

async fn query_server(
    server: SocketAddr,
    host: &str,
    record_type: RecordType,
) -> anyhow::Result<Vec<IpAddr>> {
    let bind_addr = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind_addr)
        .await
        .with_context(|| format!("bind UDP socket for DNS query to {server}"))?;
    let id = NEXT_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let query = build_query(host, record_type, id)?;
    socket
        .send_to(&query, server)
        .await
        .with_context(|| format!("send DNS query to {server}"))?;

    let mut response = [0u8; 1500];
    let (received, from) = timeout(DNS_TIMEOUT, socket.recv_from(&mut response))
        .await
        .context("DNS query timed out")?
        .with_context(|| format!("read DNS response from {server}"))?;
    ensure!(
        from.ip() == server.ip(),
        "unexpected DNS response source {from}"
    );
    parse_response(&response[..received], id, record_type)
}

fn build_query(host: &str, record_type: RecordType, id: u16) -> anyhow::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    encode_name(host, &mut packet)?;
    packet.extend_from_slice(&(record_type as u16).to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes());
    Ok(packet)
}

fn encode_name(host: &str, packet: &mut Vec<u8>) -> anyhow::Result<()> {
    let normalized = host.trim().trim_end_matches('.');
    ensure!(!normalized.is_empty(), "DNS host must not be empty");
    for label in normalized.split('.') {
        ensure!(!label.is_empty(), "DNS label must not be empty");
        ensure!(label.len() <= 63, "DNS label too long in {host}");
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    Ok(())
}

fn parse_response(packet: &[u8], id: u16, record_type: RecordType) -> anyhow::Result<Vec<IpAddr>> {
    ensure!(packet.len() >= 12, "DNS response too short");
    ensure!(read_u16(packet, 0)? == id, "DNS transaction ID mismatch");
    let flags = read_u16(packet, 2)?;
    ensure!(flags & 0x8000 != 0, "DNS response missing QR bit");
    let rcode = flags & 0x000f;
    ensure!(rcode == 0, "DNS server returned rcode {rcode}");

    let questions = read_u16(packet, 4)? as usize;
    let answers = read_u16(packet, 6)? as usize;
    let mut offset = 12usize;

    for _ in 0..questions {
        offset = skip_name(packet, offset)?;
        ensure!(offset + 4 <= packet.len(), "DNS question truncated");
        offset += 4;
    }

    let mut records = Vec::new();
    for _ in 0..answers {
        offset = skip_name(packet, offset)?;
        ensure!(offset + 10 <= packet.len(), "DNS answer header truncated");
        let rr_type = read_u16(packet, offset)?;
        let rr_class = read_u16(packet, offset + 2)?;
        let rd_len = read_u16(packet, offset + 8)? as usize;
        offset += 10;
        ensure!(
            offset + rd_len <= packet.len(),
            "DNS answer payload truncated"
        );
        if rr_class == 1 {
            match (rr_type, record_type, rd_len) {
                (1, RecordType::A, 4) => records.push(IpAddr::V4(Ipv4Addr::new(
                    packet[offset],
                    packet[offset + 1],
                    packet[offset + 2],
                    packet[offset + 3],
                ))),
                (28, RecordType::Aaaa, 16) => {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&packet[offset..offset + 16]);
                    records.push(IpAddr::V6(Ipv6Addr::from(octets)));
                }
                _ => {}
            }
        }
        offset += rd_len;
    }

    Ok(records)
}

fn skip_name(packet: &[u8], mut offset: usize) -> anyhow::Result<usize> {
    loop {
        ensure!(offset < packet.len(), "DNS name out of bounds");
        let len = packet[offset];
        if len & 0b1100_0000 == 0b1100_0000 {
            ensure!(offset + 1 < packet.len(), "DNS pointer truncated");
            return Ok(offset + 2);
        }
        if len == 0 {
            return Ok(offset + 1);
        }
        offset += 1;
        ensure!(offset + len as usize <= packet.len(), "DNS label truncated");
        offset += len as usize;
    }
}

fn read_u16(packet: &[u8], offset: usize) -> anyhow::Result<u16> {
    ensure!(offset + 2 <= packet.len(), "read_u16 out of bounds");
    Ok(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nameserver_spec_with_default_port() {
        assert_eq!(
            parse_nameserver_spec("1.1.1.1").expect("parse"),
            ("1.1.1.1".to_string(), 53)
        );
        assert_eq!(
            parse_nameserver_spec("udp://8.8.8.8:5353").expect("parse"),
            ("8.8.8.8".to_string(), 5353)
        );
        assert_eq!(
            parse_nameserver_spec("[2606:4700:4700::1111]:53").expect("parse"),
            ("2606:4700:4700::1111".to_string(), 53)
        );
    }

    #[test]
    fn builds_query_with_question() {
        let query = build_query("example.com", RecordType::A, 0x1234).expect("build query");
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        assert!(query.ends_with(&[0x00, 0x01, 0x00, 0x01]));
    }

    #[test]
    fn parses_a_record_response() {
        let response = [
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
            b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
            0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 0x01,
            0x02, 0x03, 0x04,
        ];
        let parsed = parse_response(&response, 0x1234, RecordType::A).expect("parse response");
        assert_eq!(parsed, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
    }

    #[test]
    fn reorders_ips_by_strategy() {
        let mut ips = vec![
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ];
        reorder_ips(&mut ips, IpStrategy::PreferIpv4);
        assert!(ips[0].is_ipv4());
        assert!(ips[1].is_ipv4());

        reorder_ips(&mut ips, IpStrategy::PreferIpv6);
        assert!(ips[0].is_ipv6());
    }

    #[test]
    fn deduplicates_while_preserving_order() {
        let mut ips = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
        ];
        dedup_ips(&mut ips);
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0], IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(ips[1], IpAddr::V6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn stores_and_returns_cached_records() {
        let key = DnsCacheKey {
            host: "example.com".to_string(),
            nameserver: None,
            ip_strategy: IpStrategy::System,
        };
        store_cached(key.clone(), &[IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);

        let lookup = DnsCacheKey {
            host: "example.com".to_string(),
            nameserver: None,
            ip_strategy: IpStrategy::System,
        };
        assert_eq!(
            lookup_cached(&lookup),
            Some(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))])
        );
    }
}
