use anyhow::{Context, bail};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::net::UdpSocket;
use tracing::warn;

use crate::accounting::SessionControl;
use crate::config::OutboundConfig;
use crate::limiter::SharedRateLimiter;

use super::rules::RouteRules;
use super::socksaddr::SocksAddr;
use super::traffic::TrafficRecorder;
use super::transport;

pub const MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";
pub const LEGACY_MAGIC_ADDRESS: &str = "sp.udp-over-tcp.arpa";

const AF_IPV4: u8 = 0x00;
const AF_IPV6: u8 = 0x01;
const AF_FQDN: u8 = 0x02;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UotVersion {
    V2,
    Legacy,
}

#[derive(Debug, Clone)]
pub struct UotRequest {
    pub is_connect: bool,
    pub destination: Option<SocksAddr>,
}

pub struct PreparedUotRelay {
    socket: Arc<UdpSocket>,
    mode: RelayMode,
    route_rules: RouteRules,
    outbound: OutboundConfig,
}

#[derive(Clone)]
struct UdpRelayContext {
    socket: Arc<UdpSocket>,
    mode: RelayMode,
    control: Arc<SessionControl>,
    limiter: Option<Arc<SharedRateLimiter>>,
    traffic: TrafficRecorder,
}

#[derive(Debug, Clone)]
enum RelayMode {
    Connect { destination: SocksAddr },
    Associate,
}

#[derive(Debug)]
struct ClientPacket {
    destination: SocksAddr,
    payload: Vec<u8>,
    wire_len: usize,
}

pub fn version_for(destination: &SocksAddr) -> Option<UotVersion> {
    match destination {
        SocksAddr::Domain(host, _) if host.eq_ignore_ascii_case(MAGIC_ADDRESS) => {
            Some(UotVersion::V2)
        }
        SocksAddr::Domain(host, _) if host.eq_ignore_ascii_case(LEGACY_MAGIC_ADDRESS) => {
            Some(UotVersion::Legacy)
        }
        _ => None,
    }
}

pub async fn read_request<R>(reader: &mut R, version: UotVersion) -> anyhow::Result<UotRequest>
where
    R: AsyncRead + Unpin,
{
    match version {
        UotVersion::V2 => {
            let is_connect = reader.read_u8().await.context("read UOT request mode")? != 0;
            let destination = SocksAddr::read_from(reader)
                .await
                .context("read UOT request destination")?;
            Ok(UotRequest {
                is_connect,
                destination: Some(destination),
            })
        }
        UotVersion::Legacy => Ok(UotRequest {
            is_connect: false,
            destination: None,
        }),
    }
}

pub async fn prepare(
    request: UotRequest,
    route_rules: &RouteRules,
    outbound: &OutboundConfig,
) -> anyhow::Result<PreparedUotRelay> {
    let socket = Arc::new(bind_udp_socket().await?);
    let mode = if request.is_connect {
        let destination = request
            .destination
            .clone()
            .ok_or_else(|| anyhow::anyhow!("missing UOT connect destination"))?;
        if route_rules.is_blocked(&destination, "udp") {
            bail!("destination blocked by Xboard route rules: {destination}");
        }
        let target = transport::resolve_destination(&destination, route_rules, outbound)
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("no UDP addresses resolved for {destination}"))?;
        socket
            .connect(target)
            .await
            .with_context(|| format!("connect UDP socket to {target}"))?;
        RelayMode::Connect { destination }
    } else {
        RelayMode::Associate
    };
    Ok(PreparedUotRelay {
        socket,
        mode,
        route_rules: route_rules.clone(),
        outbound: outbound.clone(),
    })
}

impl PreparedUotRelay {
    pub async fn run(
        self,
        app_side: DuplexStream,
        control: Arc<SessionControl>,
        limiter: Option<Arc<SharedRateLimiter>>,
        upload: TrafficRecorder,
        download: TrafficRecorder,
    ) -> anyhow::Result<()> {
        let (reader, writer) = tokio::io::split(app_side);
        let route_rules = self.route_rules.clone();
        let outbound = self.outbound.clone();
        let select_control = control.clone();
        let client_context = UdpRelayContext {
            socket: self.socket.clone(),
            mode: self.mode.clone(),
            control: control.clone(),
            limiter: limiter.clone(),
            traffic: upload,
        };
        let server_context = UdpRelayContext {
            socket: self.socket.clone(),
            mode: self.mode.clone(),
            control,
            limiter,
            traffic: download,
        };

        let mut client_task = tokio::spawn(async move {
            relay_client_to_udp(reader, client_context, route_rules, outbound).await
        });
        let mut server_task =
            tokio::spawn(async move { relay_udp_to_client(writer, server_context).await });

        tokio::select! {
            _ = select_control.cancelled() => {
                client_task.abort();
                server_task.abort();
                Ok(())
            }
            result = &mut client_task => {
                server_task.abort();
                flatten_join(result)
            }
            result = &mut server_task => {
                client_task.abort();
                flatten_join(result)
            }
        }
    }
}

async fn relay_client_to_udp(
    mut reader: ReadHalf<DuplexStream>,
    context: UdpRelayContext,
    route_rules: RouteRules,
    outbound: OutboundConfig,
) -> anyhow::Result<()> {
    let mut destination_cache = HashMap::new();
    loop {
        if context.control.is_cancelled() {
            return Ok(());
        }
        let Some(packet) = read_client_packet(&mut reader, &context.mode).await? else {
            return Ok(());
        };
        if route_rules.is_blocked(&packet.destination, "udp") {
            warn!(destination = %packet.destination, "dropping blocked UOT packet");
            continue;
        }
        if let Some(limiter) = &context.limiter {
            limiter.consume(packet.wire_len).await;
            if context.control.is_cancelled() {
                return Ok(());
            }
        }
        let sent = match &context.mode {
            RelayMode::Connect { .. } => tokio::select! {
                _ = context.control.cancelled() => return Ok(()),
                sent = context.socket.send(&packet.payload) => sent.context("send connected UDP payload")?,
            },
            RelayMode::Associate => {
                let target = resolve_udp_target(
                    &packet.destination,
                    &route_rules,
                    &outbound,
                    &mut destination_cache,
                )
                .await?;
                tokio::select! {
                    _ = context.control.cancelled() => return Ok(()),
                    sent = context.socket.send_to(&packet.payload, target) => sent.with_context(|| format!("send UDP payload to {target}"))?,
                }
            }
        };
        if sent != packet.payload.len() {
            bail!(
                "short UDP send: expected {}, wrote {}",
                packet.payload.len(),
                sent
            );
        }
        context.traffic.record(packet.wire_len as u64);
    }
}

async fn relay_udp_to_client(
    mut writer: WriteHalf<DuplexStream>,
    context: UdpRelayContext,
) -> anyhow::Result<()> {
    let mut buffer = vec![0u8; u16::MAX as usize];
    loop {
        if context.control.is_cancelled() {
            return Ok(());
        }
        let (payload_len, source) = match &context.mode {
            RelayMode::Connect { .. } => {
                let read = tokio::select! {
                    _ = context.control.cancelled() => return Ok(()),
                    read = context.socket.recv(&mut buffer) => read.context("receive connected UDP payload")?,
                };
                let source = context
                    .socket
                    .peer_addr()
                    .context("read connected UDP peer address")?;
                (read, source)
            }
            RelayMode::Associate => tokio::select! {
                _ = context.control.cancelled() => return Ok(()),
                read = context.socket.recv_from(&mut buffer) => read.context("receive UDP payload")?,
            },
        };
        let encoded = encode_server_packet(
            &context.mode,
            &SocksAddr::Ip(source),
            &buffer[..payload_len],
        )?;
        if let Some(limiter) = &context.limiter {
            limiter.consume(encoded.len()).await;
            if context.control.is_cancelled() {
                return Ok(());
            }
        }
        tokio::select! {
            _ = context.control.cancelled() => return Ok(()),
            result = writer.write_all(&encoded) => result.context("write UOT response to AnyTLS stream")?,
        }
        context.traffic.record(encoded.len() as u64);
    }
}

async fn resolve_udp_target(
    destination: &SocksAddr,
    route_rules: &RouteRules,
    outbound: &OutboundConfig,
    cache: &mut HashMap<String, SocketAddr>,
) -> anyhow::Result<SocketAddr> {
    let cache_key = destination.to_string();
    if let Some(target) = cache.get(&cache_key) {
        return Ok(*target);
    }
    let target = transport::resolve_destination(destination, route_rules, outbound)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no UDP addresses resolved for {destination}"))?;
    cache.insert(cache_key, target);
    Ok(target)
}

async fn read_client_packet<R>(
    reader: &mut R,
    mode: &RelayMode,
) -> anyhow::Result<Option<ClientPacket>>
where
    R: AsyncRead + Unpin,
{
    match mode {
        RelayMode::Connect { destination } => {
            let Some(length) = read_length_or_eof(reader).await? else {
                return Ok(None);
            };
            let mut payload = vec![0u8; length as usize];
            reader
                .read_exact(&mut payload)
                .await
                .context("read connected UOT packet payload")?;
            Ok(Some(ClientPacket {
                destination: destination.clone(),
                payload,
                wire_len: 2 + length as usize,
            }))
        }
        RelayMode::Associate => {
            let Some((destination, addr_len)) = read_uot_destination(reader).await? else {
                return Ok(None);
            };
            let length = reader.read_u16().await.context("read UOT packet length")?;
            let mut payload = vec![0u8; length as usize];
            reader
                .read_exact(&mut payload)
                .await
                .context("read UOT packet payload")?;
            Ok(Some(ClientPacket {
                destination,
                payload,
                wire_len: addr_len + 2 + length as usize,
            }))
        }
    }
}

async fn read_length_or_eof<R>(reader: &mut R) -> anyhow::Result<Option<u16>>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    match reader.read_exact(&mut bytes).await {
        Ok(_) => Ok(Some(u16::from_be_bytes(bytes))),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error).context("read UOT packet length"),
    }
}

async fn read_uot_destination<R>(reader: &mut R) -> anyhow::Result<Option<(SocksAddr, usize)>>
where
    R: AsyncRead + Unpin,
{
    let family = match reader.read_u8().await {
        Ok(family) => family,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error).context("read UOT address family"),
    };
    let destination = match family {
        AF_IPV4 => {
            let mut octets = [0u8; 4];
            reader
                .read_exact(&mut octets)
                .await
                .context("read UOT IPv4 address")?;
            let port = reader.read_u16().await.context("read UOT port")?;
            (
                SocksAddr::Ip(SocketAddr::new(IpAddr::from(octets), port)),
                1 + 4 + 2,
            )
        }
        AF_IPV6 => {
            let mut octets = [0u8; 16];
            reader
                .read_exact(&mut octets)
                .await
                .context("read UOT IPv6 address")?;
            let port = reader.read_u16().await.context("read UOT port")?;
            (
                SocksAddr::Ip(SocketAddr::new(IpAddr::from(octets), port)),
                1 + 16 + 2,
            )
        }
        AF_FQDN => {
            let length = reader.read_u8().await.context("read UOT domain length")?;
            let mut domain = vec![0u8; length as usize];
            reader
                .read_exact(&mut domain)
                .await
                .context("read UOT domain")?;
            let port = reader.read_u16().await.context("read UOT port")?;
            (
                SocksAddr::Domain(
                    String::from_utf8(domain).context("decode UOT domain")?,
                    port,
                ),
                1 + 1 + length as usize + 2,
            )
        }
        other => bail!("unsupported UOT address family {other:#x}"),
    };
    Ok(Some(destination))
}

fn encode_server_packet(
    mode: &RelayMode,
    source: &SocksAddr,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        bail!("UDP payload too large: {}", payload.len());
    }
    let mut encoded = match mode {
        RelayMode::Connect { .. } => Vec::with_capacity(2 + payload.len()),
        RelayMode::Associate => {
            let mut bytes = Vec::with_capacity(address_wire_len(source) + 2 + payload.len());
            write_uot_destination(&mut bytes, source)?;
            bytes
        }
    };
    encoded.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    encoded.extend_from_slice(payload);
    Ok(encoded)
}

fn write_uot_destination(buffer: &mut Vec<u8>, destination: &SocksAddr) -> anyhow::Result<()> {
    match destination {
        SocksAddr::Ip(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                buffer.push(AF_IPV4);
                buffer.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                buffer.push(AF_IPV6);
                buffer.extend_from_slice(&ip.octets());
            }
        },
        SocksAddr::Domain(host, _) => {
            let host = host.as_bytes();
            if host.len() > u8::MAX as usize {
                bail!("UOT domain too long: {}", host.len());
            }
            buffer.push(AF_FQDN);
            buffer.push(host.len() as u8);
            buffer.extend_from_slice(host);
        }
    }
    let port = match destination {
        SocksAddr::Ip(addr) => addr.port(),
        SocksAddr::Domain(_, port) => *port,
    };
    buffer.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn address_wire_len(destination: &SocksAddr) -> usize {
    match destination {
        SocksAddr::Ip(addr) if addr.is_ipv4() => 1 + 4 + 2,
        SocksAddr::Ip(_) => 1 + 16 + 2,
        SocksAddr::Domain(host, _) => 1 + 1 + host.len() + 2,
    }
}

async fn bind_udp_socket() -> anyhow::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .context("create IPv6 UDP socket")?;
    socket.set_reuse_address(true).ok();
    socket.set_only_v6(false).ok();
    if socket
        .bind(&SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).into())
        .is_ok()
    {
        socket
            .set_nonblocking(true)
            .context("set IPv6 UDP socket nonblocking")?;
        let std_socket: std::net::UdpSocket = socket.into();
        return UdpSocket::from_std(std_socket).context("adopt IPv6 UDP socket");
    }

    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
        .context("create IPv4 UDP socket")?;
    socket.set_reuse_address(true).ok();
    socket
        .bind(&SocketAddr::from(([0, 0, 0, 0], 0)).into())
        .context("bind IPv4 UDP socket")?;
    socket
        .set_nonblocking(true)
        .context("set IPv4 UDP socket nonblocking")?;
    let std_socket: std::net::UdpSocket = socket.into();
    UdpSocket::from_std(std_socket).context("adopt IPv4 UDP socket")
}

fn flatten_join(result: Result<anyhow::Result<()>, tokio::task::JoinError>) -> anyhow::Result<()> {
    match result {
        Ok(result) => result,
        Err(error) if error.is_cancelled() => Ok(()),
        Err(error) => Err(error).context("join UOT relay task"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_magic_addresses() {
        assert_eq!(
            version_for(&SocksAddr::Domain(MAGIC_ADDRESS.to_string(), 0)),
            Some(UotVersion::V2)
        );
        assert_eq!(
            version_for(&SocksAddr::Domain(LEGACY_MAGIC_ADDRESS.to_string(), 0)),
            Some(UotVersion::Legacy)
        );
        assert_eq!(
            version_for(&SocksAddr::Domain("example.com".to_string(), 0)),
            None
        );
    }

    #[tokio::test]
    async fn reads_v2_request() {
        let mut bytes = &b"\x01\x03\x0bexample.com\x00\x35"[..];
        let request = read_request(&mut bytes, UotVersion::V2)
            .await
            .expect("read request");
        assert!(request.is_connect);
        assert_eq!(
            request.destination,
            Some(SocksAddr::Domain("example.com".to_string(), 53))
        );
    }

    #[tokio::test]
    async fn reads_associate_packet_destination() {
        let mut bytes = &b"\x02\x0bexample.com\x01\xbb\x00\x05hello"[..];
        let packet = read_client_packet(&mut bytes, &RelayMode::Associate)
            .await
            .expect("read packet")
            .expect("packet exists");
        assert_eq!(
            packet.destination,
            SocksAddr::Domain("example.com".to_string(), 443)
        );
        assert_eq!(packet.payload, b"hello");
        assert_eq!(packet.wire_len, 1 + 1 + 11 + 2 + 2 + 5);
    }

    #[test]
    fn encodes_associate_response() {
        let encoded = encode_server_packet(
            &RelayMode::Associate,
            &SocksAddr::Ip(SocketAddr::from(([1, 2, 3, 4], 53))),
            b"abc",
        )
        .expect("encode response");
        assert_eq!(encoded, b"\x00\x01\x02\x03\x04\x005\x00\x03abc");
    }
}
