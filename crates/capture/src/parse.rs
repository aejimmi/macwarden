//! Raw frame bytes → [`PacketRecord`] (spec R3).
//!
//! The link/IP/transport decode reuses the vendored sniffnet parse path —
//! `get_sniffable_headers` (see [`crate::link`]) and the address/port/protocol
//! extraction of `analyze_headers` — over `etherparse` directly. We do **not**
//! depend on the sniffnet binary crate; we port the ~40 lines of header
//! analysis that matter.
//!
//! Parsing is total over arbitrary bytes: any malformed or truncated frame
//! yields a typed [`ParseError`] the caller treats as "skip", never a panic.

use crate::error::ParseError;
use crate::link::{LinkType, sniffable_headers};
use crate::tls::{TlsInfo, parse_tls};
use crate::types::{AppProto, Direction, L4Proto, SocketEndpoint, Timestamp};
use etherparse::{ArpPacket, LaxPacketHeaders, LaxPayloadSlice, NetHeaders, TransportHeader};
use std::net::IpAddr;

/// A single parsed packet. Carries TLS **handshake** fields and, when built via
/// [`parse_frame`], retains the raw frame bytes for the hex/decode view — but
/// has **no** field that could hold a decrypted application-data body (spec
/// R1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketRecord {
    /// Monotonic per-trace sequence number, assigned by the caller.
    pub seq: u64,
    /// Capture time.
    pub ts: Timestamp,
    /// Source endpoint (address + optional port).
    pub src: SocketEndpoint,
    /// Destination endpoint (address + optional port).
    pub dst: SocketEndpoint,
    /// Transport protocol.
    pub proto: L4Proto,
    /// On-wire frame length in bytes.
    pub length: u32,
    /// Direction relative to the local host.
    pub direction: Direction,
    /// Best-effort application protocol (port + payload heuristic).
    pub app_proto: AppProto,
    /// Server name from a TLS Client Hello, when present.
    pub sni: Option<String>,
    /// Handshake-only TLS metadata (spec R4), when the payload is a TLS record.
    pub tls: Option<TlsInfo>,
    /// One-line, Proxyman-style human summary.
    pub summary: String,
    /// The raw frame bytes, retained for the hex dump and decode tree (R5).
    pub raw: Vec<u8>,
    /// The link type these bytes were captured with (needed to decode later).
    pub link_type: LinkType,
}

/// Parse a raw captured frame into a [`PacketRecord`].
///
/// * `raw` — the on-wire frame bytes (starting at the link layer).
/// * `link_type` — the interface's data-link type.
/// * `seq` / `ts` — caller-assigned sequence number and capture time.
/// * `local_ips` — the capturing interface's own addresses, used to derive
///   [`Direction`]. An empty slice yields [`Direction::Inbound`] for all
///   packets (unknown locality).
pub fn parse_frame(
    raw: &[u8],
    link_type: LinkType,
    seq: u64,
    ts: Timestamp,
    local_ips: &[IpAddr],
) -> Result<PacketRecord, ParseError> {
    let headers = sniffable_headers(raw, link_type)?;
    let (src_ip, dst_ip) = network_addresses(&headers)?;
    let (sport, dport, proto) = transport_ports(&headers);

    let src = SocketEndpoint::new(src_ip, sport);
    let dst = SocketEndpoint::new(dst_ip, dport);
    let direction = if local_ips.contains(&src_ip) {
        Direction::Outbound
    } else {
        Direction::Inbound
    };

    let payload = transport_payload(&headers);
    let tls = tls_payload(proto, sport, dport, payload);
    let sni = tls.as_ref().and_then(|t| t.sni.clone());
    let app_proto = classify_app_proto(proto, sport, dport, payload, tls.as_ref());

    let summary = build_summary(&src, &dst, proto, app_proto, sni.as_deref());
    Ok(PacketRecord {
        seq,
        ts,
        src,
        dst,
        proto,
        length: raw.len() as u32,
        direction,
        app_proto,
        sni,
        tls,
        summary,
        raw: raw.to_vec(),
        link_type,
    })
}

/// Source/destination IPs from the network header (IPv4/IPv6/ARP). Ports and
/// the presence of a transport layer are handled separately.
fn network_addresses(headers: &LaxPacketHeaders) -> Result<(IpAddr, IpAddr), ParseError> {
    match &headers.net {
        Some(NetHeaders::Ipv4(h, _)) => Ok((IpAddr::from(h.source), IpAddr::from(h.destination))),
        Some(NetHeaders::Ipv6(h, _)) => Ok((IpAddr::from(h.source), IpAddr::from(h.destination))),
        Some(NetHeaders::Arp(arp)) => arp_addresses(arp),
        None => Err(ParseError::NoNetworkLayer),
    }
}

/// Extract IPv4/IPv6 sender/target protocol addresses from an ARP packet,
/// mirroring sniffnet's `analyze_network_header` ARP arm.
fn arp_addresses(arp: &ArpPacket) -> Result<(IpAddr, IpAddr), ParseError> {
    let sender: &[u8] = arp.sender_protocol_addr();
    let target: &[u8] = arp.target_protocol_addr();
    let to_ip = |b: &[u8]| -> Option<IpAddr> {
        if let Ok(v4) = <[u8; 4]>::try_from(b) {
            Some(IpAddr::from(v4))
        } else if let Ok(v6) = <[u8; 16]>::try_from(b) {
            Some(IpAddr::from(v6))
        } else {
            None
        }
    };
    match (to_ip(sender), to_ip(target)) {
        (Some(s), Some(t)) => Ok((s, t)),
        _ => Err(ParseError::NoNetworkLayer),
    }
}

/// Ports + protocol from the transport header. ARP/ICMP/other carry no ports.
fn transport_ports(headers: &LaxPacketHeaders) -> (Option<u16>, Option<u16>, L4Proto) {
    if matches!(&headers.net, Some(NetHeaders::Arp(_))) {
        return (None, None, L4Proto::Arp);
    }
    match &headers.transport {
        Some(TransportHeader::Tcp(t)) => {
            (Some(t.source_port), Some(t.destination_port), L4Proto::Tcp)
        }
        Some(TransportHeader::Udp(u)) => {
            (Some(u.source_port), Some(u.destination_port), L4Proto::Udp)
        }
        Some(TransportHeader::Icmpv4(_) | TransportHeader::Icmpv6(_)) => {
            (None, None, L4Proto::Icmp)
        }
        None => (None, None, L4Proto::Other),
    }
}

/// The transport payload slice (the bytes after the L4 header), if any.
/// `etherparse`'s [`LaxPayloadSlice`] tags the payload by layer; we return the
/// inner bytes for the transport-carrying variants and an empty slice for
/// L4-less frames (ARP/ICMP-only/etc).
fn transport_payload<'a>(headers: &'a LaxPacketHeaders<'a>) -> &'a [u8] {
    match &headers.payload {
        LaxPayloadSlice::Tcp { payload, .. }
        | LaxPayloadSlice::Udp { payload, .. }
        | LaxPayloadSlice::Icmpv4 { payload, .. }
        | LaxPayloadSlice::Icmpv6 { payload, .. }
        | LaxPayloadSlice::MacsecModified { payload, .. } => payload,
        LaxPayloadSlice::Ether(e) => e.payload,
        LaxPayloadSlice::Ip(ip) => ip.payload,
        LaxPayloadSlice::LinuxSll(sll) => sll.payload,
        LaxPayloadSlice::Empty => &[],
    }
}

/// Parse a TLS record from the payload when the flow looks like TLS. Only TCP
/// flows on/off port 443 (or already-TLS-looking payloads) are probed, keeping
/// the parser off unrelated traffic.
fn tls_payload(
    proto: L4Proto,
    sport: Option<u16>,
    dport: Option<u16>,
    payload: &[u8],
) -> Option<TlsInfo> {
    if proto != L4Proto::Tcp {
        return None;
    }
    let is_tls_port = sport == Some(443) || dport == Some(443);
    let looks_like_tls = matches!(payload.first(), Some(0x14..=0x18));
    if !is_tls_port && !looks_like_tls {
        return None;
    }
    parse_tls(payload)
}

/// Heuristic application-protocol classification (spec R3).
fn classify_app_proto(
    proto: L4Proto,
    sport: Option<u16>,
    dport: Option<u16>,
    payload: &[u8],
    tls: Option<&TlsInfo>,
) -> AppProto {
    let on = |p: u16| sport == Some(p) || dport == Some(p);
    if tls.is_some() {
        return AppProto::Tls;
    }
    match proto {
        L4Proto::Udp if on(53) => AppProto::Dns,
        L4Proto::Tcp if on(53) => AppProto::Dns,
        L4Proto::Udp if on(443) => AppProto::Quic,
        L4Proto::Tcp if on(80) || looks_like_http(payload) => AppProto::Http,
        _ => AppProto::Unknown,
    }
}

/// Cheap HTTP request-line sniff for cleartext HTTP on non-standard ports.
fn looks_like_http(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 6] = [b"GET ", b"POST", b"HEAD", b"PUT ", b"HTTP", b"DELE"];
    METHODS.iter().any(|m| payload.starts_with(m))
}

/// One-line Proxyman-style summary, e.g.
/// `TCP 10.0.0.2:52344 -> 1.1.1.1:443 TLS (example.com)`.
fn build_summary(
    src: &SocketEndpoint,
    dst: &SocketEndpoint,
    proto: L4Proto,
    app: AppProto,
    sni: Option<&str>,
) -> String {
    use std::fmt::Write as _;
    let mut s = format!("{} {src} -> {dst}", proto.label());
    if app != AppProto::Unknown {
        s.push(' ');
        s.push_str(app.label());
    }
    if let Some(host) = sni {
        let _ = write!(s, " ({host})");
    }
    s
}

#[cfg(test)]
#[path = "parse_test.rs"]
mod parse_test;
