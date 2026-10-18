//! Value types carried by a [`crate::parse::PacketRecord`].
//!
//! These are deliberately small, `Copy`-where-cheap, and hold **no decrypted
//! application data** — the Tier-1 boundary (spec R1) is structural: there is
//! nowhere here for an HTTPS body to live.

use std::net::IpAddr;

/// A monotonic per-trace sequence number and a capture timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    /// Whole seconds since the Unix epoch (from the capture header).
    pub secs: i64,
    /// Microseconds within the second.
    pub usecs: i64,
}

impl Timestamp {
    /// Construct a timestamp from a `(secs, usecs)` capture header pair.
    #[must_use]
    pub const fn new(secs: i64, usecs: i64) -> Self {
        Self { secs, usecs }
    }
}

/// One endpoint of a flow: an IP address and, for TCP/UDP, a port.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketEndpoint {
    /// The network-layer address.
    pub ip: IpAddr,
    /// The transport port, absent for ICMP/ARP/other L4-less frames.
    pub port: Option<u16>,
}

impl SocketEndpoint {
    /// Build an endpoint from an address and optional port.
    #[must_use]
    pub const fn new(ip: IpAddr, port: Option<u16>) -> Self {
        Self { ip, port }
    }
}

impl std::fmt::Display for SocketEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.ip, self.port) {
            (IpAddr::V6(v6), Some(p)) => write!(f, "[{v6}]:{p}"),
            (ip, Some(p)) => write!(f, "{ip}:{p}"),
            (ip, None) => write!(f, "{ip}"),
        }
    }
}

/// Transport-layer protocol, mirroring the L4 headers `etherparse` recognises.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum L4Proto {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// ICMP (v4 or v6).
    Icmp,
    /// Address Resolution Protocol (no L4).
    Arp,
    /// A recognised network layer with no handled transport.
    Other,
}

impl L4Proto {
    /// Short uppercase label, e.g. `"TCP"`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            L4Proto::Tcp => "TCP",
            L4Proto::Udp => "UDP",
            L4Proto::Icmp => "ICMP",
            L4Proto::Arp => "ARP",
            L4Proto::Other => "OTHER",
        }
    }
}

/// Traffic direction relative to the local host, derived by comparing the
/// source address against the interface's own addresses (spec R3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Source is a local interface address — traffic leaving this host.
    Outbound,
    /// Source is remote — traffic arriving at this host.
    Inbound,
}

/// Best-effort application protocol, guessed from ports plus a payload sniff.
/// A guess only — never authoritative, and never implies decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppProto {
    /// TLS (handshake visible in cleartext; application data is opaque).
    Tls,
    /// DNS over UDP/TCP.
    Dns,
    /// Cleartext HTTP.
    Http,
    /// QUIC (UDP/443) — treated opaquely at Tier 1.
    Quic,
    /// Not identified.
    Unknown,
}

impl AppProto {
    /// Short uppercase label, e.g. `"TLS"`.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            AppProto::Tls => "TLS",
            AppProto::Dns => "DNS",
            AppProto::Http => "HTTP",
            AppProto::Quic => "QUIC",
            AppProto::Unknown => "UNKNOWN",
        }
    }
}
