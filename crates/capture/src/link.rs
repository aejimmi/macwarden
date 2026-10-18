//! Link-layer stripping — turns raw capture bytes into `etherparse` headers.
//!
//! This is a direct port of sniffnet's
//! `networking::parse_packets::get_sniffable_headers` (and its `from_null` /
//! `from_linux_sll` helpers), narrowed to the link types a macOS/Linux capture
//! actually sees. We reuse `etherparse` — the exact parser sniffnet targets —
//! rather than re-implementing L2/L3/L4 decoding.

use crate::error::ParseError;
use etherparse::{EtherType, LaxPacketHeaders};

/// The data-link layer of a captured interface, mirroring libpcap's DLT_* /
/// sniffnet's `MyLinkType`. Determines how many leading bytes precede the IP
/// header and how `etherparse` should enter the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkType {
    /// `DLT_EN10MB` — a 14-byte Ethernet II header.
    Ethernet,
    /// `DLT_RAW` / `DLT_IPV4` / `DLT_IPV6` — the frame starts at the IP header.
    RawIp,
    /// `DLT_NULL` / `DLT_LOOP` — a 4-byte BSD loopback address-family prefix.
    Null,
    /// `DLT_LINUX_SLL` — a 16-byte Linux "cooked" v1 header.
    LinuxSll,
    /// `DLT_LINUX_SLL2` — a 20-byte Linux "cooked" v2 header.
    LinuxSll2,
}

impl LinkType {
    /// Byte offset at which the network (L3) header begins for a well-formed
    /// frame of this link type. For [`LinkType::Null`] the prefix is validated
    /// separately (the address family must be an IP one).
    #[must_use]
    pub const fn l3_offset(self) -> usize {
        match self {
            LinkType::RawIp => 0,
            LinkType::Ethernet => 14,
            LinkType::Null => 4,
            LinkType::LinuxSll => 16,
            LinkType::LinuxSll2 => 20,
        }
    }

    /// Human label for this link type, used in [`ParseError`] and the decode
    /// tree.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            LinkType::Ethernet => "Ethernet",
            LinkType::RawIp => "RawIP",
            LinkType::Null => "Null/Loopback",
            LinkType::LinuxSll => "LinuxSLL",
            LinkType::LinuxSll2 => "LinuxSLL2",
        }
    }
}

/// Strip the link layer and hand the remainder to `etherparse`, producing lax
/// (best-effort, truncation-tolerant) headers. Returns a typed [`ParseError`]
/// instead of panicking on any malformed or too-short input.
pub fn sniffable_headers(
    packet: &[u8],
    link_type: LinkType,
) -> Result<LaxPacketHeaders<'_>, ParseError> {
    match link_type {
        LinkType::Ethernet => {
            LaxPacketHeaders::from_ethernet(packet).map_err(|e| ParseError::Headers(e.to_string()))
        }
        LinkType::RawIp => {
            LaxPacketHeaders::from_ip(packet).map_err(|e| ParseError::Headers(e.to_string()))
        }
        LinkType::Null => from_null(packet),
        LinkType::LinuxSll => from_linux_sll(packet, true),
        LinkType::LinuxSll2 => from_linux_sll(packet, false),
    }
}

/// BSD loopback (`DLT_NULL`/`DLT_LOOP`): a 4-byte host- or network-order
/// address family precedes the IP header. Ported from sniffnet's `from_null`.
fn from_null(packet: &[u8]) -> Result<LaxPacketHeaders<'_>, ParseError> {
    let b: [u8; 4] =
        packet
            .get(..4)
            .and_then(|h| h.try_into().ok())
            .ok_or(ParseError::TruncatedLink {
                layer: "Null/Loopback",
                have: packet.len(),
            })?;
    // https://wiki.wireshark.org/NullLoopback.md — 2 = IPv4, 24/28/30 = IPv6.
    let is_ip_family = |v: u32| matches!(v, 2 | 24 | 28 | 30);
    if !(is_ip_family(u32::from_le_bytes(b)) || is_ip_family(u32::from_be_bytes(b))) {
        return Err(ParseError::NoNetworkLayer);
    }
    let payload = packet.get(4..).unwrap_or(&[]);
    LaxPacketHeaders::from_ip(payload).map_err(|e| ParseError::Headers(e.to_string()))
}

/// Linux "cooked" capture (`DLT_LINUX_SLL`/`SLL2`). Ported from sniffnet's
/// `from_linux_sll`: read the EtherType out of the header and enter the frame
/// at the payload.
fn from_linux_sll(packet: &[u8], is_v1: bool) -> Result<LaxPacketHeaders<'_>, ParseError> {
    let header_len = if is_v1 { 16 } else { 20 };
    let layer = if is_v1 { "LinuxSLL" } else { "LinuxSLL2" };
    let payload = packet.get(header_len..).ok_or(ParseError::TruncatedLink {
        layer,
        have: packet.len(),
    })?;
    // v1 carries the protocol type at offset 14; v2 at offset 0. Both ranges
    // are in-bounds because `payload` above proved `packet.len() >= header_len`.
    let proto_range = if is_v1 { 14..16 } else { 0..2 };
    let proto = packet
        .get(proto_range)
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(u16::from_be_bytes)
        .ok_or(ParseError::TruncatedLink {
            layer,
            have: packet.len(),
        })?;
    Ok(LaxPacketHeaders::from_ether_type(EtherType(proto), payload))
}

#[cfg(test)]
#[path = "link_test.rs"]
mod link_test;
