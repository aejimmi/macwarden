//! Decode tree + hex dump for the packet inspector (spec R5).
//!
//! Pure data structures — the UI renders them later. [`decode_tree`] mirrors
//! Frame → Ethernet → IP(v4/v6) → TCP/UDP → TLS, each node tagging the byte
//! range it occupies in the raw frame so the UI can cross-highlight the hex
//! dump. Child ranges are contained within their parent's range and are
//! computed from the parsed header lengths, so they stay in-bounds even for a
//! truncated capture.

use crate::link::{LinkType, sniffable_headers};
use crate::parse::PacketRecord;
use etherparse::{LaxPacketHeaders, NetHeaders, TransportHeader};
use std::fmt::Write as _;
use std::ops::Range;

/// One node in the packet decode tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeNode {
    /// Layer label, e.g. `"Ethernet"`, `"IPv4"`, `"TCP"`, `"TLS"`.
    pub label: String,
    /// One-line summary of the layer's salient fields.
    pub summary: String,
    /// The byte range this layer occupies within the raw frame.
    pub byte_range: Range<usize>,
    /// Field name/value pairs for the inspector detail rows.
    pub fields: Vec<(String, String)>,
    /// Nested layers contained within this one.
    pub children: Vec<DecodeNode>,
}

impl DecodeNode {
    fn new(label: &str, summary: String, byte_range: Range<usize>) -> Self {
        Self {
            label: label.to_string(),
            summary,
            byte_range,
            fields: Vec::new(),
            children: Vec::new(),
        }
    }

    fn field(mut self, name: &str, value: String) -> Self {
        self.fields.push((name.to_string(), value));
        self
    }
}

/// The full decode tree for a packet: a single `Frame` root spanning the whole
/// capture, with layer children beneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeTree {
    /// The root `Frame` node.
    pub root: DecodeNode,
}

/// Build the decode tree for a parsed record from its retained raw bytes.
#[must_use]
pub fn decode_tree(record: &PacketRecord) -> DecodeTree {
    let raw = &record.raw;
    let mut frame = DecodeNode::new(
        "Frame",
        format!("{} bytes on wire, {}", raw.len(), record.link_type.label()),
        0..raw.len(),
    );

    let Ok(headers) = sniffable_headers(raw, record.link_type) else {
        return DecodeTree { root: frame };
    };

    // Layers are Wireshark-style siblings under `Frame`: each holds only its
    // own header bytes, so their ranges are non-overlapping, collectively cover
    // the parsed prefix, and are each contained within the frame (spec R5).
    let mut offset = 0usize;
    if let Some(node) = link_node(record.link_type, raw.len()) {
        offset = node.byte_range.end;
        frame.children.push(node);
    }
    let Some((net, net_end)) = net_node(&headers, offset, raw.len()) else {
        return DecodeTree { root: frame };
    };
    frame.children.push(net);
    offset = net_end;

    if let Some((transport, payload_start)) = transport_node(&headers, offset, raw.len()) {
        frame.children.push(transport);
        offset = payload_start;
    }
    if let Some(tls) = &record.tls {
        frame.children.push(tls_node(tls, offset, raw.len()));
    }
    DecodeTree { root: frame }
}

/// A TLS decode node spanning the transport payload region.
fn tls_node(tls: &crate::tls::TlsInfo, start: usize, total: usize) -> DecodeNode {
    DecodeNode::new("TLS", tls_summary(tls), start..total)
        .field("Record", format!("{:?}", tls.record_kind))
        .field("SNI", tls.sni.clone().unwrap_or_else(|| "-".to_string()))
}

/// The link-layer node, sized by the link type's fixed header length. `RawIp`
/// has no link header, so returns `None`.
fn link_node(link_type: LinkType, total: usize) -> Option<DecodeNode> {
    let end = link_type.l3_offset().min(total);
    if end == 0 {
        return None;
    }
    Some(DecodeNode::new(
        link_type.label(),
        format!("{end}-byte link header"),
        0..end,
    ))
}

/// The network-layer node and the offset at which the transport header starts.
fn net_node(headers: &LaxPacketHeaders, start: usize, total: usize) -> Option<(DecodeNode, usize)> {
    match &headers.net {
        Some(NetHeaders::Ipv4(h, _)) => {
            let end = (start + h.header_len()).min(total);
            let node = DecodeNode::new(
                "IPv4",
                format!("{} → {}", fmt_v4(h.source), fmt_v4(h.destination)),
                start..end,
            )
            .field("Source", fmt_v4(h.source))
            .field("Destination", fmt_v4(h.destination))
            .field("Protocol", format!("{}", h.protocol.0))
            .field("Total Length", format!("{}", h.total_len));
            Some((node, end))
        }
        Some(NetHeaders::Ipv6(h, _)) => {
            let end = (start + h.header_len()).min(total);
            let src = std::net::Ipv6Addr::from(h.source);
            let dst = std::net::Ipv6Addr::from(h.destination);
            let node = DecodeNode::new("IPv6", format!("{src} → {dst}"), start..end)
                .field("Source", src.to_string())
                .field("Destination", dst.to_string())
                .field("Next Header", format!("{}", h.next_header.0))
                .field("Payload Length", format!("{}", h.payload_length));
            Some((node, end))
        }
        Some(NetHeaders::Arp(_)) => {
            let node = DecodeNode::new(
                "ARP",
                "Address Resolution Protocol".to_string(),
                start..total,
            );
            Some((node, total))
        }
        None => None,
    }
}

/// The transport-layer node and the offset at which its payload starts.
fn transport_node(
    headers: &LaxPacketHeaders,
    start: usize,
    total: usize,
) -> Option<(DecodeNode, usize)> {
    match &headers.transport {
        Some(TransportHeader::Tcp(t)) => {
            let end = (start + t.header_len()).min(total);
            let node = DecodeNode::new(
                "TCP",
                format!("{} → {}", t.source_port, t.destination_port),
                start..end,
            )
            .field("Source Port", t.source_port.to_string())
            .field("Destination Port", t.destination_port.to_string())
            .field("Seq", t.sequence_number.to_string());
            Some((node, end))
        }
        Some(TransportHeader::Udp(u)) => {
            let end = (start + etherparse::UdpHeader::LEN).min(total);
            let node = DecodeNode::new(
                "UDP",
                format!("{} → {}", u.source_port, u.destination_port),
                start..end,
            )
            .field("Source Port", u.source_port.to_string())
            .field("Destination Port", u.destination_port.to_string())
            .field("Length", u.length.to_string());
            Some((node, end))
        }
        Some(TransportHeader::Icmpv4(_)) => Some((
            DecodeNode::new("ICMPv4", "ICMP".to_string(), start..total),
            total,
        )),
        Some(TransportHeader::Icmpv6(_)) => Some((
            DecodeNode::new("ICMPv6", "ICMPv6".to_string(), start..total),
            total,
        )),
        None => None,
    }
}

/// One-line TLS summary for a decode node.
fn tls_summary(tls: &crate::tls::TlsInfo) -> String {
    match (&tls.handshake_kind, &tls.sni) {
        (Some(kind), Some(sni)) => format!("{kind:?} ({sni})"),
        (Some(kind), None) => format!("{kind:?}"),
        (None, _) => format!("{:?}", tls.record_kind),
    }
}

fn fmt_v4(octets: [u8; 4]) -> String {
    std::net::Ipv4Addr::from(octets).to_string()
}

/// Render bytes as an offset/hex/ASCII hex dump (16 bytes per row). Each row is
/// `OFFSET  HH HH .. HH  |ascii|`, with non-printable bytes shown as `.`.
#[must_use]
pub fn hex_dump(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 4);
    for (row, chunk) in bytes.chunks(16).enumerate() {
        let mut hex = String::with_capacity(48);
        let mut ascii = String::with_capacity(16);
        for (i, b) in chunk.iter().enumerate() {
            let _ = write!(hex, "{b:02x} ");
            if i == 7 {
                hex.push(' ');
            }
            ascii.push(if b.is_ascii_graphic() || *b == b' ' {
                *b as char
            } else {
                '.'
            });
        }
        let _ = writeln!(out, "{:08x}  {hex:<49}|{ascii}|", row * 16);
    }
    out
}

#[cfg(test)]
#[path = "decode_test.rs"]
mod decode_test;
