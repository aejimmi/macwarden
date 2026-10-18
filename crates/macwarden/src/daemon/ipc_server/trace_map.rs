//! Map `capture` parse types → `ipc` wire DTOs for the trace stream (spec R8).
//!
//! The live [`ipc::protocol::Event::Packet`] push carries only the **light**
//! [`WirePacketRecord`] (summary + headers + SNI, no raw bytes); the **heavy**
//! [`WirePacketBytes`] (raw frame + decode tree) is built on demand for a
//! selected packet by [`super::trace_session::TraceSession::packet_bytes`]. The
//! Tier-1 boundary is preserved: nothing here can carry a decrypted body.

use capture::{AppProto, DecodeNode, DecodeTree, Direction, L4Proto, PacketRecord, decode_tree};
use ipc::protocol::{
    WireAppProto, WireDecodeNode, WireDecodeTree, WireDirection, WireL4Proto, WirePacketBytes,
    WirePacketRecord,
};

/// Map a parsed [`PacketRecord`] to the light wire summary streamed live (R8).
#[must_use]
pub fn wire_record(record: &PacketRecord) -> WirePacketRecord {
    WirePacketRecord {
        seq: record.seq,
        timestamp_ms: timestamp_ms(record),
        src: record.src.to_string(),
        dst: record.dst.to_string(),
        proto: wire_proto(record.proto),
        length: record.length,
        direction: wire_direction(record.direction),
        app_proto: wire_app_proto(record.app_proto),
        sni: record.sni.clone(),
        tls_version: record.tls.as_ref().and_then(|t| t.version.clone()),
        summary: record.summary.clone(),
    }
}

/// Build the heavy on-demand payload for a selected, still-retained packet (R8).
/// The `hex` dump the panel renders is formatted from `raw`, so the caller keeps
/// only the raw bytes on the wire; we expose [`hex_dump`] here for daemon-side
/// logging/tests without re-implementing it.
#[must_use]
pub fn wire_bytes(record: &PacketRecord) -> WirePacketBytes {
    WirePacketBytes {
        seq: record.seq,
        available: true,
        raw: record.raw.clone(),
        tree: Some(wire_tree(&decode_tree(record))),
    }
}

/// The "aged out of the ring" reply for a `seq` that is no longer retained (R6).
#[must_use]
pub fn unavailable_bytes(seq: u64) -> WirePacketBytes {
    WirePacketBytes {
        seq,
        available: false,
        raw: Vec::new(),
        tree: None,
    }
}

fn timestamp_ms(record: &PacketRecord) -> u64 {
    let ms = record.ts.secs.saturating_mul(1000) + record.ts.usecs / 1000;
    ms.max(0) as u64
}

fn wire_proto(proto: L4Proto) -> WireL4Proto {
    match proto {
        L4Proto::Tcp => WireL4Proto::Tcp,
        L4Proto::Udp => WireL4Proto::Udp,
        L4Proto::Icmp => WireL4Proto::Icmp,
        L4Proto::Arp => WireL4Proto::Arp,
        L4Proto::Other => WireL4Proto::Other,
    }
}

fn wire_direction(direction: Direction) -> WireDirection {
    match direction {
        Direction::Outbound => WireDirection::Out,
        Direction::Inbound => WireDirection::In,
    }
}

fn wire_app_proto(app: AppProto) -> WireAppProto {
    match app {
        AppProto::Tls => WireAppProto::Tls,
        AppProto::Dns => WireAppProto::Dns,
        AppProto::Http => WireAppProto::Http,
        AppProto::Quic => WireAppProto::Quic,
        AppProto::Unknown => WireAppProto::Unknown,
    }
}

fn wire_tree(tree: &DecodeTree) -> WireDecodeTree {
    WireDecodeTree {
        root: wire_node(&tree.root),
    }
}

fn wire_node(node: &DecodeNode) -> WireDecodeNode {
    WireDecodeNode {
        label: node.label.clone(),
        summary: node.summary.clone(),
        byte_range: node.byte_range.clone(),
        fields: node.fields.clone(),
        children: node.children.iter().map(wire_node).collect(),
    }
}

#[cfg(test)]
#[path = "trace_map_test.rs"]
mod trace_map_test;
