#![allow(clippy::unwrap_used, clippy::panic)]

use capture::PacketRing;
use ipc::protocol::{WireAppProto, WireDirection, WireL4Proto};

use super::super::packet_source::{DemoSource, PacketSource};
use super::*;

/// Drain the demo source until a record matching `pred` appears.
fn find_record(pred: impl Fn(&PacketRecord) -> bool) -> PacketRecord {
    let mut source = DemoSource::new(&[]);
    for _ in 0..12 {
        for record in source.drain() {
            if pred(&record) {
                return record;
            }
        }
    }
    panic!("no matching demo record found");
}

#[test]
fn test_wire_record_maps_tls_client_hello() {
    let hello = find_record(|r| r.sni.as_deref() == Some("example.com"));
    let wire = wire_record(&hello);

    assert_eq!(wire.seq, hello.seq);
    assert_eq!(wire.proto, WireL4Proto::Tcp);
    assert_eq!(wire.direction, WireDirection::Out);
    assert_eq!(wire.app_proto, WireAppProto::Tls);
    assert_eq!(wire.sni.as_deref(), Some("example.com"));
    assert!(wire.dst.contains(":443"), "dst renders ip:port");
    assert!(!wire.summary.is_empty());
}

#[test]
fn test_wire_bytes_carries_raw_and_decode_tree() {
    let hello = find_record(|r| r.sni.as_deref() == Some("example.com"));
    let bytes = wire_bytes(&hello);

    assert!(bytes.available);
    assert_eq!(bytes.seq, hello.seq);
    assert_eq!(bytes.raw, hello.raw, "raw bytes are the frame bytes");
    let tree = bytes.tree.expect("a decode tree");
    assert_eq!(tree.root.label, "Frame");
    assert!(!tree.root.children.is_empty());
}

#[test]
fn test_unavailable_bytes_is_a_graceful_miss() {
    let miss = unavailable_bytes(4242);
    assert_eq!(miss.seq, 4242);
    assert!(!miss.available);
    assert!(miss.raw.is_empty());
    assert!(miss.tree.is_none());
}

#[test]
fn test_ring_eviction_answers_available_or_unavailable() {
    // The daemon must answer *every* GetPacketBytes: a retained seq with real
    // bytes, an evicted seq with a graceful unavailable — never no reply (the
    // cause of the panel's "Loading packet…" hang).
    let mut source = DemoSource::new(&[]);
    let mut ring = PacketRing::new(2, 1 << 20); // tiny ring: holds 2 packets
    let mut seqs = Vec::new();
    for _ in 0..4 {
        for record in source.drain() {
            seqs.push(record.seq);
            ring.push(record);
        }
    }
    let latest = seqs.last().copied().unwrap();
    let evicted = seqs.first().copied().unwrap();
    // Mirror the daemon's GetPacketBytes mapping.
    let answer = |seq: u64| {
        ring.get(seq)
            .map_or_else(|| unavailable_bytes(seq), wire_bytes)
    };

    let hit = answer(latest);
    assert!(hit.available, "a retained seq answers with available bytes");

    let miss = answer(evicted);
    assert!(
        !miss.available,
        "an evicted seq answers as a graceful unavailable"
    );
    assert_eq!(miss.seq, evicted);
    assert!(miss.raw.is_empty());
}
