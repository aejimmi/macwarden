#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::parse::{PacketRecord, parse_frame};
use crate::testkit::{eth_ipv4_tcp_syn, eth_ipv4_tls_client_hello};
use crate::types::{AppProto, Direction, L4Proto, Timestamp};

fn ts() -> Timestamp {
    Timestamp::new(1_700_000_000, 0)
}

/// Depth-first collection of node labels.
fn labels(node: &DecodeNode, out: &mut Vec<String>) {
    out.push(node.label.clone());
    for child in &node.children {
        labels(child, out);
    }
}

#[test]
fn test_decode_tree_tcp_tls_layer_order() {
    let raw = eth_ipv4_tls_client_hello("example.com");
    let rec = parse_frame(&raw, LinkType::Ethernet, 0, ts(), &[]).expect("parse");
    let tree = decode_tree(&rec);
    let mut got = Vec::new();
    labels(&tree.root, &mut got);
    assert_eq!(got, vec!["Frame", "Ethernet", "IPv4", "TCP", "TLS"]);
}

#[test]
fn test_decode_tree_ranges_within_bounds_and_nested() {
    let raw = eth_ipv4_tls_client_hello("example.com");
    let rec = parse_frame(&raw, LinkType::Ethernet, 0, ts(), &[]).expect("parse");
    let tree = decode_tree(&rec);
    let len = raw.len();
    assert_eq!(tree.root.byte_range, 0..len);
    check_ranges(&tree.root, len);
}

fn check_ranges(node: &DecodeNode, len: usize) {
    assert!(node.byte_range.start <= node.byte_range.end);
    assert!(node.byte_range.end <= len);
    for child in &node.children {
        // Child must be contained within its parent's range.
        assert!(child.byte_range.start >= node.byte_range.start);
        assert!(child.byte_range.end <= node.byte_range.end);
        check_ranges(child, len);
    }
}

#[test]
fn test_decode_tree_malformed_frame_yields_frame_only() {
    // A frame that fails header parse still yields a Frame node, no panic.
    let rec_raw = vec![0xaa, 0xbb, 0xcc];
    let rec = PacketRecord {
        seq: 0,
        ts: ts(),
        src: crate::types::SocketEndpoint::new("0.0.0.0".parse().unwrap(), None),
        dst: crate::types::SocketEndpoint::new("0.0.0.0".parse().unwrap(), None),
        proto: L4Proto::Other,
        length: 3,
        direction: Direction::Inbound,
        app_proto: AppProto::Unknown,
        sni: None,
        tls: None,
        summary: String::new(),
        raw: rec_raw,
        link_type: LinkType::Ethernet,
    };
    let tree = decode_tree(&rec);
    assert_eq!(tree.root.label, "Frame");
    assert!(tree.root.children.is_empty());
}

#[test]
fn test_hex_dump_known_bytes_format() {
    let bytes = b"ABCDEFGHIJKLMNOP\x00\x01hi";
    let dump = hex_dump(bytes);
    let lines: Vec<&str> = dump.lines().collect();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("00000000  "));
    assert!(lines[0].contains("41 42 43 44 45 46 47 48"));
    assert!(lines[0].ends_with("|ABCDEFGHIJKLMNOP|"));
    assert!(lines[1].starts_with("00000010  "));
    // Non-printable bytes render as '.', printable ASCII passes through.
    assert!(lines[1].ends_with("|..hi|"));
}

#[test]
fn test_hex_dump_empty_is_empty() {
    assert_eq!(hex_dump(&[]), "");
}

#[test]
fn test_decode_tree_ipv4_fields_present() {
    let raw = eth_ipv4_tcp_syn();
    let rec = parse_frame(&raw, LinkType::Ethernet, 0, ts(), &[]).expect("parse");
    let tree = decode_tree(&rec);
    let ipv4 = tree
        .root
        .children
        .iter()
        .find(|n| n.label == "IPv4")
        .expect("has ipv4 node");
    assert!(
        ipv4.fields
            .iter()
            .any(|(k, v)| k == "Source" && v == "10.0.0.2")
    );
}
