#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::testkit::{
    eth_ipv4_tcp_syn, eth_ipv4_tls_client_hello, eth_ipv4_tls_server_hello, ipv6_udp_dns_query,
};
use std::net::IpAddr;

fn ts() -> Timestamp {
    Timestamp::new(1_700_000_000, 0)
}

#[test]
fn test_parse_frame_eth_ipv4_tcp_fields() {
    let raw = eth_ipv4_tcp_syn();
    let rec = parse_frame(&raw, LinkType::Ethernet, 0, ts(), &[]).expect("parse tcp syn");
    assert_eq!(rec.proto, L4Proto::Tcp);
    assert_eq!(rec.src.ip, "10.0.0.2".parse::<IpAddr>().unwrap());
    assert_eq!(rec.dst.ip, "93.184.216.34".parse::<IpAddr>().unwrap());
    assert_eq!(rec.src.port, Some(52344));
    assert_eq!(rec.dst.port, Some(443));
    assert_eq!(rec.length as usize, raw.len());
}

#[test]
fn test_parse_frame_ipv6_udp_fields() {
    let raw = ipv6_udp_dns_query();
    let rec = parse_frame(&raw, LinkType::RawIp, 7, ts(), &[]).expect("parse ipv6 udp");
    assert_eq!(rec.proto, L4Proto::Udp);
    assert_eq!(rec.dst.port, Some(53));
    assert_eq!(rec.app_proto, AppProto::Dns);
    assert_eq!(rec.seq, 7);
    assert!(matches!(rec.src.ip, IpAddr::V6(_)));
}

#[test]
fn test_parse_frame_direction_outbound_when_source_is_local() {
    let raw = eth_ipv4_tcp_syn();
    let local: Vec<IpAddr> = vec!["10.0.0.2".parse().unwrap()];
    let rec = parse_frame(&raw, LinkType::Ethernet, 0, ts(), &local).expect("parse");
    assert_eq!(rec.direction, Direction::Outbound);
}

#[test]
fn test_parse_frame_direction_inbound_when_source_is_remote() {
    let raw = eth_ipv4_tcp_syn();
    let local: Vec<IpAddr> = vec!["93.184.216.34".parse().unwrap()];
    let rec = parse_frame(&raw, LinkType::Ethernet, 0, ts(), &local).expect("parse");
    assert_eq!(rec.direction, Direction::Inbound);
}

#[test]
fn test_parse_frame_populates_sni_and_summary_for_client_hello() {
    let raw = eth_ipv4_tls_client_hello("example.com");
    let rec = parse_frame(&raw, LinkType::Ethernet, 0, ts(), &[]).expect("parse client hello");
    assert_eq!(rec.app_proto, AppProto::Tls);
    assert_eq!(rec.sni.as_deref(), Some("example.com"));
    assert!(rec.summary.contains("example.com"));
    assert!(rec.summary.contains("TLS"));
}

#[test]
fn test_parse_frame_server_hello_carries_tls_version() {
    let raw = eth_ipv4_tls_server_hello();
    let rec = parse_frame(&raw, LinkType::Ethernet, 0, ts(), &[]).expect("parse server hello");
    assert_eq!(rec.app_proto, AppProto::Tls);
    let tls = rec.tls.expect("has tls info");
    assert_eq!(tls.version.as_deref(), Some("TLS 1.2"));
    assert!(tls.selected_cipher.is_some());
}

#[test]
fn test_parse_frame_truncated_frame_errors_without_panic() {
    let full = eth_ipv4_tcp_syn();
    // Cut the frame off inside the IP header — must be a typed error, not a panic.
    let truncated = &full[..full.len().min(18)];
    let result = parse_frame(truncated, LinkType::Ethernet, 0, ts(), &[]);
    assert!(result.is_err());
}

#[test]
fn test_parse_frame_garbage_bytes_do_not_panic() {
    for len in 0..40usize {
        let garbage: Vec<u8> = (0..len).map(|i| (i * 37 + 13) as u8).collect();
        // Any result is fine; the contract is "no panic / no OOB read".
        let _ = parse_frame(&garbage, LinkType::Ethernet, 0, ts(), &[]);
        let _ = parse_frame(&garbage, LinkType::RawIp, 0, ts(), &[]);
    }
}

#[test]
fn test_parse_frame_retains_raw_bytes_for_hex_view() {
    let raw = eth_ipv4_tcp_syn();
    let rec = parse_frame(&raw, LinkType::Ethernet, 0, ts(), &[]).expect("parse");
    assert_eq!(rec.raw, raw);
    assert_eq!(rec.link_type, LinkType::Ethernet);
}
