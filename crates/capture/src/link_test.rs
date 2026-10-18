#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::testkit::{eth_ipv4_tcp_syn, ipv6_udp_dns_query};

#[test]
fn test_l3_offset_per_link_type() {
    assert_eq!(LinkType::RawIp.l3_offset(), 0);
    assert_eq!(LinkType::Ethernet.l3_offset(), 14);
    assert_eq!(LinkType::Null.l3_offset(), 4);
    assert_eq!(LinkType::LinuxSll.l3_offset(), 16);
    assert_eq!(LinkType::LinuxSll2.l3_offset(), 20);
}

#[test]
fn test_sniffable_headers_ethernet_ok() {
    let raw = eth_ipv4_tcp_syn();
    let headers = sniffable_headers(&raw, LinkType::Ethernet).expect("ethernet parses");
    assert!(headers.net.is_some());
    assert!(headers.transport.is_some());
}

#[test]
fn test_sniffable_headers_rawip_ok() {
    let raw = ipv6_udp_dns_query();
    let headers = sniffable_headers(&raw, LinkType::RawIp).expect("raw ip parses");
    assert!(headers.net.is_some());
}

#[test]
fn test_sniffable_headers_null_bad_family_errors() {
    // 4-byte AF prefix that is not an IP family, followed by junk.
    let raw = vec![0xff, 0xff, 0xff, 0xff, 0x45, 0x00, 0x00, 0x14];
    assert!(sniffable_headers(&raw, LinkType::Null).is_err());
}

#[test]
fn test_sniffable_headers_null_too_short_errors() {
    let raw = vec![0x02, 0x00];
    assert!(matches!(
        sniffable_headers(&raw, LinkType::Null),
        Err(ParseError::TruncatedLink { .. })
    ));
}

#[test]
fn test_sniffable_headers_sll_too_short_errors() {
    let raw = vec![0x00, 0x08];
    assert!(matches!(
        sniffable_headers(&raw, LinkType::LinuxSll),
        Err(ParseError::TruncatedLink { .. })
    ));
}

#[test]
fn test_sniffable_headers_empty_input_does_not_panic() {
    for lt in [
        LinkType::Ethernet,
        LinkType::RawIp,
        LinkType::Null,
        LinkType::LinuxSll,
        LinkType::LinuxSll2,
    ] {
        let _ = sniffable_headers(&[], lt);
    }
}
