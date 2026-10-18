//! Pure unit tests for the BPF filter builder (spec R2 acceptance).

use super::*;
use crate::types::L4Proto;
use std::net::IpAddr;

fn ip(s: &str) -> IpAddr {
    s.parse().expect("valid ip literal")
}

#[test]
fn test_build_bpf_filter_single_ipv4_tcp() {
    let t = FlowTuple::new(ip("1.2.3.4"), 443, L4Proto::Tcp);
    assert_eq!(
        build_bpf_filter(&[t]),
        "(host 1.2.3.4 and port 443 and tcp)"
    );
}

#[test]
fn test_build_bpf_filter_single_udp_port() {
    let t = FlowTuple::new(ip("5.6.7.8"), 53, L4Proto::Udp);
    assert_eq!(build_bpf_filter(&[t]), "(host 5.6.7.8 and port 53 and udp)");
}

#[test]
fn test_build_bpf_filter_multi_tuple_joined_with_or() {
    let tuples = [
        FlowTuple::new(ip("1.2.3.4"), 443, L4Proto::Tcp),
        FlowTuple::new(ip("5.6.7.8"), 53, L4Proto::Udp),
    ];
    assert_eq!(
        build_bpf_filter(&tuples),
        "(host 1.2.3.4 and port 443 and tcp) or (host 5.6.7.8 and port 53 and udp)"
    );
}

#[test]
fn test_build_bpf_filter_ipv6_host() {
    let t = FlowTuple::new(ip("2001:db8::1"), 443, L4Proto::Tcp);
    assert_eq!(
        build_bpf_filter(&[t]),
        "(host 2001:db8::1 and port 443 and tcp)"
    );
}

#[test]
fn test_build_bpf_filter_empty_matches_nothing_not_everything() {
    let filter = build_bpf_filter(&[]);
    assert_eq!(filter, MATCH_NOTHING_FILTER);
    // The dangerous failure mode is an empty string (match-all); guard it.
    assert!(!filter.is_empty());
    assert_eq!(filter, "less 0");
}

#[test]
fn test_build_bpf_filter_superset_is_monotonic() {
    let base = [FlowTuple::new(ip("1.2.3.4"), 443, L4Proto::Tcp)];
    let grown = [
        FlowTuple::new(ip("1.2.3.4"), 443, L4Proto::Tcp),
        FlowTuple::new(ip("9.9.9.9"), 853, L4Proto::Tcp),
    ];
    let base_filter = build_bpf_filter(&base);
    let grown_filter = build_bpf_filter(&grown);
    // The prior clause is retained and the new flow is added.
    assert!(grown_filter.starts_with(&base_filter));
    assert!(grown_filter.contains("host 9.9.9.9 and port 853 and tcp"));
}

#[test]
fn test_build_bpf_filter_non_transport_proto_omits_qualifier() {
    let t = FlowTuple::new(ip("1.2.3.4"), 0, L4Proto::Icmp);
    assert_eq!(build_bpf_filter(&[t]), "(host 1.2.3.4 and port 0)");
}
