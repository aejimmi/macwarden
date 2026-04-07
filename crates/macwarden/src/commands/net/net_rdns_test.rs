#![allow(clippy::indexing_slicing)]
use super::*;

// ---------------------------------------------------------------------------
// is_garbage_rdns
// ---------------------------------------------------------------------------

#[test]
fn test_garbage_rdns_ec2_style() {
    let ip: IpAddr = "52.6.143.21".parse().expect("valid IP");
    assert!(
        is_garbage_rdns("ec2-52-6-143-21.compute-1.amazonaws.com", ip),
        "EC2-style rDNS should be detected as garbage"
    );
}

#[test]
fn test_garbage_rdns_in_addr_arpa() {
    let ip: IpAddr = "21.143.6.52".parse().expect("valid IP");
    assert!(
        is_garbage_rdns("52.6.143.21.in-addr.arpa", ip),
        "in-addr.arpa rDNS should be detected as garbage"
    );
}

#[test]
fn test_garbage_rdns_real_hostname_not_garbage() {
    let ip: IpAddr = "17.253.144.10".parse().expect("valid IP");
    assert!(
        !is_garbage_rdns("apple.com", ip),
        "legitimate hostname should not be garbage"
    );
}

#[test]
fn test_garbage_rdns_partial_match_not_garbage() {
    // Only 2 of 4 octets appear — should not be flagged.
    let ip: IpAddr = "192.168.1.100".parse().expect("valid IP");
    assert!(
        !is_garbage_rdns("host-192-168.example.com", ip),
        "partial octet match should not be garbage"
    );
}

#[test]
fn test_garbage_rdns_ipv6_not_flagged() {
    let ip: IpAddr = "2001:db8::1".parse().expect("valid IPv6");
    assert!(
        !is_garbage_rdns("some-ipv6-host.example.com", ip),
        "IPv6 addresses should not be flagged as garbage"
    );
}

// ---------------------------------------------------------------------------
// resolve_bare_ips — unit-testable parts
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_bare_ips_skips_hostnames() {
    let tracker_db = net::TrackerDatabase::load_builtin().expect("load tracker db");
    let mut entries = vec![ScanEntry {
        process: "Safari".to_owned(),
        pid: 1,
        code_id: None,
        destination: "apple.com".to_owned(),
        port: 443,
        protocol: "TCP".to_owned(),
        action: "ALLOW".to_owned(),
        tracker: None,
        country: None,
        asn_name: None,
        bytes_in: None,
        bytes_out: None,
        service: None,
    }];
    // Should not modify entries that already have hostnames.
    resolve_bare_ips(&mut entries, &tracker_db);
    assert_eq!(entries[0].destination, "apple.com");
}
