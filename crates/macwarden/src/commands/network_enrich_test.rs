#![allow(clippy::indexing_slicing, clippy::ip_constant)]
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;

// ---------------------------------------------------------------------------
// parse_remote
// ---------------------------------------------------------------------------

#[test]
fn test_parse_remote_arrow_ipv4() {
    let conn = "172.20.10.4:49792->160.79.104.10:443";
    let result = parse_remote(conn);
    assert_eq!(
        result,
        Some((IpAddr::V4(Ipv4Addr::new(160, 79, 104, 10)), 443))
    );
}

#[test]
fn test_parse_remote_arrow_ipv6() {
    let conn = "[::1]:49792->[2607:f8b0:4004:800::200e]:443";
    let result = parse_remote(conn);
    let expected_ip: IpAddr = "2607:f8b0:4004:800::200e".parse().expect("valid IPv6");
    assert_eq!(result, Some((expected_ip, 443)));
}

#[test]
fn test_parse_remote_bare_ipv4() {
    let conn = "160.79.104.10:443";
    let result = parse_remote(conn);
    assert_eq!(
        result,
        Some((IpAddr::V4(Ipv4Addr::new(160, 79, 104, 10)), 443))
    );
}

#[test]
fn test_parse_remote_bare_ipv6() {
    let conn = "[2607:f8b0:4004:800::200e]:80";
    let result = parse_remote(conn);
    let expected_ip: IpAddr = "2607:f8b0:4004:800::200e".parse().expect("valid IPv6");
    assert_eq!(result, Some((expected_ip, 80)));
}

#[test]
fn test_parse_remote_wildcard_returns_none() {
    assert_eq!(parse_remote("*:*"), None);
    assert_eq!(parse_remote("*:5353"), None);
    assert_eq!(parse_remote("192.168.1.1:123->*:*"), None);
}

#[test]
fn test_parse_remote_garbage_returns_none() {
    assert_eq!(parse_remote(""), None);
    assert_eq!(parse_remote("not-a-connection"), None);
}

#[test]
fn test_parse_remote_high_port() {
    let conn = "10.0.0.1:12345->93.184.216.34:65535";
    let result = parse_remote(conn);
    assert_eq!(
        result,
        Some((IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 65535))
    );
}

// ---------------------------------------------------------------------------
// is_local_addr
// ---------------------------------------------------------------------------

#[test]
fn test_is_local_addr_loopback_v4() {
    let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    assert!(is_local_addr(&ip));
}

#[test]
fn test_is_local_addr_loopback_v6() {
    let ip = IpAddr::V6(Ipv6Addr::LOCALHOST);
    assert!(is_local_addr(&ip));
}

#[test]
fn test_is_local_addr_link_local_v4() {
    let ip = IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1));
    assert!(is_local_addr(&ip));
}

#[test]
fn test_is_local_addr_link_local_v6() {
    let ip: IpAddr = "fe80::1".parse().expect("valid link-local IPv6");
    assert!(is_local_addr(&ip));
}

#[test]
fn test_is_local_addr_private_10() {
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    assert!(is_local_addr(&ip));
}

#[test]
fn test_is_local_addr_private_172() {
    let ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
    assert!(is_local_addr(&ip));
}

#[test]
fn test_is_local_addr_private_192() {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    assert!(is_local_addr(&ip));
}

#[test]
fn test_is_local_addr_multicast_v4() {
    let ip = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1));
    assert!(is_local_addr(&ip));
}

#[test]
fn test_is_local_addr_unspecified_v4() {
    let ip = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
    assert!(is_local_addr(&ip));
}

#[test]
fn test_is_local_addr_public_v4() {
    let ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
    assert!(!is_local_addr(&ip));
}

#[test]
fn test_is_local_addr_public_v6() {
    let ip: IpAddr = "2607:f8b0:4004:800::200e"
        .parse()
        .expect("valid public IPv6");
    assert!(!is_local_addr(&ip));
}

// ---------------------------------------------------------------------------
// display_process
// ---------------------------------------------------------------------------

#[test]
fn test_display_process_prefers_service_name_over_code_id() {
    // When the service name is readable, prefer it over code_id.
    let entry = NetEntry {
        pid: 1,
        process: "rapportd".to_owned(),
        service: Some("com.apple.rapport".to_owned()),
        group: None,
        connection: "1.2.3.4:443".to_owned(),
        conn_type: "ESTABLISHED".to_owned(),
        remote_ip: None,
        remote_host: None,
        remote_port: None,
        country: None,
        owner: None,
        tracker: None,
        code_id: Some("com.apple.rapport.discovery".to_owned()),
    };
    assert_eq!(display_process(&entry), "com.apple.rapport");
}

#[test]
fn test_display_process_uses_code_id_for_version_name() {
    // When the process name is a version number (garbage), use code_id.
    let entry = NetEntry {
        pid: 1,
        process: "2.1.92".to_owned(),
        service: Some("2.1.92".to_owned()),
        group: None,
        connection: "1.2.3.4:443".to_owned(),
        conn_type: "ESTABLISHED".to_owned(),
        remote_ip: None,
        remote_host: None,
        remote_port: None,
        country: None,
        owner: None,
        tracker: None,
        code_id: Some("com.anthropic.claude-code".to_owned()),
    };
    assert_eq!(display_process(&entry), "claude-code");
}

#[test]
fn test_display_process_fallback_to_service() {
    let entry = NetEntry {
        pid: 1,
        process: "rapportd".to_owned(),
        service: Some("com.apple.rapport".to_owned()),
        group: None,
        connection: "1.2.3.4:443".to_owned(),
        conn_type: "ESTABLISHED".to_owned(),
        remote_ip: None,
        remote_host: None,
        remote_port: None,
        country: None,
        owner: None,
        tracker: None,
        code_id: None,
    };
    assert_eq!(display_process(&entry), "com.apple.rapport");
}

#[test]
fn test_display_process_fallback_to_process_name() {
    let entry = NetEntry {
        pid: 1,
        process: "firefox".to_owned(),
        service: None,
        group: None,
        connection: "1.2.3.4:443".to_owned(),
        conn_type: "ESTABLISHED".to_owned(),
        remote_ip: None,
        remote_host: None,
        remote_port: None,
        country: None,
        owner: None,
        tracker: None,
        code_id: None,
    };
    assert_eq!(display_process(&entry), "firefox");
}

// ---------------------------------------------------------------------------
// display_remote
// ---------------------------------------------------------------------------

#[test]
fn test_display_remote_with_hostname() {
    let entry = NetEntry {
        pid: 1,
        process: "p".to_owned(),
        service: None,
        group: None,
        connection: "10.0.0.1:123->93.184.216.34:443".to_owned(),
        conn_type: "ESTABLISHED".to_owned(),
        remote_ip: Some("93.184.216.34".to_owned()),
        remote_host: Some("example.com".to_owned()),
        remote_port: Some(443),
        country: None,
        owner: None,
        tracker: None,
        code_id: None,
    };
    assert_eq!(display_remote(&entry), "example.com");
}

#[test]
fn test_display_remote_with_ip_only() {
    let entry = NetEntry {
        pid: 1,
        process: "p".to_owned(),
        service: None,
        group: None,
        connection: "10.0.0.1:123->93.184.216.34:443".to_owned(),
        conn_type: "ESTABLISHED".to_owned(),
        remote_ip: Some("93.184.216.34".to_owned()),
        remote_host: None,
        remote_port: Some(443),
        country: None,
        owner: None,
        tracker: None,
        code_id: None,
    };
    assert_eq!(display_remote(&entry), "93.184.216.34:443");
}

#[test]
fn test_display_remote_fallback_to_connection() {
    let entry = NetEntry {
        pid: 1,
        process: "p".to_owned(),
        service: None,
        group: None,
        connection: "*:5353".to_owned(),
        conn_type: "UDP".to_owned(),
        remote_ip: None,
        remote_host: None,
        remote_port: None,
        country: None,
        owner: None,
        tracker: None,
        code_id: None,
    };
    assert_eq!(display_remote(&entry), "*:5353");
}
