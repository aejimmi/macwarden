#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal valid RESERVED_5 event buffer with the given fields.
fn build_event_buf(af: u32, ip: [u8; 4], hostname: Option<&str>) -> Vec<u8> {
    let mut buf = vec![0u8; MIN_EVENT_SIZE];

    // address_family at 0x00
    buf[OFF_AF..OFF_AF + 4].copy_from_slice(&af.to_le_bytes());

    // address_family2 at 0x18 (must match)
    buf[OFF_AF2..OFF_AF2 + 4].copy_from_slice(&af.to_le_bytes());

    // resolved_ip at 0x1c
    buf[OFF_IP..OFF_IP + 4].copy_from_slice(&ip);

    // hostname_len and hostname
    if let Some(host) = hostname {
        let host_bytes = host.as_bytes();
        let len = host_bytes.len() as u32;
        buf[OFF_HOSTNAME_LEN..OFF_HOSTNAME_LEN + 4].copy_from_slice(&len.to_le_bytes());
        buf[OFF_HOSTNAME..OFF_HOSTNAME + host_bytes.len()].copy_from_slice(host_bytes);
    }
    // else: hostname_len stays 0

    buf
}

// ---------------------------------------------------------------------------
// Success cases
// ---------------------------------------------------------------------------

#[test]
fn test_parse_valid_ipv4_with_hostname() {
    let buf = build_event_buf(AF_INET, [17, 253, 144, 10], Some("apple.com"));
    let event = parse_reserved5_event(&buf).expect("should parse");

    assert_eq!(event.address_family, AddressFamily::Inet);
    assert_eq!(event.resolved_ip, Ipv4Addr::new(17, 253, 144, 10));
    assert_eq!(event.hostname.as_deref(), Some("apple.com"));
}

#[test]
fn test_parse_valid_ipv6_af_with_hostname() {
    let buf = build_event_buf(AF_INET6, [8, 8, 8, 8], Some("dns.google"));
    let event = parse_reserved5_event(&buf).expect("should parse");

    assert_eq!(event.address_family, AddressFamily::Inet6);
    assert_eq!(event.resolved_ip, Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(event.hostname.as_deref(), Some("dns.google"));
}

#[test]
fn test_parse_valid_no_hostname_with_ip() {
    // No hostname but valid IP -- should succeed.
    let buf = build_event_buf(AF_INET, [192, 168, 1, 1], None);
    let event = parse_reserved5_event(&buf).expect("should parse");

    assert_eq!(event.hostname, None);
    assert_eq!(event.resolved_ip, Ipv4Addr::new(192, 168, 1, 1));
}

#[test]
fn test_parse_hostname_with_null_terminator() {
    // Hostname with trailing null bytes (as it would appear in the raw event).
    let mut buf = build_event_buf(AF_INET, [1, 2, 3, 4], None);
    let host = b"example.com\0\0\0";
    let len = host.len() as u32;
    buf[OFF_HOSTNAME_LEN..OFF_HOSTNAME_LEN + 4].copy_from_slice(&len.to_le_bytes());
    buf[OFF_HOSTNAME..OFF_HOSTNAME + host.len()].copy_from_slice(host);

    let event = parse_reserved5_event(&buf).expect("should parse");
    assert_eq!(event.hostname.as_deref(), Some("example.com"));
}

#[test]
fn test_parse_to_destination_with_hostname() {
    let buf = build_event_buf(AF_INET, [10, 0, 0, 1], Some("tracker.example.com"));
    let event = parse_reserved5_event(&buf).expect("should parse");
    let dest = event.to_destination();

    assert_eq!(dest.host.as_deref(), Some("tracker.example.com"));
    assert_eq!(dest.ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert!(dest.port.is_none(), "ES events have no port");
    assert!(dest.protocol.is_none(), "ES events have no protocol");
    assert_eq!(dest.address_family, AddressFamily::Inet);
}

#[test]
fn test_parse_to_destination_without_hostname() {
    let buf = build_event_buf(AF_INET, [172, 16, 0, 1], None);
    let event = parse_reserved5_event(&buf).expect("should parse");
    let dest = event.to_destination();

    assert!(dest.host.is_none());
    assert_eq!(dest.ip, IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)));
}

// ---------------------------------------------------------------------------
// Validation failures
// ---------------------------------------------------------------------------

#[test]
fn test_parse_buffer_too_small() {
    let buf = vec![0u8; 100]; // way too small
    let err = parse_reserved5_event(&buf).expect_err("should fail");
    let msg = err.to_string();
    assert!(msg.contains("too small"), "error: {msg}");
}

#[test]
fn test_parse_unknown_address_family() {
    let buf = build_event_buf(99, [1, 2, 3, 4], Some("test.com"));
    let err = parse_reserved5_event(&buf).expect_err("should fail");
    let msg = err.to_string();
    assert!(msg.contains("unknown address family"), "error: {msg}");
}

#[test]
fn test_parse_address_family_mismatch() {
    let mut buf = build_event_buf(AF_INET, [1, 2, 3, 4], Some("test.com"));
    // Corrupt address_family2 to a different value.
    buf[OFF_AF2..OFF_AF2 + 4].copy_from_slice(&AF_INET6.to_le_bytes());

    let err = parse_reserved5_event(&buf).expect_err("should fail");
    let msg = err.to_string();
    assert!(msg.contains("mismatch"), "error: {msg}");
}

#[test]
fn test_parse_hostname_len_too_large() {
    let mut buf = build_event_buf(AF_INET, [1, 2, 3, 4], None);
    // Set hostname_len to something absurdly large.
    let bad_len: u32 = 999;
    buf[OFF_HOSTNAME_LEN..OFF_HOSTNAME_LEN + 4].copy_from_slice(&bad_len.to_le_bytes());

    let err = parse_reserved5_event(&buf).expect_err("should fail");
    let msg = err.to_string();
    assert!(msg.contains("too large"), "error: {msg}");
}

#[test]
fn test_parse_no_hostname_and_zero_ip() {
    let buf = build_event_buf(AF_INET, [0, 0, 0, 0], None);
    let err = parse_reserved5_event(&buf).expect_err("should fail");
    let msg = err.to_string();
    assert!(msg.contains("unusable"), "error: {msg}");
}

#[test]
fn test_parse_hostname_invalid_utf8() {
    let mut buf = build_event_buf(AF_INET, [1, 2, 3, 4], None);
    // Write invalid UTF-8 as hostname.
    let bad_bytes: &[u8] = &[0xFF, 0xFE, 0x80, 0x81];
    let len = bad_bytes.len() as u32;
    buf[OFF_HOSTNAME_LEN..OFF_HOSTNAME_LEN + 4].copy_from_slice(&len.to_le_bytes());
    buf[OFF_HOSTNAME..OFF_HOSTNAME + bad_bytes.len()].copy_from_slice(bad_bytes);

    let err = parse_reserved5_event(&buf).expect_err("should fail");
    let msg = err.to_string();
    assert!(msg.contains("UTF-8"), "error: {msg}");
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_parse_exactly_min_size_buffer() {
    // Buffer is exactly MIN_EVENT_SIZE -- should work.
    let buf = build_event_buf(AF_INET, [8, 8, 4, 4], Some("dns.example.com"));
    assert_eq!(buf.len(), MIN_EVENT_SIZE);
    let event = parse_reserved5_event(&buf).expect("should parse");
    assert_eq!(event.hostname.as_deref(), Some("dns.example.com"));
}

#[test]
fn test_parse_larger_buffer_succeeds() {
    // Buffer larger than MIN_EVENT_SIZE (e.g. NOTIFY event with resolver_path).
    let mut buf = build_event_buf(AF_INET, [1, 1, 1, 1], Some("one.one.one.one"));
    buf.extend_from_slice(&[0u8; 512]); // extra data after hostname
    let event = parse_reserved5_event(&buf).expect("should parse");
    assert_eq!(event.hostname.as_deref(), Some("one.one.one.one"));
}

#[test]
fn test_parse_max_length_hostname() {
    // Hostname at exactly MAX_HOSTNAME_LEN (255) chars.
    let hostname = "a".repeat(MAX_HOSTNAME_LEN as usize);
    let mut buf = vec![0u8; OFF_HOSTNAME + MAX_HOSTNAME_LEN as usize + 1];
    buf[OFF_AF..OFF_AF + 4].copy_from_slice(&AF_INET.to_le_bytes());
    buf[OFF_AF2..OFF_AF2 + 4].copy_from_slice(&AF_INET.to_le_bytes());
    buf[OFF_IP..OFF_IP + 4].copy_from_slice(&[10, 0, 0, 1]);
    buf[OFF_HOSTNAME_LEN..OFF_HOSTNAME_LEN + 4].copy_from_slice(&MAX_HOSTNAME_LEN.to_le_bytes());
    buf[OFF_HOSTNAME..OFF_HOSTNAME + hostname.len()].copy_from_slice(hostname.as_bytes());

    let event = parse_reserved5_event(&buf).expect("should parse");
    assert_eq!(event.hostname.as_deref(), Some(hostname.as_str()));
}

#[test]
fn test_parse_hostname_all_nulls_becomes_none() {
    // hostname_len > 0 but all bytes are null -- should return None.
    let mut buf = build_event_buf(AF_INET, [10, 0, 0, 1], None);
    let len: u32 = 10;
    buf[OFF_HOSTNAME_LEN..OFF_HOSTNAME_LEN + 4].copy_from_slice(&len.to_le_bytes());
    // hostname bytes are already all zeros from build_event_buf

    let event = parse_reserved5_event(&buf).expect("should parse");
    assert!(event.hostname.is_none(), "all-null hostname should be None");
}

// ---------------------------------------------------------------------------
// Helpers (unit tests)
// ---------------------------------------------------------------------------

#[test]
fn test_trim_nulls_no_nulls() {
    assert_eq!(trim_nulls(b"hello"), b"hello");
}

#[test]
fn test_trim_nulls_trailing() {
    assert_eq!(trim_nulls(b"hello\0\0\0"), b"hello");
}

#[test]
fn test_trim_nulls_empty() {
    assert_eq!(trim_nulls(b""), b"");
}

#[test]
fn test_trim_nulls_all_null() {
    assert_eq!(trim_nulls(b"\0\0\0"), b"");
}
