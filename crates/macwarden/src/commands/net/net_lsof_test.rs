use super::*;

// ---------------------------------------------------------------------------
// lsof parsing
// ---------------------------------------------------------------------------

const SAMPLE_LSOF: &str = "\
COMMAND     PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari     1234   user    6u  IPv4 0x12345      0t0  TCP 192.168.1.5:54321->93.184.216.34:443 (ESTABLISHED)
Chrome     5678   user    8u  IPv4 0x12346      0t0  TCP 192.168.1.5:55555->142.250.80.14:443 (ESTABLISHED)
mDNSRespo   456   root   12u  IPv4 0x12347      0t0  UDP *:5353
Slack      7890   user   10u  IPv4 0x12348      0t0  TCP 192.168.1.5:60000->34.75.32.100:443 (ESTABLISHED)
Safari     1234   user    7u  IPv4 0x12349      0t0  TCP *:8080 (LISTEN)
";

#[test]
fn test_parse_lsof_output_skips_listen() {
    let conns = parse_lsof_output(SAMPLE_LSOF);
    // LISTEN on *:8080 should be skipped, mDNS *:5353 should be skipped (wildcard)
    assert!(
        conns.iter().all(|c| c.remote_host != "*"),
        "wildcard destinations should be filtered out"
    );
}

#[test]
fn test_parse_lsof_output_extracts_remote() {
    let conns = parse_lsof_output(SAMPLE_LSOF);
    let safari = conns.iter().find(|c| c.process == "Safari");
    assert!(safari.is_some(), "should find Safari connection");
    let s = safari.expect("safari should exist");
    assert_eq!(s.remote_host, "93.184.216.34");
    assert_eq!(s.remote_port, 443);
    assert_eq!(s.protocol, "TCP");
}

#[test]
fn test_parse_lsof_output_deduplicates() {
    let input = "\
COMMAND     PID   USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
proc       100   user    6u  IPv4 0x1     0t0  TCP 10.0.0.1:1->1.2.3.4:443 (ESTABLISHED)
proc       100   user    7u  IPv4 0x2     0t0  TCP 10.0.0.1:2->1.2.3.4:443 (ESTABLISHED)
";
    let conns = parse_lsof_output(input);
    // Same PID, same remote host:port should be deduped.
    assert_eq!(conns.len(), 1, "duplicates should be removed");
}

#[test]
fn test_parse_lsof_output_same_host_different_ports_deduped() {
    // Same process + same host = collapsed, even with different ports.
    // Users care about "which process talks to which host", not port-level detail.
    let input = "\
COMMAND     PID   USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
proc       100   user    6u  IPv4 0x1     0t0  TCP 10.0.0.1:1->1.2.3.4:443 (ESTABLISHED)
proc       100   user    7u  IPv4 0x2     0t0  TCP 10.0.0.1:2->1.2.3.4:80 (ESTABLISHED)
";
    let conns = parse_lsof_output(input);
    assert_eq!(conns.len(), 1, "same process+host should be deduped");
}

#[test]
fn test_parse_lsof_line_returns_none_for_short_line() {
    assert!(parse_lsof_line("too short").is_none());
}

#[test]
fn test_parse_lsof_line_returns_none_for_listen() {
    let line = "Safari     1234   user    7u  IPv4 0x1234   0t0  TCP *:8080 (LISTEN)";
    assert!(parse_lsof_line(line).is_none());
}

// ---------------------------------------------------------------------------
// split_host_port
// ---------------------------------------------------------------------------

#[test]
fn test_split_host_port_ipv4() {
    let (host, port) = split_host_port("1.2.3.4:443").expect("should parse");
    assert_eq!(host, "1.2.3.4");
    assert_eq!(port, 443);
}

#[test]
fn test_split_host_port_ipv6() {
    let (host, port) = split_host_port("[::1]:8080").expect("should parse");
    assert_eq!(host, "::1");
    assert_eq!(port, 8080);
}

#[test]
fn test_split_host_port_no_port() {
    let (host, port) = split_host_port("example.com").expect("should parse");
    assert_eq!(host, "example.com");
    assert_eq!(port, 0);
}

// ---------------------------------------------------------------------------
// parse_remote
// ---------------------------------------------------------------------------

#[test]
fn test_parse_remote_with_arrow() {
    let (host, port) = parse_remote("10.0.0.1:55000->1.2.3.4:443").expect("should parse");
    assert_eq!(host, "1.2.3.4");
    assert_eq!(port, 443);
}

#[test]
fn test_parse_remote_no_arrow() {
    let (host, port) = parse_remote("1.2.3.4:5353").expect("should parse");
    assert_eq!(host, "1.2.3.4");
    assert_eq!(port, 5353);
}

// ---------------------------------------------------------------------------
// detect_protocol
// ---------------------------------------------------------------------------

#[test]
fn test_detect_protocol_tcp() {
    let parts = vec![
        "Safari", "123", "user", "6u", "IPv4", "0x1", "0t0", "TCP", "foo",
    ];
    assert_eq!(detect_protocol(&parts), "TCP");
}

#[test]
fn test_detect_protocol_udp() {
    let parts = vec![
        "mDNS", "456", "root", "12u", "IPv4", "0x1", "0t0", "UDP", "*:5353",
    ];
    assert_eq!(detect_protocol(&parts), "UDP");
}

#[test]
fn test_detect_protocol_fallback() {
    let parts = vec!["foo", "1", "u", "1u", "IPv4", "0x1", "0t0", "RAW", "bar"];
    assert_eq!(detect_protocol(&parts), "TCP");
}
