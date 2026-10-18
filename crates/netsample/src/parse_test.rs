#![allow(clippy::indexing_slicing, clippy::panic, clippy::unreadable_literal)]

use super::*;

const SAMPLE: &str = "\
time                        bytes_in       bytes_out
20:24:41.086926 apsd.372         34735          142109
20:24:41.085118    tcp4 172.20.10.4:49442<->17.57.146.54:5223    34735    142109
20:24:41.086935 mDNSResponder.488    197670467    51896857
20:24:41.084694    udp4 *:5353<->*:*    79773214    24269337
20:24:41.086938 com.apple.WebKi.67353    75767    46038
20:24:41.696768    tcp6 2a02:aa7:4647:d191:892e:90bb:c538:c36a.56878<->2607:6bc0::10.443    482592    47243486
";

#[test]
fn test_parse_process_line_extracts_pid_and_counters() {
    let procs = parse(SAMPLE);
    let apsd = procs.iter().find(|p| p.pid == 372).expect("apsd present");
    assert_eq!(apsd.name, "apsd");
    assert_eq!(apsd.bytes_in, 34735);
    assert_eq!(apsd.bytes_out, 142_109);
}

#[test]
fn test_parse_attaches_conn_to_preceding_process() {
    let procs = parse(SAMPLE);
    let apsd = procs.iter().find(|p| p.pid == 372).expect("apsd present");
    assert_eq!(apsd.conns.len(), 1);
    let c = &apsd.conns[0];
    assert_eq!(c.remote_ip, "17.57.146.54");
    assert_eq!(c.remote_port, 5223);
    assert_eq!(c.proto, "tcp4");
}

#[test]
fn test_parse_skips_wildcard_connections() {
    let procs = parse(SAMPLE);
    let mdns = procs.iter().find(|p| p.pid == 488).expect("mdns present");
    assert!(mdns.conns.is_empty(), "wildcard listener should be dropped");
}

#[test]
fn test_parse_truncated_name_keeps_trailing_pid() {
    let procs = parse(SAMPLE);
    let webkit = procs
        .iter()
        .find(|p| p.pid == 67353)
        .expect("webkit present");
    assert_eq!(webkit.name, "com.apple.WebKi");
}

#[test]
fn test_parse_ipv6_endpoint() {
    let procs = parse(SAMPLE);
    let webkit = procs
        .iter()
        .find(|p| p.pid == 67353)
        .expect("webkit present");
    assert_eq!(webkit.conns.len(), 1);
    let c = &webkit.conns[0];
    assert_eq!(c.remote_ip, "2607:6bc0::10");
    assert_eq!(c.remote_port, 443);
    assert_eq!(c.proto, "tcp6");
}

#[test]
fn test_parse_ignores_header_and_blank() {
    assert!(parse("").is_empty());
    assert!(parse("time  bytes_in  bytes_out\n").is_empty());
}

#[test]
fn test_parse_process_with_zero_counters() {
    let procs = parse("00:00:00.0 idle.9    0    0\n");
    assert_eq!(procs.len(), 1);
    assert_eq!(procs[0].bytes_in, 0);
    assert_eq!(procs[0].bytes_out, 0);
}
