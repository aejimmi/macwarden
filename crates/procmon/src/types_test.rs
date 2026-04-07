#![allow(clippy::ip_constant)]

use super::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// ProcessInfo Display
// ---------------------------------------------------------------------------

#[test]
fn test_process_info_display_with_code_id() {
    let info = ProcessInfo {
        pid: 123,
        path: PathBuf::from("/usr/bin/curl"),
        code_id: Some("com.apple.curl".to_string()),
        team_id: None,
        is_apple_signed: true,
        is_valid_signature: true,
    };
    assert_eq!(info.to_string(), "com.apple.curl (pid 123) [Apple]");
}

#[test]
fn test_process_info_display_without_code_id() {
    let info = ProcessInfo {
        pid: 456,
        path: PathBuf::from("/opt/local/bin/foo"),
        code_id: None,
        team_id: Some("TEAM123".to_string()),
        is_apple_signed: false,
        is_valid_signature: true,
    };
    assert_eq!(
        info.to_string(),
        "/opt/local/bin/foo (pid 456) [team TEAM123]"
    );
}

#[test]
fn test_process_info_display_apple_with_team() {
    let info = ProcessInfo {
        pid: 1,
        path: PathBuf::from("/sbin/launchd"),
        code_id: Some("com.apple.xpc.launchd".to_string()),
        team_id: Some("APPLE".to_string()),
        is_apple_signed: true,
        is_valid_signature: true,
    };
    assert_eq!(
        info.to_string(),
        "com.apple.xpc.launchd (pid 1) [Apple] [team APPLE]"
    );
}

// ---------------------------------------------------------------------------
// ResponsibleProcess Display
// ---------------------------------------------------------------------------

#[test]
fn test_responsible_process_display_with_code_id() {
    let rp = ResponsibleProcess {
        pid: 789,
        path: PathBuf::from("/Applications/Safari.app/Contents/MacOS/Safari"),
        code_id: Some("com.apple.Safari".to_string()),
    };
    assert_eq!(rp.to_string(), "com.apple.Safari (pid 789)");
}

#[test]
fn test_responsible_process_display_without_code_id() {
    let rp = ResponsibleProcess {
        pid: 101,
        path: PathBuf::from("/usr/sbin/httpd"),
        code_id: None,
    };
    assert_eq!(rp.to_string(), "/usr/sbin/httpd (pid 101)");
}

// ---------------------------------------------------------------------------
// SocketInfo Display
// ---------------------------------------------------------------------------

#[test]
fn test_socket_info_display_tcp() {
    let si = SocketInfo {
        local_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        local_port: 8080,
        remote_addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        remote_port: 443,
        protocol: SocketProtocol::Tcp,
        state: SocketState::Established,
    };
    assert_eq!(
        si.to_string(),
        "TCP 127.0.0.1:8080 -> 10.0.0.1:443 [ESTABLISHED]"
    );
}

#[test]
fn test_socket_info_display_udp_ipv6() {
    let si = SocketInfo {
        local_addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
        local_port: 53,
        remote_addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        remote_port: 0,
        protocol: SocketProtocol::Udp,
        state: SocketState::Other,
    };
    assert_eq!(si.to_string(), "UDP ::1:53 -> :::0 [OTHER]");
}

// ---------------------------------------------------------------------------
// SocketProtocol Display
// ---------------------------------------------------------------------------

#[test]
fn test_socket_protocol_display() {
    assert_eq!(SocketProtocol::Tcp.to_string(), "TCP");
    assert_eq!(SocketProtocol::Udp.to_string(), "UDP");
}

// ---------------------------------------------------------------------------
// SocketState Display
// ---------------------------------------------------------------------------

#[test]
fn test_socket_state_display() {
    assert_eq!(SocketState::Established.to_string(), "ESTABLISHED");
    assert_eq!(SocketState::Listen.to_string(), "LISTEN");
    assert_eq!(SocketState::TimeWait.to_string(), "TIME_WAIT");
    assert_eq!(SocketState::CloseWait.to_string(), "CLOSE_WAIT");
    assert_eq!(SocketState::SynSent.to_string(), "SYN_SENT");
    assert_eq!(SocketState::SynReceived.to_string(), "SYN_RECEIVED");
    assert_eq!(SocketState::Closed.to_string(), "CLOSED");
    assert_eq!(SocketState::Other.to_string(), "OTHER");
}

// ---------------------------------------------------------------------------
// NetworkUsage Display
// ---------------------------------------------------------------------------

#[test]
fn test_network_usage_display() {
    let usage = NetworkUsage {
        pid: 42,
        bytes_in: 1024,
        bytes_out: 2048,
    };
    assert_eq!(usage.to_string(), "pid 42 : 1024 bytes in, 2048 bytes out");
}

// ---------------------------------------------------------------------------
// CodeSigningInfo Display
// ---------------------------------------------------------------------------

#[test]
fn test_code_signing_info_display_valid_apple() {
    let info = CodeSigningInfo {
        code_id: Some("com.apple.Safari".to_string()),
        team_id: None,
        is_apple_signed: true,
        is_valid: true,
    };
    assert_eq!(info.to_string(), "com.apple.Safari [Apple]");
}

#[test]
fn test_code_signing_info_display_unsigned() {
    let info = CodeSigningInfo {
        code_id: None,
        team_id: None,
        is_apple_signed: false,
        is_valid: false,
    };
    assert_eq!(info.to_string(), "<unsigned> [INVALID]");
}

#[test]
fn test_code_signing_info_display_third_party() {
    let info = CodeSigningInfo {
        code_id: Some("com.example.app".to_string()),
        team_id: Some("TEAM456".to_string()),
        is_apple_signed: false,
        is_valid: true,
    };
    assert_eq!(info.to_string(), "com.example.app [team TEAM456]");
}
