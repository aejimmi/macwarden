#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

#[test]
fn test_sshd_failed_password() {
    let line = "sshd[123]: Failed password for root from 203.0.113.7 port 55234 ssh2";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(v4(203, 0, 113, 7))
    );
}

#[test]
fn test_sshd_invalid_user() {
    let line = "sshd[99]: Invalid user admin from 198.51.100.9 port 40022";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(v4(198, 51, 100, 9))
    );
}

#[test]
fn test_sshd_publickey() {
    let line = "sshd[7]: Failed publickey for deploy from 192.0.2.44 port 22 ssh2: RSA";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(v4(192, 0, 2, 44))
    );
}

#[test]
fn test_sshd_ipv4_mapped_ipv6() {
    let line = "sshd[7]: Failed password for root from ::ffff:203.0.113.8 port 22 ssh2";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(v4(203, 0, 113, 8))
    );
}

#[test]
fn test_sshd_ipv6_peer() {
    let line = "sshd[7]: Failed password for root from 2001:db8::1 port 22 ssh2";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
    );
}

#[test]
fn test_screensharingd_viewer_address() {
    let line = "screensharingd[55]: Authentication: FAILED :: User Name: guest :: Viewer Address: 203.0.113.20 :: Type: DH";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(v4(203, 0, 113, 20))
    );
}

#[test]
fn test_screensharingd_at_anchor() {
    let line = "screensharingd: Authentication failed for user at 198.51.100.77";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(v4(198, 51, 100, 77))
    );
}

#[test]
fn test_redacted_private() {
    let line = "sshd[123]: Failed password for root from <private> port 55234 ssh2";
    assert_eq!(parse_auth_failure(line), AuthLine::Redacted);
}

#[test]
fn test_non_failure_line_ignored() {
    let line = "sshd[123]: Accepted password for user from 203.0.113.7 port 22 ssh2";
    assert_eq!(parse_auth_failure(line), AuthLine::Ignore);
}

#[test]
fn test_garbage_line_ignored() {
    for line in [
        "",
        "random noise with no marker",
        "Failed password for root from not-an-ip port 22",
        "Failed password", // marker but no peer
        "\0\0\0 Failed password from",
        "Invalid user \u{202e}\u{202d} from 999.999.999.999",
    ] {
        assert!(
            matches!(parse_auth_failure(line), AuthLine::Ignore),
            "line should be ignored: {line:?}"
        );
    }
}

#[test]
fn test_spoofed_username_not_extracted_as_peer() {
    // The attacker controls the username; the peer field is what the OS emits
    // after `from`. The username IP-looking value must not become the offender.
    let line = "sshd[1]: Invalid user 8.8.8.8 from 203.0.113.30 port 22";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(v4(203, 0, 113, 30))
    );
}

#[test]
fn test_username_injected_from_ip_not_misattributed() {
    // The attacker sets the username to `x from 8.8.8.8`, so the raw line carries
    // two `from` tokens. The real peer is the one before `port <n>`; the injected
    // 8.8.8.8 makes the line ambiguous, which must resolve to Ignore — and MUST
    // NOT ban 8.8.8.8 (a public resolver the private-range ignore list misses).
    let line = "sshd[1]: Invalid user x from 8.8.8.8 from 203.0.113.30 port 22";
    assert_eq!(parse_auth_failure(line), AuthLine::Ignore);
    // The specific safety property: the smuggled third party is never the verdict.
    assert_ne!(parse_auth_failure(line), AuthLine::Failure(v4(8, 8, 8, 8)));
}

#[test]
fn test_username_injected_fake_port_form_not_misattributed() {
    // A username crafted to look like a full peer clause. The line then has two
    // distinct candidates (8.8.8.8 and the real 203.0.113.31) → Ignore, not a ban
    // of 8.8.8.8.
    let line = "sshd[1]: Invalid user hax from 8.8.8.8 port 1 from 203.0.113.31 port 22";
    let parsed = parse_auth_failure(line);
    assert_ne!(parsed, AuthLine::Failure(v4(8, 8, 8, 8)));
    assert_eq!(parsed, AuthLine::Ignore);
}

#[test]
fn test_legit_from_ip_port_still_resolves() {
    // The canonical, un-injected form still parses to the single real peer.
    let line = "sshd[42]: Failed password for admin from 198.51.100.5 port 33001 ssh2";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(v4(198, 51, 100, 5))
    );
}

#[test]
fn test_parse_ip_ipv4_colon_port_token() {
    // `parse_ip`'s trailing `:port` branch: a `host:port` peer token resolves to
    // the host address (port stripped).
    let line = "sshd[7]: Failed password for root from 1.2.3.4:9999";
    assert_eq!(parse_auth_failure(line), AuthLine::Failure(v4(1, 2, 3, 4)));
}

#[test]
fn test_parse_ip_bracketed_ipv6_with_port_token() {
    // A bracketed IPv6-with-port token (`[addr]:port`) resolves to the inner
    // address rather than mis-parsing to nothing.
    let line = "sshd[7]: Failed password for root from [2001:db8::1]:9999";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap()))
    );
}

#[test]
fn test_parse_ip_bare_bracketed_ipv6_token() {
    // A bracketed IPv6 without a port also resolves to the inner address.
    let line = "sshd[7]: Failed password for root from [2001:db8::2] port 22 ssh2";
    assert_eq!(
        parse_auth_failure(line),
        AuthLine::Failure(IpAddr::V6("2001:db8::2".parse::<Ipv6Addr>().unwrap()))
    );
}

#[test]
fn test_signal_from_line() {
    let line = "sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2";
    let sig = signal_from_line(line).unwrap();
    assert_eq!(sig.ip, v4(203, 0, 113, 7));
    assert_eq!(sig.detector, DETECTOR_AUTH_FAILURE);
    // Redacted / ignore yield no signal.
    assert!(signal_from_line("Failed password for root from <private>").is_none());
    assert!(signal_from_line("Accepted password").is_none());
}
