//! The `auth-failure` detector: a **parser** from a unified-log line to an auth
//! failure or a redaction marker. Parsing only — no subprocess; the daemon owns
//! the `log stream` feed and passes lines here.
//!
//! Total over attacker-controlled input by construction: substring scanning (no
//! catastrophic-backtrack regex), no indexing that can panic, and every
//! candidate peer string is passed through [`IpAddr::from_str`] before it can
//! enter the ban path.
//!
//! # Anti-injection
//!
//! `sshd` logs the attacker-supplied **username** verbatim, so a naive "first IP
//! after ` from `" parse lets a username like `x from 8.8.8.8` smuggle a fake
//! peer and get a third party banned. To defend against that we (1) prefer the
//! token immediately **before** `port <n>` — the position the OS reserves for the
//! real peer in the `from <ip> port <n>` grammar — plus the Screen-Sharing
//! `Viewer Address:` / ` at ` anchors, and (2) require the line to yield exactly
//! **one** distinct parseable peer. A line carrying two or more different
//! candidate IPs is ambiguous and is dropped ([`AuthLine::Ignore`]) rather than
//! risk mis-attribution — so a crafted username can, at worst, suppress the
//! offender's own ban, never ban an unrelated address.
//!
//! On modern macOS the peer IP may be logged as `<private>` unless private-data
//! logging is enabled; that case is reported as [`AuthLine::Redacted`] so the
//! daemon can log its one-time warning and disable the detector rather than
//! silently banning nothing.

use std::net::IpAddr;
use std::str::FromStr;

use crate::record::{DETECTOR_AUTH_FAILURE, Signal};

/// The redaction placeholder the unified log substitutes for private data.
const REDACTION: &str = "<private>";

/// Substrings that mark an authentication **failure** line worth parsing.
const FAILURE_MARKERS: &[&str] = &[
    "Failed password",
    "Failed publickey",
    "Failed keyboard-interactive",
    "Invalid user",
    "authentication failure",
    "maximum authentication attempts",
    "Authentication: FAILED",
    "Authentication failed",
];

/// Anchors after which a candidate peer token may appear (Screen Sharing's
/// `Viewer Address:` / ` at `, and the generic ` from `). The authoritative
/// sshd peer — the token before `port <n>` — is collected separately.
const PEER_ANCHORS: &[&str] = &[" from ", "Viewer Address: ", " at "];

/// The ` port <n>` marker whose preceding token is the authoritative sshd peer.
const PORT_MARKER: &str = " port ";

/// The classification of one unified-log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthLine {
    /// An auth failure whose peer IP parsed cleanly.
    Failure(IpAddr),
    /// An auth-failure line whose peer field is redacted as `<private>`.
    Redacted,
    /// Not an auth-failure line, or no parseable peer field.
    Ignore,
}

/// Parse one unified-log line into an [`AuthLine`].
#[must_use]
pub fn parse_auth_failure(line: &str) -> AuthLine {
    if !FAILURE_MARKERS.iter().any(|m| line.contains(m)) {
        return AuthLine::Ignore;
    }
    let candidates = peer_candidates(line);
    if candidates.is_empty() {
        return AuthLine::Ignore;
    }
    // A redacted peer means the OS withheld the real address: never guess, report
    // redaction so the daemon can self-disable the detector.
    if candidates.contains(&REDACTION) {
        return AuthLine::Redacted;
    }
    let mut ips: Vec<IpAddr> = candidates.iter().filter_map(|t| parse_ip(t)).collect();
    ips.sort_unstable();
    ips.dedup();
    match ips.as_slice() {
        [ip] => AuthLine::Failure(*ip),
        // Zero parseable peers, or two+ distinct (ambiguous — a crafted username
        // smuggling a second IP): drop rather than risk mis-attribution.
        _ => AuthLine::Ignore,
    }
}

/// Parse one unified-log line into a failure [`Signal`], or `None`.
///
/// A [`AuthLine::Redacted`] line yields `None` here — the daemon inspects
/// [`parse_auth_failure`] directly to detect redaction and self-disable.
#[must_use]
pub fn signal_from_line(line: &str) -> Option<Signal> {
    match parse_auth_failure(line) {
        AuthLine::Failure(ip) => Some(Signal::new(ip, DETECTOR_AUTH_FAILURE)),
        AuthLine::Redacted | AuthLine::Ignore => None,
    }
}

/// Collect every candidate peer token in `line`: the token before each
/// `port <n>` marker (the authoritative sshd peer position) and the token after
/// each [`PEER_ANCHORS`] entry. Duplicates are fine — the caller dedups by parsed
/// IP and requires a unique result.
fn peer_candidates(line: &str) -> Vec<&str> {
    let mut out = Vec::new();
    out.extend(token_before_port(line));
    for anchor in PEER_ANCHORS {
        let mut from = 0;
        while let Some(rel) = line[from..].find(anchor) {
            let after = from + rel + anchor.len();
            if let Some(token) = line[after..].split_whitespace().next()
                && !token.is_empty()
            {
                out.push(token);
            }
            from = after;
        }
    }
    out
}

/// The whitespace token immediately preceding a `port <digit>` marker — the
/// address field the `sshd` `from <ip> port <n>` grammar reserves for the real
/// peer, unspoofable by the attacker-controlled username.
fn token_before_port(line: &str) -> Option<&str> {
    let idx = line.find(PORT_MARKER)?;
    let after = &line[idx + PORT_MARKER.len()..];
    if !after.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    line[..idx].split_whitespace().next_back()
}

/// Parse a peer token into an [`IpAddr`], tolerating an IPv4-mapped `::ffff:`
/// prefix, a bracketed `[..]` / `[..]:port` IPv6 form, and a trailing `:port` /
/// `,` / `;` / `.` punctuation.
fn parse_ip(token: &str) -> Option<IpAddr> {
    let t = token
        .trim_matches(|c| c == ',' || c == ';')
        .trim_end_matches('.');
    // Bracketed IPv6, optionally with a `:port` suffix: `[2001:db8::1]:9999`.
    if let Some(rest) = t.strip_prefix('[') {
        let inner = rest.split_once(']').map_or(rest, |(inner, _tail)| inner);
        return IpAddr::from_str(inner).ok().map(normalize);
    }
    if let Ok(ip) = IpAddr::from_str(t) {
        return Some(normalize(ip));
    }
    // A trailing `:port` on a bare IPv4 (some formats): split once from the end.
    if let Some((host, port)) = t.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
        && let Ok(ip) = IpAddr::from_str(host)
    {
        return Some(normalize(ip));
    }
    None
}

/// Fold an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, how `sshd` logs an IPv4
/// peer on a dual-stack socket) down to its IPv4 form, so a ban matches the
/// flow's remote endpoint regardless of the log's address representation.
fn normalize(ip: IpAddr) -> IpAddr {
    if let IpAddr::V6(v6) = ip
        && let Some(v4) = v6.to_ipv4_mapped()
    {
        return IpAddr::V4(v4);
    }
    ip
}

#[cfg(test)]
#[path = "authlog_test.rs"]
mod authlog_test;
