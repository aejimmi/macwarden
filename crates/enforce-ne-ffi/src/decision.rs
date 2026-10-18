//! Pure decision logic: build matcher inputs and consult [`net::RuleSet`].
//!
//! This module is free of FFI and I/O. It maps the loosely-typed inputs the
//! Swift provider resolves from an `NEFilterFlow` (code id, path, host, ip,
//! port, protocol) into a [`net::ProcessIdentity`] + [`net::Destination`] and
//! returns the verdict [`net::RuleSet::decide_for`] produces. Identity
//! resolution (audit token -> code id/path) stays in Swift so this core has no
//! platform dependency.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use net::{
    AddressFamily, Destination, NetworkAction, ProcessIdentity, Protocol, RuleSet, is_apple_code_id,
};

/// Verdict returned across the C ABI. Values are stable and match the header.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeDecision {
    /// Allow the flow.
    Allow = 0,
    /// Drop the flow.
    Deny = 1,
    /// Allow but record (maps to allow at the provider).
    Log = 2,
}

impl NeDecision {
    /// Map a [`NetworkAction`] onto the C-ABI verdict.
    #[must_use]
    pub fn from_action(action: NetworkAction) -> Self {
        match action {
            NetworkAction::Allow => Self::Allow,
            NetworkAction::Deny => Self::Deny,
            NetworkAction::Log => Self::Log,
        }
    }
}

/// Build a [`ProcessIdentity`] from the fields the provider resolved.
///
/// Empty or absent `code_id`/`path` are treated as unknown. `is_apple_signed`
/// is derived purely from the code id (`net::is_apple_code_id`) so the
/// "Allow Apple Programs" policy shim behaves as in the daemon, with no I/O.
#[must_use]
pub fn build_identity(code_id: Option<&str>, path: Option<&str>) -> ProcessIdentity {
    let code_id = code_id
        .filter(|s| !s.is_empty())
        .map(std::borrow::ToOwned::to_owned);
    let is_apple_signed = code_id.as_deref().map(is_apple_code_id);
    ProcessIdentity {
        pid: 0,
        uid: 0,
        path: PathBuf::from(path.filter(|s| !s.is_empty()).unwrap_or_default()),
        code_id,
        team_id: None,
        is_valid_signature: None,
        is_apple_signed,
    }
}

/// Build a [`Destination`] from host/ip/port/proto fields.
///
/// An empty or unparseable `ip` falls back to the unspecified IPv4 address so
/// a host-only rule can still match. `port == 0` and `proto` outside the
/// known IANA numbers (6 = TCP, 17 = UDP) are treated as absent.
#[must_use]
pub fn build_destination(
    host: Option<&str>,
    ip: Option<&str>,
    port: u16,
    proto: u8,
) -> Destination {
    let ip_addr = ip
        .and_then(|s| s.parse::<IpAddr>().ok())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let address_family = match ip_addr {
        IpAddr::V4(_) => AddressFamily::Inet,
        IpAddr::V6(_) => AddressFamily::Inet6,
    };
    Destination {
        host: host
            .filter(|s| !s.is_empty())
            .map(std::borrow::ToOwned::to_owned),
        ip: ip_addr,
        port: (port != 0).then_some(port),
        protocol: protocol_from_u8(proto),
        address_family,
    }
}

/// Map an IANA protocol number to [`Protocol`]; unknown values are `None`.
#[must_use]
fn protocol_from_u8(proto: u8) -> Option<Protocol> {
    match proto {
        6 => Some(Protocol::Tcp),
        17 => Some(Protocol::Udp),
        _ => None,
    }
}

/// Decide a flow against a rule set. Pure; never panics on well-formed inputs.
#[must_use]
pub fn decide(
    rules: &RuleSet,
    code_id: Option<&str>,
    path: Option<&str>,
    host: Option<&str>,
    ip: Option<&str>,
    port: u16,
    proto: u8,
) -> NeDecision {
    let process = build_identity(code_id, path);
    let dest = build_destination(host, ip, port, proto);
    NeDecision::from_action(rules.decide_for(&process, &dest).action)
}

#[cfg(test)]
#[path = "decision_test.rs"]
mod decision_test;
