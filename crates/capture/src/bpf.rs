//! BPF filter construction from a target app's 5-tuples (spec R2/R7).
//!
//! This module is **pure** — it emits a libpcap filter *string* from typed
//! `(ip, port, proto)` tuples and never touches a device, so it is unit-tested
//! without root. The tuples originate from the daemon's connection scanner
//! (typed `IpAddr`/`u16`/proto), **never** from client-supplied strings, which
//! is the mitigation for BPF-filter injection in the threat model: only numeric
//! hosts and ports are ever emitted.
//!
//! An **empty** tuple set yields a filter that matches *nothing*
//! ([`MATCH_NOTHING_FILTER`]) — never a filter that matches everything. An
//! empty BPF program matches the whole interface, so we must never emit an empty
//! string.

use crate::types::L4Proto;
use std::fmt::Write as _;
use std::net::IpAddr;

/// A libpcap filter primitive that is never true, used when there are no tuples
/// to match. `less length` is `len <= length`; a captured frame always has a
/// positive length, so `less 0` matches nothing while still compiling as a
/// valid BPF program. This is deliberately **not** the empty string, which
/// libpcap treats as match-all.
pub const MATCH_NOTHING_FILTER: &str = "less 0";

/// One remote flow the trace is scoped to: a numeric host, port, and transport.
///
/// Constructed by the daemon from its own connection scanner (spec R7), so the
/// values are always typed and trusted. `proto` is normally [`L4Proto::Tcp`] or
/// [`L4Proto::Udp`]; other protocols yield a host+port clause with no transport
/// qualifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowTuple {
    /// Remote host address (IPv4 or IPv6).
    pub ip: IpAddr,
    /// Remote transport port.
    pub port: u16,
    /// Transport protocol.
    pub proto: L4Proto,
}

impl FlowTuple {
    /// Build a flow tuple from a host, port, and transport protocol.
    #[must_use]
    pub const fn new(ip: IpAddr, port: u16, proto: L4Proto) -> Self {
        Self { ip, port, proto }
    }
}

/// Build a libpcap filter expression matching **only** the given flows.
///
/// Each tuple becomes `(host <ip> and port <n> and <proto>)`; tuples are joined
/// with ` or `. Adding a flow to the set is monotonic — the resulting string is
/// a superset of the prior one. An empty set returns [`MATCH_NOTHING_FILTER`],
/// never a match-all filter (spec R2, threat model "BPF filter injection").
#[must_use]
pub fn build_bpf_filter(tuples: &[FlowTuple]) -> String {
    if tuples.is_empty() {
        return MATCH_NOTHING_FILTER.to_string();
    }
    let mut out = String::new();
    for (i, t) in tuples.iter().enumerate() {
        if i > 0 {
            out.push_str(" or ");
        }
        append_clause(&mut out, t);
    }
    out
}

/// Append one `(host <ip> and port <n>[ and <proto>])` clause. `host` accepts
/// both IPv4 and IPv6 literals in libpcap, so a single form covers both.
fn append_clause(out: &mut String, t: &FlowTuple) {
    let _ = write!(out, "(host {} and port {}", t.ip, t.port);
    if let Some(tok) = proto_token(t.proto) {
        let _ = write!(out, " and {tok}");
    }
    out.push(')');
}

/// The libpcap transport qualifier for a protocol, or `None` for protocols with
/// no port-bearing transport (ICMP/ARP/other) — those match on host+port alone.
fn proto_token(proto: L4Proto) -> Option<&'static str> {
    match proto {
        L4Proto::Tcp => Some("tcp"),
        L4Proto::Udp => Some("udp"),
        L4Proto::Icmp | L4Proto::Arp | L4Proto::Other => None,
    }
}

#[cfg(test)]
#[path = "bpf_test.rs"]
mod bpf_test;
