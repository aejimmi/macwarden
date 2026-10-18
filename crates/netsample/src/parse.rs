//! Pure parser for `nettop -x -J bytes_in,bytes_out -l 1` output.
//!
//! `nettop` emits one line per process followed by indented per-connection
//! lines. Every line is prefixed with a timestamp column. Process lines carry
//! cumulative `bytes_in`/`bytes_out` counters keyed by `name.pid`; connection
//! lines carry a `proto local<->remote` token plus their own counters.
//!
//! This module is deliberately platform-neutral and side-effect free so it can
//! be unit-tested on any target, including Linux CI. Spawning the subprocess
//! lives in the macOS-only [`super::sample`].

/// A single remote connection owned by a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    /// Protocol token as reported (`tcp4`, `tcp6`, `udp4`, `udp6`).
    pub proto: String,
    /// Remote IP address (may include an IPv6 zone suffix).
    pub remote_ip: String,
    /// Remote port.
    pub remote_port: u16,
    /// Cumulative bytes received on this connection.
    pub bytes_in: u64,
    /// Cumulative bytes sent on this connection.
    pub bytes_out: u64,
}

/// A process row with its aggregate counters and live connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcNet {
    /// Process id parsed from the `name.pid` column.
    pub pid: u32,
    /// Process name as reported by nettop (may be truncated).
    pub name: String,
    /// Cumulative bytes received by the whole process.
    pub bytes_in: u64,
    /// Cumulative bytes sent by the whole process.
    pub bytes_out: u64,
    /// Real remote connections (wildcards / listeners filtered out).
    pub conns: Vec<Conn>,
}

/// Parse full nettop output into per-process rows.
///
/// Lines that fail to parse are skipped rather than propagated — nettop output
/// is best-effort telemetry, not a contract.
#[must_use]
pub fn parse(output: &str) -> Vec<ProcNet> {
    let mut procs: Vec<ProcNet> = Vec::new();
    for line in output.lines() {
        if is_header(line) {
            continue;
        }
        match classify(line) {
            Some(Row::Proc(p)) => procs.push(p),
            Some(Row::Conn(c)) => {
                if let Some(last) = procs.last_mut() {
                    last.conns.push(c);
                }
            }
            None => {}
        }
    }
    procs
}

fn is_header(line: &str) -> bool {
    line.trim_start().starts_with("time")
}

enum Row {
    Proc(ProcNet),
    Conn(Conn),
}

/// A connection line begins (after the timestamp) with a protocol token.
fn is_proto(tok: &str) -> bool {
    matches!(tok, "tcp4" | "tcp6" | "udp4" | "udp6")
}

fn classify(line: &str) -> Option<Row> {
    let mut toks = line.split_whitespace();
    let _timestamp = toks.next()?;
    let first = toks.next()?;
    if is_proto(first) {
        return parse_conn(first, &mut toks).map(Row::Conn);
    }
    parse_proc(first, &mut toks).map(Row::Proc)
}

fn parse_proc<'a>(name_pid: &str, toks: &mut impl Iterator<Item = &'a str>) -> Option<ProcNet> {
    let (name, pid_str) = name_pid.rsplit_once('.')?;
    let pid: u32 = pid_str.parse().ok()?;
    let bytes_in = toks.next().and_then(|t| t.parse().ok()).unwrap_or(0);
    let bytes_out = toks.next().and_then(|t| t.parse().ok()).unwrap_or(0);
    Some(ProcNet {
        pid,
        name: name.to_string(),
        bytes_in,
        bytes_out,
        conns: Vec::new(),
    })
}

fn parse_conn<'a>(proto: &str, toks: &mut impl Iterator<Item = &'a str>) -> Option<Conn> {
    let endpoints = toks.next()?;
    let (_local, remote) = endpoints.split_once("<->")?;
    let is_v6 = proto.ends_with('6');
    let (remote_ip, remote_port) = split_endpoint(remote, is_v6)?;
    if remote_ip.contains('*') || remote_ip.is_empty() {
        return None;
    }
    let bytes_in = toks.next().and_then(|t| t.parse().ok()).unwrap_or(0);
    let bytes_out = toks.next().and_then(|t| t.parse().ok()).unwrap_or(0);
    Some(Conn {
        proto: proto.to_string(),
        remote_ip: remote_ip.to_string(),
        remote_port,
        bytes_in,
        bytes_out,
    })
}

/// Split a remote endpoint into `(ip, port)`. IPv4 uses `ip:port`; IPv6 uses
/// `ip.port` (the address itself contains the colons).
fn split_endpoint(endpoint: &str, is_v6: bool) -> Option<(&str, u16)> {
    let sep = if is_v6 { '.' } else { ':' };
    let (ip, port_str) = endpoint.rsplit_once(sep)?;
    let port = port_str.parse().unwrap_or(0);
    Some((ip, port))
}

#[cfg(test)]
#[path = "parse_test.rs"]
mod parse_test;
