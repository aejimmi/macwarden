//! lsof parsing for network connection enumeration.
//!
//! Runs `lsof -i -P` and parses the output into structured
//! [`LsofConnection`] values suitable for rule evaluation.

use std::process::Command;

use anyhow::{Context, Result};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Raw parsed connection from lsof output.
#[derive(Debug)]
pub(crate) struct LsofConnection {
    pub(crate) process: String,
    pub(crate) pid: u32,
    pub(crate) remote_host: String,
    pub(crate) remote_port: u16,
    pub(crate) protocol: String,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Run `lsof -i -P` and parse the output into connections.
pub(crate) fn collect_lsof_connections() -> Result<Vec<LsofConnection>> {
    // Drop -n flag: let lsof resolve hostnames. Slower but much more readable.
    // Keep -P to show numeric ports (port names are ambiguous).
    let output = Command::new("lsof")
        .args(["-i", "-P"])
        .output()
        .context("failed to run lsof")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_lsof_output(&stdout))
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse lsof output lines into structured connections.
///
/// Only includes outbound/established connections -- skips LISTEN sockets
/// and connections to `*:*`.
fn parse_lsof_output(output: &str) -> Vec<LsofConnection> {
    let mut connections = Vec::new();
    for line in output.lines().skip(1) {
        if let Some(conn) = parse_lsof_line(line) {
            connections.push(conn);
        }
    }
    dedup_connections(&mut connections);
    connections
}

/// Deduplicate connections by (process_name, remote_host).
/// Multiple connections from the same process to the same host are collapsed.
fn dedup_connections(conns: &mut Vec<LsofConnection>) {
    conns.sort_by(|a, b| {
        a.process
            .cmp(&b.process)
            .then_with(|| a.remote_host.cmp(&b.remote_host))
    });
    conns.dedup_by(|a, b| a.process == b.process && a.remote_host == b.remote_host);
}

/// Parse a single lsof output line.
fn parse_lsof_line(line: &str) -> Option<LsofConnection> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 9 {
        return None;
    }

    let process = parts.first()?.to_string();
    let pid: u32 = parts.get(1)?.parse().ok()?;
    let state = parts.last().copied().unwrap_or("");

    if state.contains("LISTEN") {
        return None;
    }

    let name_col = find_connection_column(&parts)?;
    let (remote_host, remote_port) = parse_remote(name_col)?;

    if remote_host == "*" {
        return None;
    }

    Some(LsofConnection {
        process,
        pid,
        remote_host,
        remote_port,
        protocol: detect_protocol(&parts),
    })
}

/// Find the column containing the connection string (has `"->"` or is column 8).
fn find_connection_column<'a>(parts: &[&'a str]) -> Option<&'a str> {
    for &p in parts.iter().rev() {
        if p.contains("->") {
            return Some(p);
        }
    }
    parts.get(8).copied()
}

/// Extract remote host and port from a connection string.
fn parse_remote(col: &str) -> Option<(String, u16)> {
    if let Some(arrow_pos) = col.find("->") {
        split_host_port(&col[arrow_pos + 2..])
    } else {
        split_host_port(col)
    }
}

/// Split `host:port`. Handles IPv6 brackets like `[::1]:443`.
fn split_host_port(s: &str) -> Option<(String, u16)> {
    if let Some(bracket_end) = s.find(']') {
        let host = &s[1..bracket_end];
        let port = s.get(bracket_end + 2..)?.parse().unwrap_or(0);
        Some((host.to_owned(), port))
    } else if let Some(colon) = s.rfind(':') {
        let host = &s[..colon];
        let port = s[colon + 1..].parse().unwrap_or(0);
        Some((host.to_owned(), port))
    } else {
        Some((s.to_owned(), 0))
    }
}

/// Detect TCP or UDP from lsof columns.
fn detect_protocol(parts: &[&str]) -> String {
    for &p in parts {
        if p.eq_ignore_ascii_case("TCP") || p.eq_ignore_ascii_case("UDP") {
            return p.to_ascii_uppercase();
        }
    }
    "TCP".to_owned()
}

#[cfg(test)]
#[path = "net_lsof_test.rs"]
mod net_lsof_test;
