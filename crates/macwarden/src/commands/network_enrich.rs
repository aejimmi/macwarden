//! Enrichment for `macwarden network` entries.
//!
//! Parses remote IP/port from lsof connection strings, then batch-enriches
//! entries with code signing identity, GeoIP, reverse DNS, and tracker
//! detection.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tracing::warn;

use net::{GeoLookup, TrackerDatabase};

use crate::commands::net::net_scan::{format_code_id, lookup_code_id};
use crate::commands::network::NetEntry;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of unique IPs to resolve via reverse DNS.
const RDNS_BATCH_CAP: usize = 50;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Batch-enrich network entries with code signing, GeoIP, rDNS, and tracker
/// detection.
///
/// Mutates entries in place, filling in enrichment fields. All enrichment
/// is best-effort -- failures are logged at debug level and the entry is
/// left with `None` for that field.
pub fn enrich_entries(entries: &mut [NetEntry]) {
    // 1. Parse remote IP/port from connection strings.
    for entry in entries.iter_mut() {
        if let Some((ip, port)) = parse_remote(&entry.connection) {
            entry.remote_ip = Some(ip.to_string());
            entry.remote_port = Some(port);
        }
    }

    // 2. Code signing lookup per unique PID.
    let unique_pids: Vec<(u32, String)> = {
        let mut seen = HashSet::new();
        entries
            .iter()
            .filter(|e| seen.insert(e.pid))
            .map(|e| (e.pid, e.process.clone()))
            .collect()
    };
    let code_ids: HashMap<u32, String> = unique_pids
        .into_iter()
        .filter_map(|(pid, name)| {
            let id = lookup_code_id(pid, &name)?;
            Some((pid, id))
        })
        .collect();
    for entry in entries.iter_mut() {
        if let Some(id) = code_ids.get(&entry.pid) {
            entry.code_id = Some(id.clone());
        }
    }

    // 3. GeoIP lookup per unique remote IP.
    let geo = match GeoLookup::new() {
        Ok(g) => Some(g),
        Err(e) => {
            warn!("GeoIP databases unavailable: {e}");
            None
        }
    };
    if let Some(ref geo) = geo {
        for entry in entries.iter_mut() {
            let Some(ref ip_str) = entry.remote_ip else {
                continue;
            };
            let Ok(ip) = ip_str.parse::<IpAddr>() else {
                continue;
            };
            if is_local_addr(&ip) {
                continue;
            }
            let info = geo.lookup(ip);
            entry.country = info.country;
            entry.owner = info.asn_name;
        }
    }

    // 4. Reverse DNS for unique remote IPs (cap at RDNS_BATCH_CAP).
    let unique_ips: Vec<IpAddr> = {
        let mut seen = HashSet::new();
        entries
            .iter()
            .filter_map(|e| {
                let ip: IpAddr = e.remote_ip.as_deref()?.parse().ok()?;
                if is_local_addr(&ip) {
                    return None;
                }
                if seen.insert(ip) { Some(ip) } else { None }
            })
            .take(RDNS_BATCH_CAP)
            .collect()
    };
    let resolved: HashMap<IpAddr, String> = unique_ips
        .iter()
        .filter_map(|&ip| {
            let name = reverse_lookup(ip)?;
            Some((ip, name))
        })
        .collect();
    for entry in entries.iter_mut() {
        let Some(ref ip_str) = entry.remote_ip else {
            continue;
        };
        let Ok(ip) = ip_str.parse::<IpAddr>() else {
            continue;
        };
        if let Some(hostname) = resolved.get(&ip) {
            entry.remote_host = Some(hostname.clone());
        }
    }

    // 5. Tracker check on resolved hostnames.
    let tracker_db = match TrackerDatabase::load_builtin() {
        Ok(db) => Some(db),
        Err(e) => {
            warn!("tracker database unavailable: {e}");
            None
        }
    };
    if let Some(ref db) = tracker_db {
        for entry in entries.iter_mut() {
            if let Some(h) = entry.remote_host.as_deref()
                && let Some(m) = db.lookup(h)
            {
                entry.tracker = Some(m.category.to_string());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a remote IP address and port from an lsof connection string.
///
/// Handles formats like:
/// - `172.20.10.4:49792->160.79.104.10:443` (arrow format, IPv4)
/// - `[::1]:49792->[2607:f8b0:4004:800::200e]:443` (arrow format, IPv6)
/// - `160.79.104.10:443` (bare remote, IPv4)
/// - `[2607:f8b0:4004:800::200e]:443` (bare remote, IPv6)
///
/// Returns `None` for unparseable strings or wildcard entries like `*:*`.
pub fn parse_remote(connection: &str) -> Option<(IpAddr, u16)> {
    // Arrow format: take everything after "->"
    let remote_part = connection.split("->").nth(1).unwrap_or(connection);

    // Skip wildcard entries.
    if remote_part.contains('*') {
        return None;
    }

    parse_ip_port(remote_part)
}

/// Parse `ip:port` from a string, handling both IPv4 and bracketed IPv6.
fn parse_ip_port(s: &str) -> Option<(IpAddr, u16)> {
    // IPv6 bracketed: [addr]:port
    if let Some(rest) = s.strip_prefix('[') {
        let bracket_end = rest.find(']')?;
        let ip_str = rest.get(..bracket_end)?;
        let ip: IpAddr = ip_str.parse().ok()?;
        // Expect "]:port" after the bracket
        let after_bracket = rest.get(bracket_end + 1..)?;
        let port_str = after_bracket.strip_prefix(':')?;
        let port: u16 = port_str.parse().ok()?;
        return Some((ip, port));
    }

    // IPv4: last colon separates ip and port
    let colon_pos = s.rfind(':')?;
    let ip_str = s.get(..colon_pos)?;
    let port_str = s.get(colon_pos + 1..)?;
    let ip: IpAddr = ip_str.parse().ok()?;
    let port: u16 = port_str.parse().ok()?;
    Some((ip, port))
}

/// Check if an IP address is local (loopback, link-local, multicast,
/// unspecified).
pub fn is_local_addr(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || is_private_v4(*v4)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() || is_link_local_v6(v6)
        }
    }
}

/// Check if an IPv4 address is in a private range (RFC 1918).
fn is_private_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // 10.0.0.0/8
    octets[0] == 10
    // 172.16.0.0/12
    || (octets[0] == 172 && (16..=31).contains(&octets[1]))
    // 192.168.0.0/16
    || (octets[0] == 192 && octets[1] == 168)
}

/// Check if an IPv6 address is link-local (fe80::/10).
fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    let segments = ip.segments();
    segments[0] & 0xffc0 == 0xfe80
}

// ---------------------------------------------------------------------------
// Reverse DNS (duplicated from net_rdns.rs to avoid refactoring)
// ---------------------------------------------------------------------------

/// Perform a single reverse DNS lookup, filtering out garbage results.
fn reverse_lookup(ip: IpAddr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&ip).ok()?;

    // Skip if the result is just the IP printed back.
    if name == ip.to_string() {
        return None;
    }

    // Skip bare names with no dots (e.g. "localhost").
    if !name.contains('.') {
        return None;
    }

    // Skip garbage auto-generated rDNS that embeds the IP octets.
    if is_garbage_rdns(&name, ip) {
        return None;
    }

    // Strip trailing dot if present (some resolvers return FQDN).
    let clean = name.strip_suffix('.').unwrap_or(&name);
    Some(clean.to_owned())
}

/// Heuristic: rDNS is garbage if it's auto-generated CDN/cloud noise.
fn is_garbage_rdns(name: &str, ip: IpAddr) -> bool {
    let lower = name.to_ascii_lowercase();
    // Known garbage patterns (CDN node IDs, auto-generated cloud rDNS).
    if lower.ends_with(".1e100.net")
        || lower.contains(".compute.amazonaws.com")
        || lower.contains(".compute-1.amazonaws.com")
        || lower.starts_with("ec2-")
        || lower.contains(".cloudfront.net")
        || lower.contains(".bc.googleusercontent.com")
        || lower.contains("in-addr.arpa")
    {
        return true;
    }
    // Fallback: all IPv4 octets present in the name.
    match ip {
        IpAddr::V4(v4) => {
            let octets: Vec<String> = v4.octets().iter().map(ToString::to_string).collect();
            octets.iter().all(|o| lower.contains(o.as_str()))
        }
        IpAddr::V6(_) => false,
    }
}

/// Format a process name for display.
///
/// Uses code signing identity only when the lsof process name is garbage
/// (version numbers like "2.1.92", or very short dotted strings). Otherwise
/// prefers the more readable lsof/service name.
pub fn display_process(entry: &NetEntry) -> String {
    let base_name = entry.service.as_deref().unwrap_or(entry.process.as_str());

    // If the base name looks like a version number or is very short and dotted,
    // try the code signing identity instead.
    let is_garbage_name = base_name.contains('.')
        && base_name.len() < 8
        && base_name.chars().all(|c| c.is_ascii_digit() || c == '.');

    if let Some(ref code_id) = entry.code_id
        && is_garbage_name
    {
        return format_code_id(code_id);
    }

    base_name.to_owned()
}

/// Format the remote endpoint for display.
///
/// Prefers resolved hostname, falls back to IP:port, then raw connection.
pub fn display_remote(entry: &NetEntry) -> String {
    if let Some(ref host) = entry.remote_host {
        return host.clone();
    }
    if let Some(ref ip) = entry.remote_ip {
        if let Some(port) = entry.remote_port {
            return format!("{ip}:{port}");
        }
        return ip.clone();
    }
    entry.connection.clone()
}

#[cfg(test)]
#[path = "network_enrich_test.rs"]
mod network_enrich_test;
