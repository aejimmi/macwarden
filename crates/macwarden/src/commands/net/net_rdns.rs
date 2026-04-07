//! Reverse DNS resolution for bare IP destinations.
//!
//! Collects unique IPs from scan entries, resolves them sequentially
//! (capped at [`RDNS_BATCH_CAP`]), and patches entries with the resolved
//! hostname. Also re-checks the tracker database against newly resolved
//! hostnames to catch tracker connections that were hidden behind IPs.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use tracing::debug;

use net::TrackerDatabase;

use super::net_scan::ScanEntry;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of unique IPs to resolve via reverse DNS.
const RDNS_BATCH_CAP: usize = 50;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Batch reverse DNS resolution on entries whose destination is still a bare IP.
///
/// Collects unique IPs, resolves up to [`RDNS_BATCH_CAP`] sequentially, and
/// patches matching entries with the resolved hostname. Entries that resolve
/// to a tracker domain get their `tracker` field updated.
pub(super) fn resolve_bare_ips(entries: &mut [ScanEntry], tracker_db: &TrackerDatabase) {
    let unique_ips: Vec<IpAddr> = {
        let mut seen = HashSet::new();
        entries
            .iter()
            .filter_map(|e| {
                let ip: IpAddr = e.destination.parse().ok()?;
                if seen.insert(ip) { Some(ip) } else { None }
            })
            .take(RDNS_BATCH_CAP)
            .collect()
    };

    if unique_ips.is_empty() {
        return;
    }

    debug!(
        count = unique_ips.len(),
        "resolving reverse DNS for bare IPs"
    );

    let resolved: HashMap<IpAddr, String> = unique_ips
        .iter()
        .filter_map(|&ip| {
            let name = reverse_lookup(ip)?;
            Some((ip, name))
        })
        .collect();

    // Patch entries with resolved hostnames.
    for entry in entries.iter_mut() {
        let Ok(ip) = entry.destination.parse::<IpAddr>() else {
            continue;
        };
        if let Some(hostname) = resolved.get(&ip) {
            entry.destination.clone_from(hostname);
            // Re-check tracker DB against the newly resolved hostname.
            if entry.tracker.is_none() {
                entry.tracker = tracker_db.lookup(hostname).map(|m| m.category.to_string());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

/// Perform a single reverse DNS lookup, filtering out garbage results.
///
/// Returns `None` for:
/// - Lookup failures
/// - Results that are just the IP address echoed back
/// - Results with no dots (bare hostnames like "localhost")
/// - Results that look like auto-generated rDNS (contain the IP octets)
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
    // e.g. "ec2-52-6-143-21.compute-1.amazonaws.com" for 52.6.143.21
    if is_garbage_rdns(&name, ip) {
        return None;
    }

    // Strip trailing dot if present (some resolvers return FQDN).
    let clean = name.strip_suffix('.').unwrap_or(&name);
    Some(clean.to_owned())
}

/// Heuristic: rDNS is garbage if it contains all octets of the IPv4 address.
///
/// Catches patterns like:
/// - `"ec2-52-6-143-21.compute-1.amazonaws.com"` for `52.6.143.21`
/// - `"21.143.6.52.in-addr.arpa"` reverse entries
fn is_garbage_rdns(name: &str, ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets: Vec<String> = v4.octets().iter().map(ToString::to_string).collect();
            octets.iter().all(|o| name.contains(o.as_str()))
        }
        IpAddr::V6(_) => {
            // IPv6 rDNS is almost always garbage; skip conservatively.
            false
        }
    }
}

#[cfg(test)]
#[path = "net_rdns_test.rs"]
mod net_rdns_test;
