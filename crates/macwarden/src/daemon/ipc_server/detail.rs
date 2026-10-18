//! Inspector detail (R6): process identity, live hosts, and openbinary passthrough.
//!
//! Detail fuses the current live-connection set (filtered to the requested app /
//! process / host) with the code-signing `Signature` from procmon and an
//! openbinary line pulled from the **inventory cache only** — the daemon never
//! uploads on a detail request (privacy + latency); live upload stays a CLI
//! action. An unknown id/host returns `None`, mirroring the panel trait's
//! `Option<Detail>`.
//!
//! [`assemble_detail`] is the pure core (a set of connections + a precomputed
//! signature/openbinary line → a `WireDetail`); the resolvers wrap it with the
//! impure scan + procmon + inventory lookups.

use std::collections::{BTreeMap, BTreeSet};

use ipc::protocol::{WireDetail, WireSignature};
use net::RuleSet;

use super::snapshot::LiveConn;
use super::state::ServerState;

/// Maximum hostnames/IPs/ports listed in a detail (already truncated by daemon).
const MAX_DETAIL_ITEMS: usize = 12;

/// Detail for an app by id (code id, process name, or executable path) (R6).
///
/// Reads the background sampler's cached connection set — never scans inline —
/// so it answers in milliseconds regardless of scan cost.
pub fn app_detail(state: &ServerState, id: &str) -> Option<WireDetail> {
    let conns = state.latest_conns();
    let matched: Vec<&LiveConn> = conns
        .iter()
        .filter(|c| c.app_id() == id || c.process == id || c.path.as_deref() == Some(id))
        .collect();
    build(state, id, &matched)
}

/// Detail for a process by id (its pid rendered as a string) (R6). Reads the
/// cached sample, never scans inline.
pub fn proc_detail(state: &ServerState, id: &str) -> Option<WireDetail> {
    let conns = state.latest_conns();
    let matched: Vec<&LiveConn> = conns.iter().filter(|c| c.pid.to_string() == id).collect();
    build(state, id, &matched)
}

/// Detail for a destination by hostname (R6). Reads the cached sample, never
/// scans inline.
pub fn domain_detail(state: &ServerState, host: &str) -> Option<WireDetail> {
    let conns = state.latest_conns();
    let matched: Vec<&LiveConn> = conns
        .iter()
        .filter(|c| c.display_host() == host || c.host.as_deref() == Some(host))
        .collect();
    build(state, host, &matched)
}

/// Resolve signature + openbinary for the matched set and assemble the detail.
fn build(state: &ServerState, key: &str, matched: &[&LiveConn]) -> Option<WireDetail> {
    let first = matched.first()?;
    let signature = signature_from_conn(first);
    let openbinary = openbinary_line(state, first.path.as_deref());
    let ruleset = state.ruleset();
    let apple_allow = crate::commands::net::policy_apple_allow();
    Some(assemble_detail(
        key,
        matched,
        &ruleset,
        signature,
        openbinary,
        apple_allow,
    ))
}

/// Pure assembly of a [`WireDetail`] from matched connections plus a resolved
/// signature and openbinary line (R6). Unit-testable without procmon/inventory.
#[must_use]
pub fn assemble_detail(
    key: &str,
    matched: &[&LiveConn],
    ruleset: &RuleSet,
    signature: WireSignature,
    openbinary: String,
    apple_allow: bool,
) -> WireDetail {
    let first = matched.first();
    let name = first.map_or_else(|| key.to_owned(), |c| detail_name(c));
    let bundle_id = first
        .and_then(|c| c.code_id.clone())
        .unwrap_or_else(|| key.to_owned());
    let path = first.and_then(|c| c.path.clone()).unwrap_or_default();
    let bundle_path = super::bundle::bundle_path(first.and_then(|c| c.path.as_deref()));

    let mut in_bytes = 0u64;
    let mut out_bytes = 0u64;
    let mut seen_pids = BTreeSet::new();
    // Counted (not just deduped) so the detail can show per-destination
    // multiplicity (`1.2.3.4 ×2`), reconciling the deduped lists with the
    // per-connection allowed/denied tally below.
    let mut hostnames: BTreeMap<String, u32> = BTreeMap::new();
    let mut ips: BTreeMap<String, u32> = BTreeMap::new();
    let mut ports: BTreeMap<String, u32> = BTreeMap::new();
    let mut allowed_count = 0u32;
    let mut denied_count = 0u32;

    for conn in matched {
        if seen_pids.insert(conn.pid) {
            in_bytes = in_bytes.saturating_add(conn.bytes_in);
            out_bytes = out_bytes.saturating_add(conn.bytes_out);
        }
        if let Some(host) = &conn.host {
            *hostnames.entry(host.clone()).or_default() += 1;
        }
        if let Some(ip) = conn.ip {
            *ips.entry(ip.to_string()).or_default() += 1;
        }
        if conn.port != 0 {
            *ports
                .entry(format!("{}/{}", conn.port, conn.protocol.to_lowercase()))
                .or_default() += 1;
        }
        let (_, allowed) = conn.evaluate(ruleset, apple_allow);
        if allowed {
            allowed_count += 1;
        } else {
            denied_count += 1;
        }
    }

    WireDetail {
        name,
        bundle_id,
        bundle_path,
        in_bytes,
        out_bytes,
        path,
        user: first
            .and_then(|c| c.user.clone())
            .unwrap_or_else(|| "—".to_owned()),
        signature,
        openbinary,
        hostnames: tally(hostnames),
        ips: tally(ips),
        ports: tally(ports),
        allowed_count,
        denied_count,
        allowed: denied_count == 0 || allowed_count > 0,
    }
}

/// Format a counted, sorted destination map into a bounded `Vec`, appending a
/// `×N` multiplier when a value was seen on more than one connection — so the
/// deduped list visibly reconciles with the per-connection allowed/denied tally.
fn tally(map: BTreeMap<String, u32>) -> Vec<String> {
    map.into_iter()
        .take(MAX_DETAIL_ITEMS)
        .map(|(value, count)| {
            if count > 1 {
                format!("{value} \u{d7}{count}")
            } else {
                value
            }
        })
        .collect()
}

/// Inspector header name: the enclosing `.app` name for a bundle's primary
/// executable, else the connection's own display name.
fn detail_name(conn: &LiveConn) -> String {
    let base = display_name(conn);
    match conn.path.as_deref() {
        Some(path) => super::bundle::app_display_name(path, &base),
        None => base,
    }
}

/// Friendly display name for a connection (trimmed code id, else process).
fn display_name(conn: &LiveConn) -> String {
    conn.code_id.as_deref().map_or_else(
        || conn.process.clone(),
        crate::commands::net::net_scan::format_code_id,
    )
}

/// Openbinary line from the **inventory cache only** — never uploads (R6).
///
/// If the inventory store holds an analyzed record for this binary path, its
/// title/summary pass through; otherwise the line is `"not yet analyzed"`. Uses
/// the store's keyed [`inventory::InventoryStore::get`] so a large inventory
/// doesn't cost a full clone per detail request.
fn openbinary_line(state: &ServerState, path: Option<&str>) -> String {
    const UNANALYZED: &str = "not yet analyzed";
    let (Some(path), Some(store)) = (path, state.inventory()) else {
        return UNANALYZED.to_owned();
    };
    let Some(record) = store.get(path) else {
        return UNANALYZED.to_owned();
    };
    let Some(analysis) = record.openbinary else {
        return UNANALYZED.to_owned();
    };
    openbinary_summary(&analysis).unwrap_or_else(|| UNANALYZED.to_owned())
}

/// Build the wire signature from a cached connection's already-resolved
/// code-signing facts — no per-request `procmon` check (R6). The background
/// sampler resolves `is_apple_signed`/`team_id` once per pid, so this is pure and
/// fast on every detail request.
fn signature_from_conn(conn: &LiveConn) -> WireSignature {
    signature_from_info(conn.is_apple_signed.unwrap_or(false), conn.team_id.clone())
}

/// Fold an openbinary analysis JSON into a one-line title/summary (R6).
#[must_use]
pub fn openbinary_summary(analysis: &serde_json::Value) -> Option<String> {
    let title = analysis.get("title").and_then(serde_json::Value::as_str);
    let summary = analysis.get("summary").and_then(serde_json::Value::as_str);
    match (title, summary) {
        (Some(t), Some(s)) => Some(format!("{t} — {s}")),
        (Some(t), None) => Some(t.to_owned()),
        (None, Some(s)) => Some(s.to_owned()),
        (None, None) => None,
    }
}

/// Map code-signing facts to the wire signature (R6).
#[must_use]
pub fn signature_from_info(is_apple_signed: bool, team_id: Option<String>) -> WireSignature {
    if is_apple_signed {
        WireSignature::Apple
    } else if let Some(team) = team_id {
        WireSignature::DevId(team)
    } else {
        WireSignature::Unsigned
    }
}

#[cfg(test)]
#[path = "detail_test.rs"]
mod detail_test;
