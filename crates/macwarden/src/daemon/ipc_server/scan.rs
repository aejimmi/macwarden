//! The real [`ConnectionScanner`]: `nettop` via the shared [`netsample`] crate.
//!
//! This is the impure boundary the pure [`super::snapshot::build_snapshot`]
//! sits behind. [`NettopScanner`] samples `nettop` — the same source the panel's
//! live view uses — so a daemon-backed panel sees the same rich per-process,
//! per-connection set rather than the far sparser `lsof` view an earlier scanner
//! produced. It normalizes each connection into a neutral [`LiveConn`] and
//! reuses the `net` command's code-signing and local-noise helpers. On non-macOS
//! it yields an empty set so the crate still builds and tests on Linux CI.
//!
//! # Session accumulation
//!
//! A single `nettop` sample of a quiet machine reports only the handful of
//! processes holding an open socket at that instant. The panel reaches its rich
//! (tens of apps) list by *accumulating* every app and destination seen across
//! its session — its Session scope keeps idle-but-seen rows at rate 0. The
//! daemon snapshot carries no live rates (all bps are 0), so it is inherently a
//! totals view; to match the panel the scanner retains the union of every
//! [`LiveConn`] seen during the daemon's lifetime, bounded by [`MAX_RETAINED`].

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(any(target_os = "macos", test))]
use netsample::ProcNet;

use super::error::{Result, ServerError};
use super::proc_sample::{ProcSampler, ProcStat};
use super::rate::RateTracker;
use super::rdns_cache::RdnsResolver;
use super::snapshot::{ConnectionScanner, LiveConn};

/// Upper bound on retained destinations, guarding against unbounded growth over
/// long daemon uptimes. Far above a typical machine's distinct-destination count.
const MAX_RETAINED: usize = 4096;

/// Dedup identity for a retained connection: app, destination host, port, proto.
type ConnKey = (String, String, u16, String);

/// A pid's resolved `(code_id, exe_path, is_apple_signed, team_id)` — cached
/// because the code-signing lookup is the scan's dominant cost (~hundreds of ms
/// per pid via `Security.framework`), while a running pid's signature never
/// changes. `team_id` is carried so the detail path can build the wire signature
/// from the cached sample without its own per-request code-signing check (R6).
type PidIdentity = (Option<String>, Option<String>, Option<bool>, Option<String>);

/// Retained cross-sample session state (see the module-level note).
#[derive(Debug, Default)]
struct Session {
    seen: HashMap<ConnKey, LiveConn>,
    /// pid → resolved identity, so a slow code-signing lookup runs once per pid
    /// for the daemon's lifetime rather than on every snapshot. Without this the
    /// scan blows past the panel worker's read timeout and no snapshot lands.
    identity: HashMap<u32, PidIdentity>,
    /// Per-connection cumulative-byte baselines, turning `nettop`'s totals into
    /// live per-tick rates. Keyed identically to `seen`.
    rates: RateTracker<ConnKey>,
}

/// Collects live connections via `nettop` (the shared [`netsample`] sampler),
/// accumulating the session union so the served snapshot stays rich.
///
/// This is the daemon's default scanner: `nettop -x` reports every process with
/// active sockets and their remote endpoints, matching the panel's own live
/// source, and the retained union matches the panel's Session view.
#[derive(Debug, Clone, Default)]
pub struct NettopScanner {
    session: Arc<Mutex<Session>>,
    /// Background reverse-DNS cache. Each fresh sample reads it (non-blocking)
    /// to stamp `LiveConn.host`; misses resolve off-thread and appear on a later
    /// tick, so destination names fill in progressively without ever blocking
    /// the snapshot's request hot path.
    rdns: RdnsResolver,
    /// Persistent per-process CPU/MEM sampler. One `sysinfo::System` lives for
    /// the daemon's lifetime so CPU deltas accumulate across snapshots (nettop
    /// carries bytes but no CPU/MEM); its stats stamp every retained `LiveConn`.
    sampler: Arc<ProcSampler>,
}

impl NettopScanner {
    /// Build a scanner with an empty session. One instance lives for the
    /// daemon's lifetime so accumulation persists across `get_snapshot` calls.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl ConnectionScanner for NettopScanner {
    fn scan(&self) -> Result<Vec<LiveConn>> {
        // Sample CPU/MEM before taking the session lock — the sysinfo refresh is
        // self-contained and must not hold the connection lock.
        let stats = self.sampler.sample();
        let mut session = self
            .session
            .lock()
            .map_err(|_| ServerError::Scan("session lock poisoned".to_owned()))?;
        let fresh = sample_live_conns(&mut session.identity, &self.rdns)?;
        Ok(accumulate(&mut session, fresh, &stats))
    }
}

/// Merge a fresh sample into the retained set and return the full union.
///
/// Pure over its inputs (no syscalls) so it is unit-testable on any target.
/// Existing keys refresh to the latest identity/counters; new keys are admitted
/// until [`MAX_RETAINED`] is reached, after which only refreshes are applied.
///
/// After merging, every retained connection is re-stamped with the latest
/// per-pid CPU/MEM from `stats`, so a still-alive but idle-socket process keeps
/// live resource numbers and a departed pid (absent from `stats`) falls back to
/// zero rather than showing stale figures.
///
/// Live byte-rates are derived from the **fresh** sample's cumulative counters
/// (via [`RateTracker`]) before the merge, then stamped onto every retained
/// connection: a connection absent from this sample re-stamps to rate 0 rather
/// than showing a stale rate.
fn accumulate(
    session: &mut Session,
    fresh: Vec<LiveConn>,
    stats: &HashMap<u32, ProcStat>,
) -> Vec<LiveConn> {
    let samples: Vec<(ConnKey, u64, u64)> = fresh
        .iter()
        .map(|c| (conn_key(c), c.conn_bytes_in, c.conn_bytes_out))
        .collect();
    let rates = session.rates.observe(&samples, Instant::now());

    for conn in fresh {
        let key = conn_key(&conn);
        if session.seen.contains_key(&key) || session.seen.len() < MAX_RETAINED {
            session.seen.insert(key, conn);
        }
    }
    for conn in session.seen.values_mut() {
        // `stats_known` flags whether CPU/memory were readable (root-owned /
        // hardened processes report unreadable → the panel renders "—"). The uid,
        // and thus the username, resolves for every process regardless, so the
        // owner is threaded through even when the stats are unknown. A pid absent
        // from `stats` (exited between samples) is fully unknown.
        if let Some(stat) = stats.get(&conn.pid) {
            conn.cpu = stat.cpu;
            conn.mem_bytes = stat.mem_bytes;
            conn.stats_known = stat.stats_known;
            // Keep the last resolved owner even if a later sample can't read it.
            if stat.user.is_some() {
                conn.user = stat.user.clone();
            }
        } else {
            conn.cpu = 0.0;
            conn.mem_bytes = 0;
            conn.stats_known = false;
        }
        let (in_bps, out_bps) = rates.get(&conn_key(conn)).copied().unwrap_or((0, 0));
        conn.rate_in_bps = in_bps;
        conn.rate_out_bps = out_bps;
    }
    session.seen.values().cloned().collect()
}

/// The retained-connection dedup key, at the panel's per-destination granularity.
///
/// Keyed by the destination **IP** when known (else the display host) so a
/// connection keeps one stable key across the tick where its hostname resolves:
/// the retained row is *refreshed* with the resolved `host` rather than split
/// into a second IP-keyed row.
fn conn_key(conn: &LiveConn) -> ConnKey {
    let dest = conn
        .ip
        .map_or_else(|| conn.display_host(), |ip| ip.to_string());
    (conn.app_id(), dest, conn.port, conn.protocol.clone())
}

#[cfg(target_os = "macos")]
fn sample_live_conns(
    identity: &mut HashMap<u32, PidIdentity>,
    rdns: &RdnsResolver,
) -> Result<Vec<LiveConn>> {
    let procs = netsample::sample().map_err(|e| ServerError::Scan(e.to_string()))?;
    let mut out = Vec::new();
    for proc in &procs {
        if proc.conns.is_empty() {
            continue;
        }
        // Resolve identity once per pid and cache it — the code-signing lookup
        // is the scan's dominant cost, so reuse it across snapshots. The cache
        // is bounded so heavy process churn cannot grow it without limit.
        let (code_id, path, apple, team_id) = if let Some(cached) = identity.get(&proc.pid) {
            cached.clone()
        } else {
            let resolved = resolve_identity(proc.pid);
            if identity.len() < MAX_RETAINED {
                identity.insert(proc.pid, resolved.clone());
            }
            resolved
        };
        out.extend(map_proc(
            proc,
            code_id.as_deref(),
            path.as_deref(),
            apple,
            team_id.as_deref(),
            rdns,
        ));
    }
    Ok(out)
}

/// Resolve a pid's `(code_id, path, is_apple_signed, team_id)` via procmon's
/// code-signing lookup in one pass (R4). `team_id` is kept so the detail path can
/// build the wire signature from the cached sample without re-checking (R6).
#[cfg(target_os = "macos")]
fn resolve_identity(pid: u32) -> PidIdentity {
    let Some(path) = proc_pidpath(pid) else {
        return (None, None, None, None);
    };
    match procmon::code_signing::get_code_signing_info(pid, std::path::Path::new(&path)) {
        Ok(info) => (
            info.code_id,
            Some(path),
            Some(info.is_apple_signed),
            info.team_id,
        ),
        Err(_) => (None, Some(path), None, None),
    }
}

#[cfg(not(target_os = "macos"))]
fn sample_live_conns(
    _identity: &mut HashMap<u32, PidIdentity>,
    _rdns: &RdnsResolver,
) -> Result<Vec<LiveConn>> {
    Ok(Vec::new())
}

/// Map one nettop process's connections into daemon [`LiveConn`] rows.
///
/// The per-pid attribution (`code_id`, `path`) is resolved by the caller and
/// threaded through. Each destination IP is looked up in the background rDNS
/// cache — a **non-blocking** read that stamps `host` on a cache hit and
/// enqueues a miss for off-thread resolution, so names fill in on later ticks.
/// Local noise (loopback, link-local, multicast) is dropped; process-level byte
/// counters are stamped on every connection per the [`LiveConn`] contract.
#[cfg(any(target_os = "macos", test))]
fn map_proc(
    proc: &ProcNet,
    code_id: Option<&str>,
    path: Option<&str>,
    is_apple_signed: Option<bool>,
    team_id: Option<&str>,
    rdns: &RdnsResolver,
) -> Vec<LiveConn> {
    use std::net::IpAddr;

    use crate::commands::net::net_scan::is_local_noise;

    proc.conns
        .iter()
        .filter(|conn| !is_local_noise(&conn.remote_ip))
        .map(|conn| {
            let protocol = if conn.proto.starts_with("udp") {
                "UDP"
            } else {
                "TCP"
            };
            let ip = conn.remote_ip.parse::<IpAddr>().ok();
            let host = ip.and_then(|ip| rdns.resolve(ip));
            LiveConn {
                code_id: code_id.map(str::to_owned),
                process: proc.name.clone(),
                pid: proc.pid,
                path: path.map(str::to_owned),
                host,
                ip,
                port: conn.remote_port,
                protocol: protocol.to_owned(),
                bytes_in: proc.bytes_in,
                bytes_out: proc.bytes_out,
                is_apple_signed,
                team_id: team_id.map(str::to_owned),
                // Per-connection cumulative counters feed the live rate delta;
                // the process-level totals above stay the Session view.
                conn_bytes_in: conn.bytes_in,
                conn_bytes_out: conn.bytes_out,
                // Stamped from the sysinfo sampler and the rate tracker in
                // `accumulate`; nettop carries no CPU/MEM and a single sample
                // has no rate, so these start zeroed here.
                cpu: 0.0,
                mem_bytes: 0,
                // Resolved in `accumulate` from the sampler; unknown until then.
                stats_known: false,
                user: None,
                rate_in_bps: 0,
                rate_out_bps: 0,
            }
        })
        .collect()
}

/// Resolve a pid's executable path via `proc_pidpath`.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn proc_pidpath(pid: u32) -> Option<String> {
    let mut buf = vec![0u8; 4096];
    // SAFETY: `buf` is a valid, writable buffer of `buf.len()` bytes;
    // `proc_pidpath` writes at most that many bytes and returns the length
    // written (<= 0 on failure), which we bounds-check before slicing.
    let len = unsafe { libc::proc_pidpath(pid as i32, buf.as_mut_ptr().cast(), buf.len() as u32) };
    if len <= 0 {
        return None;
    }
    let bytes = buf.get(..len as usize)?;
    std::str::from_utf8(bytes).ok().map(ToOwned::to_owned)
}

#[cfg(test)]
#[path = "scan_test.rs"]
mod scan_test;
