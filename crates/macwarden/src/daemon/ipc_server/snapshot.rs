//! Live snapshot fusion (R4): live connections + per-destination verdicts.
//!
//! [`build_snapshot`] is a **pure function** over an injected slice of
//! [`LiveConn`] and a borrowed [`net::RuleSet`]. It computes each destination's
//! [`WireVerdict`] via [`net::RuleSet::decide_for`] — this is what makes the
//! panel's dots reflect real policy rather than the `LiveSource`'s hardcoded
//! `Allow`. Because it takes its inputs by reference and produces plain wire
//! DTOs, it is unit-testable without a socket, root, or `lsof`.
//!
//! A [`ConnectionScanner`] is the injectable seam that produces the live
//! connections; the real `nettop`-backed implementation lives in
//! [`super::scan`], while tests feed synthetic [`LiveConn`] values directly.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use ipc::protocol::{
    WireAppRow, WireDomainRow, WireFlow, WireNetRow, WireProcGroup, WireProcRow, WireTotals,
    WireVerdict,
};
use net::{
    AddressFamily, Destination, MatchTier, NetworkAction, NetworkDecision, ProcessIdentity,
    Protocol, RuleSet,
};

use super::error::Result;
use super::policy_shim::decide_with_policy;

/// Maximum destinations retained per app row (most-connected first).
const MAX_DOMAINS_PER_APP: usize = 12;

/// One live outbound connection, normalized from whatever backend produced it.
///
/// This is the daemon's neutral intermediate: the pure builder consumes it and
/// the impure [`ConnectionScanner`] produces it, so neither the builder nor its
/// tests depend on `lsof` or procmon.
#[derive(Debug, Clone, Default)]
pub struct LiveConn {
    /// Code-signing identity of the responsible process, if resolved.
    pub code_id: Option<String>,
    /// Process short name (from the connection backend).
    pub process: String,
    /// Process id.
    pub pid: u32,
    /// Executable path, if resolved.
    pub path: Option<String>,
    /// Resolved destination hostname, if known.
    pub host: Option<String>,
    /// Destination IP, if parseable.
    pub ip: Option<IpAddr>,
    /// Destination port (0 when unknown).
    pub port: u16,
    /// `"TCP"` or `"UDP"`.
    pub protocol: String,
    /// Process-level bytes received (best-effort; same for every conn of a pid).
    pub bytes_in: u64,
    /// Process-level bytes sent (best-effort).
    pub bytes_out: u64,
    /// This connection's own cumulative bytes received (from `nettop`). Feeds the
    /// per-tick rate delta; distinct from the process-level `bytes_in`.
    pub conn_bytes_in: u64,
    /// This connection's own cumulative bytes sent (from `nettop`).
    pub conn_bytes_out: u64,
    /// Live receive rate for this connection in bytes/sec, stamped by the scanner
    /// from the cross-sample delta. Zero for an idle or newly seen connection.
    pub rate_in_bps: u64,
    /// Live send rate for this connection in bytes/sec.
    pub rate_out_bps: u64,
    /// Whether the responsible process is Apple-signed, if resolved. Feeds the
    /// "Allow Apple Programs" decide-time shim (R4).
    pub is_apple_signed: Option<bool>,
    /// The responsible process's code-signing team id, if resolved (a Developer
    /// ID signature). Resolved once by the sampler alongside `is_apple_signed`, so
    /// the detail path builds the wire signature from the cached sample without a
    /// fresh per-request `procmon` code-signing check (R6).
    pub team_id: Option<String>,
    /// Process CPU usage percent from `sysinfo` (same for every conn of a pid).
    /// Meaningful only when [`Self::stats_known`] is `true`.
    pub cpu: f32,
    /// Process resident memory in bytes from `sysinfo` (same for every conn).
    /// Meaningful only when [`Self::stats_known`] is `true`.
    pub mem_bytes: u64,
    /// Whether CPU/memory were actually readable for this pid (R6/B). `false`
    /// when the unprivileged daemon could not read the process's task info
    /// (root-owned / hardened-runtime / already-exited pid) — the panel then
    /// renders "—" instead of a fabricated `0`. Defaults to `false`.
    pub stats_known: bool,
    /// Owning username, resolved at sample time from the process uid (R6).
    /// `None` when unresolvable (process gone / uid absent), rendered as "—".
    pub user: Option<String>,
}

impl LiveConn {
    /// Stable app grouping key: the code id, else the process name.
    #[must_use]
    pub fn app_id(&self) -> String {
        self.code_id.clone().unwrap_or_else(|| self.process.clone())
    }

    /// Evaluate this connection against a rule set, applying the Apple-programs
    /// floor when `apple_allow` is set (R4/R6 detail counts).
    #[must_use]
    pub fn evaluate(&self, ruleset: &RuleSet, apple_allow: bool) -> (WireVerdict, bool) {
        let (process, destination) = self.decision_inputs();
        verdict_of(&decide_with_policy(
            ruleset,
            &process,
            None,
            &destination,
            apple_allow,
        ))
    }

    /// The display host for a destination row: hostname, else IP, else `process`.
    #[must_use]
    pub fn display_host(&self) -> String {
        if let Some(host) = &self.host {
            return host.clone();
        }
        self.ip
            .map_or_else(|| self.process.clone(), |ip| ip.to_string())
    }

    /// Build the `net` decision inputs for this connection.
    fn decision_inputs(&self) -> (ProcessIdentity, Destination) {
        let ip = self.ip.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        let process = ProcessIdentity {
            pid: self.pid,
            uid: 0,
            path: PathBuf::from(self.path.clone().unwrap_or_else(|| self.process.clone())),
            code_id: self.code_id.clone(),
            team_id: None,
            is_valid_signature: None,
            is_apple_signed: self.is_apple_signed,
        };
        let protocol = if self.protocol.eq_ignore_ascii_case("UDP") {
            Some(Protocol::Udp)
        } else {
            Some(Protocol::Tcp)
        };
        let destination = Destination {
            host: self.host.clone(),
            ip,
            port: if self.port == 0 {
                None
            } else {
                Some(self.port)
            },
            protocol,
            address_family: if ip.is_ipv6() {
                AddressFamily::Inet6
            } else {
                AddressFamily::Inet
            },
        };
        (process, destination)
    }
}

/// The injectable seam that produces the daemon's live connection view (R4).
///
/// The real implementation samples `nettop` and enriches via procmon; tests
/// inject a stub that returns fixed [`LiveConn`] values, so the builder and
/// handlers exercise without a socket or macOS APIs.
pub trait ConnectionScanner: Send + Sync {
    /// Collect the current set of live outbound connections.
    fn scan(&self) -> Result<Vec<LiveConn>>;
}

/// The fused snapshot payload, before the ruleset `generation` is stamped on.
#[derive(Debug, Clone, PartialEq)]
pub struct SnapshotData {
    /// Apps-tab rows.
    pub apps: Vec<WireAppRow>,
    /// Network-tab flat destination rows.
    pub net_rows: Vec<WireNetRow>,
    /// Processes-tab rows.
    pub procs: Vec<WireProcRow>,
    /// Processes-tab rows grouped by responsible app.
    pub proc_groups: Vec<WireProcGroup>,
    /// Footer totals.
    pub totals: WireTotals,
}

/// Map a `net` decision to the wire verdict + allowed flag (R4).
///
/// A tracker-tier denial serializes as [`WireVerdict::Tracker`], any other
/// denial as [`WireVerdict::Blocked`], and everything else as
/// [`WireVerdict::Allow`].
#[must_use]
pub fn verdict_of(decision: &NetworkDecision) -> (WireVerdict, bool) {
    match decision.action {
        NetworkAction::Deny => {
            let is_tracker = matches!(
                decision.matched_rule.as_ref().map(|m| &m.tier),
                Some(MatchTier::Tracker { .. })
            );
            let verdict = if is_tracker {
                WireVerdict::Tracker
            } else {
                WireVerdict::Blocked
            };
            (verdict, false)
        }
        NetworkAction::Allow | NetworkAction::Log => (WireVerdict::Allow, true),
    }
}

/// Fuse live connections and rule-set verdicts into the wire snapshot (R4).
///
/// `apple_allow` threads the "Allow Apple Programs" policy flag into the
/// decide-time shim so Block-All verdicts reflect the Apple carve-out (R4).
#[must_use]
pub fn build_snapshot(conns: &[LiveConn], ruleset: &RuleSet, apple_allow: bool) -> SnapshotData {
    let mut apps: BTreeMap<String, AppAccum> = BTreeMap::new();
    let mut procs: BTreeMap<u32, ProcAccum> = BTreeMap::new();
    let mut trackers_blocked: u64 = 0;
    let mut down_bps: u64 = 0;
    let mut up_bps: u64 = 0;

    for conn in conns {
        let (process, destination) = conn.decision_inputs();
        let decision = decide_with_policy(ruleset, &process, None, &destination, apple_allow);
        let (verdict, allowed) = verdict_of(&decision);
        if verdict == WireVerdict::Tracker {
            trackers_blocked += 1;
        }
        down_bps = down_bps.saturating_add(conn.rate_in_bps);
        up_bps = up_bps.saturating_add(conn.rate_out_bps);

        apps.entry(conn.app_id())
            .or_insert_with(|| AppAccum::new(conn))
            .add_conn(conn, verdict, allowed);

        procs
            .entry(conn.pid)
            .or_insert_with(|| ProcAccum::new(conn))
            .add_conn(conn);
    }

    let app_rows: Vec<WireAppRow> = apps.into_values().map(AppAccum::finish).collect();
    let net_rows = build_net_rows(&app_rows);
    let (proc_rows, proc_groups) = build_procs(procs.into_values().collect());
    let totals = totals(
        &app_rows,
        conns.len() as u64,
        trackers_blocked,
        down_bps,
        up_bps,
    );

    SnapshotData {
        apps: app_rows,
        net_rows,
        procs: proc_rows,
        proc_groups,
        totals,
    }
}

/// Flatten app destinations into the Network-tab rows.
fn build_net_rows(apps: &[WireAppRow]) -> Vec<WireNetRow> {
    apps.iter()
        .flat_map(|app| {
            app.domains.iter().map(move |domain| WireNetRow {
                app_name: app.name.clone(),
                app_path: app.bundle_path.clone(),
                domain: domain.clone(),
            })
        })
        .collect()
}

/// Build the flat process rows and their responsible-app groups.
fn build_procs(accums: Vec<ProcAccum>) -> (Vec<WireProcRow>, Vec<WireProcGroup>) {
    let mut groups: BTreeMap<String, WireProcGroup> = BTreeMap::new();
    let mut rows = Vec::with_capacity(accums.len());
    for acc in accums {
        let row = WireProcRow {
            id: acc.pid.to_string(),
            name: acc.name.clone(),
            bundle_path: super::bundle::bundle_path(acc.path.as_deref()),
            cpu: acc.cpu,
            mem_bytes: acc.mem_bytes,
            net_bps: acc.net_bps,
            net_bytes: acc.bytes,
            is_system: acc.is_system(),
            stats_known: acc.stats_known,
        };
        let group = groups
            .entry(acc.app_id.clone())
            .or_insert_with(|| WireProcGroup {
                id: acc.app_id.clone(),
                name: acc.name.clone(),
                bundle_path: row.bundle_path.clone(),
                cpu: 0.0,
                mem_bytes: 0,
                net_bps: 0,
                net_bytes: 0,
                procs: Vec::new(),
                stats_known: false,
            });
        group.cpu += row.cpu;
        group.mem_bytes = group.mem_bytes.saturating_add(row.mem_bytes);
        group.net_bps = group.net_bps.saturating_add(acc.net_bps);
        group.net_bytes = group.net_bytes.saturating_add(acc.bytes);
        // A group's stats are known if any member's are (the sum then reflects the
        // readable members); a group of only-unreadable members stays "unknown".
        group.stats_known |= row.stats_known;
        group.procs.push(row.clone());
        rows.push(row);
    }
    (rows, groups.into_values().collect())
}

/// Compute the footer totals. Live aggregate rates come from the per-connection
/// deltas summed by the caller; the byte totals stay the Session accumulation.
fn totals(
    apps: &[WireAppRow],
    connections: u64,
    trackers_blocked: u64,
    down_bps: u64,
    up_bps: u64,
) -> WireTotals {
    let down_bytes = apps.iter().map(|a| a.down_bytes).sum();
    let up_bytes = apps.iter().map(|a| a.up_bytes).sum();
    WireTotals {
        down_bytes,
        up_bytes,
        trackers_blocked,
        connections,
        down_bps,
        up_bps,
    }
}

/// Per-app accumulator folded across the connection stream.
struct AppAccum {
    id: String,
    name: String,
    path: Option<String>,
    is_apple_signed: Option<bool>,
    down_bps: u64,
    up_bps: u64,
    pid_bytes: BTreeMap<u32, (u64, u64)>,
    domains: BTreeMap<String, WireDomainRow>,
}

impl AppAccum {
    fn new(conn: &LiveConn) -> Self {
        Self {
            id: conn.app_id(),
            name: display_name(conn),
            path: conn.path.clone(),
            is_apple_signed: conn.is_apple_signed,
            down_bps: 0,
            up_bps: 0,
            pid_bytes: BTreeMap::new(),
            domains: BTreeMap::new(),
        }
    }

    fn add_conn(&mut self, conn: &LiveConn, verdict: WireVerdict, allowed: bool) {
        self.pid_bytes
            .insert(conn.pid, (conn.bytes_in, conn.bytes_out));
        self.down_bps = self.down_bps.saturating_add(conn.rate_in_bps);
        self.up_bps = self.up_bps.saturating_add(conn.rate_out_bps);
        let rate = conn.rate_in_bps.saturating_add(conn.rate_out_bps);
        let host = conn.display_host();
        self.domains
            .entry(host.clone())
            .and_modify(|d| {
                d.sockets = d.sockets.saturating_add(1);
                d.rate_bps = d.rate_bps.saturating_add(rate);
                d.verdict = verdict;
                d.allowed = allowed;
            })
            .or_insert(WireDomainRow {
                host,
                country: None,
                verdict,
                rate_bps: rate,
                total_bytes: 0,
                sockets: 1,
                allowed,
            });
    }

    fn finish(self) -> WireAppRow {
        let down_bytes: u64 = self.pid_bytes.values().map(|(d, _)| *d).sum();
        let up_bytes: u64 = self.pid_bytes.values().map(|(_, u)| *u).sum();
        let is_system = is_system_binary(self.is_apple_signed, self.path.as_deref());
        let mut domains: Vec<WireDomainRow> = self.domains.into_values().collect();
        domains.sort_by(|a, b| b.sockets.cmp(&a.sockets).then_with(|| a.host.cmp(&b.host)));
        domains.truncate(MAX_DOMAINS_PER_APP);
        let allowed = domains.is_empty() || domains.iter().any(|d| d.allowed);
        let flow = app_flow(self.down_bps, self.up_bps, down_bytes, up_bytes);
        WireAppRow {
            id: self.id,
            name: self.name,
            bundle_path: super::bundle::bundle_path(self.path.as_deref()),
            allowed,
            known_bad: false,
            down_bytes,
            up_bytes,
            flow,
            is_system,
            domains,
        }
    }
}

/// Pick the app's flow: a live rate when traffic is moving, else the retained
/// session buffer, else idle. Live rate takes precedence so the panel's "Live"
/// scope shows real throughput while "Session" reads the accumulated bytes.
fn app_flow(down_bps: u64, up_bps: u64, down_bytes: u64, up_bytes: u64) -> WireFlow {
    let rate = down_bps.saturating_add(up_bps);
    if rate > 0 {
        return WireFlow::Active(rate);
    }
    let total = down_bytes.saturating_add(up_bytes);
    if total > 0 {
        WireFlow::Session(total)
    } else {
        WireFlow::Idle
    }
}

/// System prefixes an Apple-signed binary must live under to count as a macOS
/// **system** binary. Third-party Apple-signed apps under `/Applications` are
/// deliberately excluded.
const SYSTEM_PREFIXES: [&str; 5] = [
    "/System/",
    "/usr/libexec/",
    "/usr/sbin/",
    "/usr/bin/",
    "/Library/Apple/",
];

/// Whether a binary is an Apple-signed macOS system daemon: Apple-signed **and**
/// resident under a system prefix. Both conditions are required so an
/// Apple-signed third-party app is not mislabeled as system.
#[must_use]
fn is_system_binary(is_apple_signed: Option<bool>, path: Option<&str>) -> bool {
    if is_apple_signed != Some(true) {
        return false;
    }
    path.is_some_and(|p| SYSTEM_PREFIXES.iter().any(|prefix| p.starts_with(prefix)))
}

/// Per-pid accumulator for the Processes tab.
struct ProcAccum {
    pid: u32,
    name: String,
    path: Option<String>,
    app_id: String,
    is_apple_signed: Option<bool>,
    bytes: u64,
    net_bps: u64,
    cpu: f32,
    mem_bytes: u64,
    stats_known: bool,
}

impl ProcAccum {
    fn new(conn: &LiveConn) -> Self {
        Self {
            pid: conn.pid,
            name: display_name(conn),
            path: conn.path.clone(),
            app_id: conn.app_id(),
            is_apple_signed: conn.is_apple_signed,
            bytes: 0,
            net_bps: 0,
            cpu: conn.cpu,
            mem_bytes: conn.mem_bytes,
            stats_known: conn.stats_known,
        }
    }

    /// Fold one of the pid's connections in. Process-level bytes are identical
    /// across a pid's connections, so `bytes` is set (not summed), while the live
    /// `net_bps` sums the per-connection rate deltas across destinations.
    fn add_conn(&mut self, conn: &LiveConn) {
        self.bytes = conn.bytes_in.saturating_add(conn.bytes_out);
        self.net_bps = self
            .net_bps
            .saturating_add(conn.rate_in_bps.saturating_add(conn.rate_out_bps));
    }

    fn is_system(&self) -> bool {
        is_system_binary(self.is_apple_signed, self.path.as_deref())
    }
}

/// Friendly display name: the `.app` name for a bundle's primary executable
/// (via [`super::bundle::app_display_name`]), otherwise the trimmed code id (or
/// process), always with any ad-hoc code-signing hash suffix stripped.
fn display_name(conn: &LiveConn) -> String {
    let base = conn.code_id.as_deref().map_or_else(
        || conn.process.clone(),
        crate::commands::net::net_scan::format_code_id,
    );
    let fallback = super::bundle::strip_hash_suffix(&base);
    conn.path.as_deref().map_or_else(
        || fallback.to_owned(),
        |path| super::bundle::app_display_name(path, fallback),
    )
}

#[cfg(test)]
#[path = "snapshot_test.rs"]
mod snapshot_test;
