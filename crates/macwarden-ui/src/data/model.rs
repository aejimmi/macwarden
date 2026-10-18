//! Snapshot types shared by every [`super::source::PanelSource`] implementation.
//!
//! These are plain data — no GPUI, no platform APIs — so the whole model layer
//! compiles and is unit-tested on any target, including Linux CI.

use std::path::PathBuf;

/// The verdict rendered as a 6px dot beside a destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Connection is permitted — accent-green dot.
    Allow,
    /// Connection is denied — red dot.
    Blocked,
    /// Known tracker endpoint — purple dot.
    Tracker,
}

impl Verdict {
    /// Short lowercase label used in plain text next to the dot.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Allow => "allowed",
            Verdict::Blocked => "blocked",
            Verdict::Tracker => "tracker",
        }
    }
}

/// Code-signing identity summarised for the inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// Signed by Apple.
    Apple,
    /// Signed with a Developer ID and a team identifier.
    DevId(String),
    /// No valid signature.
    Unsigned,
}

impl Signature {
    /// One-line description for the inspector signature row.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Signature::Apple => "Apple".to_string(),
            Signature::DevId(team) => format!("Developer ID · {team}"),
            Signature::Unsigned => "unsigned".to_string(),
        }
    }
}

/// A destination row nested under an app, or shown flat in the Network tab.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainRow {
    /// Hostname, e.g. `googlevideo.com`.
    pub host: String,
    /// ISO country code when known, e.g. `US`.
    pub country: Option<String>,
    /// Current verdict dot.
    pub verdict: Verdict,
    /// Real-time throughput in bytes per second (0 renders as `—`).
    pub rate_bps: u64,
    /// Accumulated bytes to this destination since the panel launched.
    pub total_bytes: u64,
    /// Number of active sockets collapsed into this endpoint row.
    pub sockets: u32,
    /// Whether the per-domain two-state control is on (allowed).
    pub allowed: bool,
}

/// Real-time throughput state shown in an Apps row under the Real-time scope.
///
/// This is what makes the live view read as "now" rather than a cumulative
/// counter: active apps show a jittering rate, idle-with-buffer apps show a
/// session total, and quiet processes show `—` or a deliberate `0 B`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    /// Actively transferring at this many bytes per second.
    Active(u64),
    /// Idle, but holding a session buffer of this many bytes (a paused call).
    Session(u64),
    /// Deliberately zero — a suppressed or blocked background process.
    Zero,
    /// Nothing happening.
    Idle,
}

impl Flow {
    /// Real-time label: `2.1 MB/s`, `4.2 MB`, `0 B`, or `—`. The scope selector
    /// already communicates Live vs Session, so the value carries no suffix.
    #[must_use]
    pub fn label(self) -> String {
        match self {
            Flow::Active(bps) => format_rate(bps),
            Flow::Session(bytes) => format_bytes(bytes),
            Flow::Zero => "0 B".to_string(),
            Flow::Idle => "—".to_string(),
        }
    }
}

/// An application row in the Apps tab.
#[derive(Debug, Clone, PartialEq)]
pub struct AppRow {
    /// Stable key — bundle id or executable path.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Bundle path for real-icon extraction; `None` falls back to a monogram.
    pub bundle_path: Option<PathBuf>,
    /// Whether network access is currently allowed for this app.
    pub allowed: bool,
    /// Flagged by openbinary as a known-bad binary (renders a red chip).
    pub known_bad: bool,
    /// Whether this is an Apple-signed macOS system binary. Drives folding the
    /// Apple daemons under a single collapsible "macOS System" group at the top
    /// of the Apps list. Defaults to `false` for non-system apps.
    pub is_system: bool,
    /// Scoped bytes downloaded (the Today total; drifts only slightly).
    pub down_bytes: u64,
    /// Scoped bytes uploaded (the Today total; drifts only slightly).
    pub up_bytes: u64,
    /// Current real-time throughput state (Real-time scope display).
    pub flow: Flow,
    /// Destinations this app has reached, most active first.
    pub domains: Vec<DomainRow>,
}

impl AppRow {
    /// First character of the name, used for the monogram fallback tile.
    #[must_use]
    pub fn monogram(&self) -> char {
        self.name.chars().next().unwrap_or('?').to_ascii_uppercase()
    }
}

/// A flat destination row in the Network tab (owning app + endpoint).
#[derive(Debug, Clone, PartialEq)]
pub struct NetRow {
    /// Owning app display name.
    pub app_name: String,
    /// Owning app bundle path for the icon.
    pub app_path: Option<PathBuf>,
    /// The destination.
    pub domain: DomainRow,
}

/// A process row in the Processes tab.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcRow {
    /// Stable key — pid rendered as string, or bundle id in demo mode.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Bundle/executable path for the icon.
    pub bundle_path: Option<PathBuf>,
    /// CPU usage percent (0-100 per core-normalised). Meaningful only when
    /// [`Self::stats_known`] is `true`.
    pub cpu: f32,
    /// Resident memory in bytes. Meaningful only when [`Self::stats_known`].
    pub mem_bytes: u64,
    /// Network throughput in bytes per second.
    pub net_bps: u64,
    /// Accumulated network bytes since the panel launched.
    pub net_bytes: u64,
    /// Whether CPU/memory were readable. `false` → the row renders "—" for both
    /// (the daemon could not read a root-owned / hardened / exited process).
    pub stats_known: bool,
}

impl ProcRow {
    /// Monogram fallback character.
    #[must_use]
    pub fn monogram(&self) -> char {
        self.name.chars().next().unwrap_or('?').to_ascii_uppercase()
    }

    /// CPU label: `"12.3%"` when known, `"—"` when the stats were unreadable.
    #[must_use]
    pub fn cpu_label(&self) -> String {
        if self.stats_known {
            format!("{:.1}%", self.cpu)
        } else {
            "—".to_string()
        }
    }

    /// Memory label: a compact byte string when known, `"—"` when unreadable.
    #[must_use]
    pub fn mem_label(&self) -> String {
        if self.stats_known {
            format_bytes(self.mem_bytes)
        } else {
            "—".to_string()
        }
    }
}

/// A rollup of one or more processes that share a responsible app.
///
/// The Processes tab renders one group row with summed CPU/MEM/NET; the
/// disclosure expands to the individual [`ProcRow`]s that compose it.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcGroup {
    /// Stable key — bundle/executable path, or the sole process id.
    pub id: String,
    /// Display name (the owning app, or the process itself when standalone).
    pub name: String,
    /// Bundle/executable path for the icon.
    pub bundle_path: Option<PathBuf>,
    /// Summed CPU usage percent across members.
    pub cpu: f32,
    /// Summed resident memory in bytes.
    pub mem_bytes: u64,
    /// Summed network throughput in bytes per second.
    pub net_bps: u64,
    /// Summed accumulated network bytes since launch.
    pub net_bytes: u64,
    /// Member processes, most resource-heavy first.
    pub procs: Vec<ProcRow>,
    /// Whether the summed CPU/memory are known for at least one member. `false`
    /// (every member unreadable) → the group renders "—" for CPU/MEM.
    pub stats_known: bool,
}

impl ProcGroup {
    /// Wrap a single process as its own one-member group.
    #[must_use]
    pub fn singleton(proc: ProcRow) -> Self {
        Self {
            id: proc.id.clone(),
            name: proc.name.clone(),
            bundle_path: proc.bundle_path.clone(),
            cpu: proc.cpu,
            mem_bytes: proc.mem_bytes,
            net_bps: proc.net_bps,
            net_bytes: proc.net_bytes,
            stats_known: proc.stats_known,
            procs: vec![proc],
        }
    }

    /// CPU label: `"12.3%"` when known, `"—"` when unreadable.
    #[must_use]
    pub fn cpu_label(&self) -> String {
        if self.stats_known {
            format!("{:.1}%", self.cpu)
        } else {
            "—".to_string()
        }
    }

    /// Memory label: a compact byte string when known, `"—"` when unreadable.
    #[must_use]
    pub fn mem_label(&self) -> String {
        if self.stats_known {
            format_bytes(self.mem_bytes)
        } else {
            "—".to_string()
        }
    }

    /// First character of the name, used for the monogram fallback tile.
    #[must_use]
    pub fn monogram(&self) -> char {
        self.name.chars().next().unwrap_or('?').to_ascii_uppercase()
    }

    /// Whether this group has more than one member (drives the disclosure).
    #[must_use]
    pub fn is_group(&self) -> bool {
        self.procs.len() > 1
    }
}

/// The inspector snapshot pushed when a row body is clicked.
#[derive(Debug, Clone, PartialEq)]
pub struct Detail {
    /// Display name.
    pub name: String,
    /// Bundle identifier or a synthesized id.
    pub bundle_id: String,
    /// Bundle/executable path for the icon.
    pub bundle_path: Option<PathBuf>,
    /// Session bytes in.
    pub in_bytes: u64,
    /// Session bytes out.
    pub out_bytes: u64,
    /// Executable path string.
    pub path: String,
    /// Owning user.
    pub user: String,
    /// Code-signing summary.
    pub signature: Signature,
    /// openbinary verdict line, e.g. `known good · curl 8.7`.
    pub openbinary: String,
    /// Top hostnames (already truncated by the source).
    pub hostnames: Vec<String>,
    /// A few representative IP addresses.
    pub ips: Vec<String>,
    /// Ports / protocols summary strings.
    pub ports: Vec<String>,
    /// Count of allowed connections.
    pub allowed_count: u32,
    /// Count of denied connections.
    pub denied_count: u32,
    /// Whether network is currently allowed (drives the Block action state).
    pub allowed: bool,
}

impl Detail {
    /// A partial detail seeded from an [`AppRow`] the panel already has, for
    /// instant inspector rendering before the daemon's full detail arrives. The
    /// fields the row cannot know (path, user, signature, openbinary, IPs, ports)
    /// are left as placeholders and filled in when the daemon response merges.
    #[must_use]
    pub fn from_app_row(app: &AppRow) -> Self {
        let mut allowed_count = 0;
        let mut denied_count = 0;
        let mut hostnames = Vec::new();
        for d in &app.domains {
            if d.allowed {
                allowed_count += 1;
            } else {
                denied_count += 1;
            }
            hostnames.push(d.host.clone());
        }
        hostnames.truncate(12);
        Self {
            name: app.name.clone(),
            bundle_id: app.id.clone(),
            bundle_path: app.bundle_path.clone(),
            in_bytes: app.down_bytes,
            out_bytes: app.up_bytes,
            path: String::new(),
            user: "—".to_string(),
            signature: Signature::Unsigned,
            openbinary: "—".to_string(),
            hostnames,
            ips: Vec::new(),
            ports: Vec::new(),
            allowed_count,
            denied_count,
            allowed: app.allowed,
        }
    }

    /// A partial detail seeded from a [`ProcRow`] for instant inspector rendering.
    #[must_use]
    pub fn from_proc_row(proc: &ProcRow) -> Self {
        Self {
            name: proc.name.clone(),
            bundle_id: proc.id.clone(),
            bundle_path: proc.bundle_path.clone(),
            in_bytes: proc.net_bytes,
            out_bytes: 0,
            path: String::new(),
            user: "—".to_string(),
            signature: Signature::Unsigned,
            openbinary: "—".to_string(),
            hostnames: Vec::new(),
            ips: Vec::new(),
            ports: Vec::new(),
            allowed_count: 0,
            denied_count: 0,
            allowed: true,
        }
    }

    /// A partial detail seeded from a [`NetRow`] (a flat destination) for instant
    /// inspector rendering of a domain route.
    #[must_use]
    pub fn from_net_row(row: &NetRow) -> Self {
        let d = &row.domain;
        let (allowed_count, denied_count) = if d.allowed { (1, 0) } else { (0, 1) };
        Self {
            name: d.host.clone(),
            bundle_id: d.host.clone(),
            bundle_path: row.app_path.clone(),
            in_bytes: d.total_bytes,
            out_bytes: 0,
            path: String::new(),
            user: "—".to_string(),
            signature: Signature::Unsigned,
            openbinary: "—".to_string(),
            hostnames: vec![d.host.clone()],
            ips: Vec::new(),
            ports: Vec::new(),
            allowed_count,
            denied_count,
            allowed: d.allowed,
        }
    }
}

/// Footer totals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Totals {
    /// Session bytes downloaded.
    pub down_bytes: u64,
    /// Session bytes uploaded.
    pub up_bytes: u64,
    /// Trackers blocked this session.
    pub trackers_blocked: u64,
    /// Total internet connections observed.
    pub connections: u64,
    /// Current aggregate download rate in bytes per second (live footer).
    pub down_bps: u64,
    /// Current aggregate upload rate in bytes per second (live footer).
    pub up_bps: u64,
}

/// Format a byte count as a compact human string (`406 MB`, `14.5 MB`).
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    if bytes == 0 {
        return "0 B".to_string();
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    let precision = usize::from(value < 10.0 && unit > 1);
    let suffix = UNITS.get(unit).copied().unwrap_or("B");
    format!("{value:.precision$} {suffix}")
}

/// Format a per-second byte rate (`—` when zero, else `1.2 MB/s`).
#[must_use]
pub fn format_rate(bytes_per_sec: u64) -> String {
    if bytes_per_sec == 0 {
        return "—".to_string();
    }
    format!("{}/s", format_bytes(bytes_per_sec))
}

/// Render a metric under a scope: accumulated total bytes when `totals` is set
/// (Hour / Today / Session), otherwise the live per-second rate. This is the one
/// place the "never show /s under a totals scope" rule is enforced.
#[must_use]
pub fn format_scoped(totals: bool, rate_bps: u64, total_bytes: u64) -> String {
    if totals {
        format_bytes(total_bytes)
    } else {
        format_rate(rate_bps)
    }
}

#[cfg(test)]
#[path = "model_test.rs"]
mod model_test;
