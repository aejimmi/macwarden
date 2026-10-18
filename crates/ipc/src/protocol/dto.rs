//! Wire DTOs: a faithful, superset-compatible mirror of `macwarden-ui`'s
//! `data/model.rs` types, plus the mutation/history value types.
//!
//! # Mapping to `macwarden-ui` `model.rs`
//!
//! `ipc` cannot depend on `macwarden-ui`, so the mapping impl lives on the panel
//! side (a `DaemonSource: PanelSource`). This table is the contract that mapping
//! implements; every `model.rs` field has a DTO source here. The only shape
//! change is `Option<PathBuf>` → `Option<String>` (paths travel as UTF-8 on the
//! wire) — the panel converts back with `PathBuf::from`.
//!
//! - `Verdict` → [`WireVerdict`]: `Allow`/`Blocked`/`Tracker` one-to-one.
//! - `Signature` → [`WireSignature`]: `Apple`/`DevId(team)`/`Unsigned`.
//! - `Flow` → [`WireFlow`]: `Active(bps)`/`Session(bytes)`/`Zero`/`Idle`.
//! - `DomainRow` → [`WireDomainRow`]: `host`, `country`, `verdict`, `rate_bps`,
//!   `total_bytes`, `sockets`, `allowed` — all one-to-one.
//! - `AppRow` → [`WireAppRow`]: `id`, `name`, `bundle_path` (PathBuf→String),
//!   `allowed`, `known_bad`, `down_bytes`, `up_bytes`, `flow`, `is_system`,
//!   `domains`. (`AppRow::monogram()` is derived — no DTO field.)
//! - `NetRow` → [`WireNetRow`]: `app_name`, `app_path` (PathBuf→String),
//!   `domain`.
//! - `ProcRow` → [`WireProcRow`]: `id`, `name`, `bundle_path`, `cpu`,
//!   `mem_bytes`, `net_bps`, `net_bytes`, `is_system`.
//! - `ProcGroup` → [`WireProcGroup`]: `id`, `name`, `bundle_path`, `cpu`,
//!   `mem_bytes`, `net_bps`, `net_bytes`, `procs`.
//! - `Detail` → [`WireDetail`]: `name`, `bundle_id`, `bundle_path`, `in_bytes`,
//!   `out_bytes`, `path`, `user`, `signature`, `openbinary`, `hostnames`, `ips`,
//!   `ports`, `allowed_count`, `denied_count`, `allowed`.
//! - `Totals` → [`WireTotals`]: `down_bytes`, `up_bytes`, `trackers_blocked`,
//!   `connections`, `down_bps`, `up_bps`.

use serde::{Deserialize, Serialize};

/// The verdict rendered as a dot beside a destination. Mirrors
/// `macwarden-ui`'s `Verdict`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireVerdict {
    /// Connection is permitted.
    Allow,
    /// Connection is denied.
    Blocked,
    /// Known tracker endpoint.
    Tracker,
}

/// Code-signing identity summary. Mirrors `macwarden-ui`'s `Signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireSignature {
    /// Signed by Apple.
    Apple,
    /// Signed with a Developer ID and a team identifier.
    DevId(String),
    /// No valid signature.
    Unsigned,
}

/// Real-time throughput state for an app row. Mirrors `macwarden-ui`'s `Flow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireFlow {
    /// Actively transferring at this many bytes per second.
    Active(u64),
    /// Idle, but holding a session buffer of this many bytes.
    Session(u64),
    /// Deliberately zero — a suppressed or blocked background process.
    Zero,
    /// Nothing happening.
    Idle,
}

/// A destination row nested under an app or shown flat in the Network tab.
/// Mirrors `macwarden-ui`'s `DomainRow`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDomainRow {
    /// Hostname, e.g. `googlevideo.com`.
    pub host: String,
    /// ISO country code when known, e.g. `US`.
    #[serde(default)]
    pub country: Option<String>,
    /// Current verdict dot, computed from the daemon's live `RuleSet`.
    pub verdict: WireVerdict,
    /// Real-time throughput in bytes per second.
    pub rate_bps: u64,
    /// Accumulated bytes to this destination.
    pub total_bytes: u64,
    /// Number of active sockets collapsed into this endpoint row.
    pub sockets: u32,
    /// Whether the per-domain two-state control is on (allowed).
    pub allowed: bool,
}

/// An application row in the Apps tab. Mirrors `macwarden-ui`'s `AppRow`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAppRow {
    /// Stable key — bundle id or executable path.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Bundle path for real-icon extraction (`None` → monogram fallback).
    #[serde(default)]
    pub bundle_path: Option<String>,
    /// Whether network access is currently allowed for this app.
    pub allowed: bool,
    /// Flagged by openbinary as a known-bad binary.
    pub known_bad: bool,
    /// Scoped bytes downloaded (the Today total).
    pub down_bytes: u64,
    /// Scoped bytes uploaded (the Today total).
    pub up_bytes: u64,
    /// Current real-time throughput state.
    pub flow: WireFlow,
    /// Whether this is an Apple-signed macOS **system** binary (Apple-signed and
    /// resident under a system prefix). Lets the panel fold system daemons into a
    /// single "macOS System" row. Defaults to `false` for pre-flag daemons.
    #[serde(default)]
    pub is_system: bool,
    /// Destinations this app has reached, most active first.
    #[serde(default)]
    pub domains: Vec<WireDomainRow>,
}

/// A flat destination row in the Network tab. Mirrors `macwarden-ui`'s `NetRow`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireNetRow {
    /// Owning app display name.
    pub app_name: String,
    /// Owning app bundle path for the icon.
    #[serde(default)]
    pub app_path: Option<String>,
    /// The destination.
    pub domain: WireDomainRow,
}

/// A process row in the Processes tab. Mirrors `macwarden-ui`'s `ProcRow`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireProcRow {
    /// Stable key — pid rendered as string, or bundle id.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Bundle/executable path for the icon.
    #[serde(default)]
    pub bundle_path: Option<String>,
    /// CPU usage percent (0-100 per core-normalised).
    pub cpu: f32,
    /// Resident memory in bytes.
    pub mem_bytes: u64,
    /// Network throughput in bytes per second.
    pub net_bps: u64,
    /// Accumulated network bytes.
    pub net_bytes: u64,
    /// Whether this is an Apple-signed macOS **system** binary (Apple-signed and
    /// resident under a system prefix). Defaults to `false` for pre-flag daemons.
    #[serde(default)]
    pub is_system: bool,
    /// Whether [`Self::cpu`]/[`Self::mem_bytes`] are actually known. `false` means
    /// the daemon could not read this process's resources (unprivileged access to
    /// a root-owned / hardened / exited pid) and the panel must render "—" rather
    /// than a fabricated `0`. Defaults to `true` for pre-flag daemons, which only
    /// ever reported real (or already-zeroed) numbers.
    #[serde(default = "default_true")]
    pub stats_known: bool,
}

/// serde default for the additive `stats_known` flag: a daemon or panel that
/// predates the flag treated all reported stats as known, so absence means `true`.
fn default_true() -> bool {
    true
}

/// A rollup of processes sharing a responsible app. Mirrors `ProcGroup`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WireProcGroup {
    /// Stable key — bundle/executable path, or the sole process id.
    pub id: String,
    /// Display name (owning app, or the process itself when standalone).
    pub name: String,
    /// Bundle/executable path for the icon.
    #[serde(default)]
    pub bundle_path: Option<String>,
    /// Summed CPU usage percent across members.
    pub cpu: f32,
    /// Summed resident memory in bytes.
    pub mem_bytes: u64,
    /// Summed network throughput in bytes per second.
    pub net_bps: u64,
    /// Summed accumulated network bytes.
    pub net_bytes: u64,
    /// Member processes, most resource-heavy first.
    #[serde(default)]
    pub procs: Vec<WireProcRow>,
    /// Whether the summed CPU/memory are known for at least one member. `false`
    /// (all members unreadable) → the panel renders "—". Defaults to `true` for
    /// pre-flag daemons.
    #[serde(default = "default_true")]
    pub stats_known: bool,
}

/// The inspector snapshot for a row. Mirrors `macwarden-ui`'s `Detail`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDetail {
    /// Display name.
    pub name: String,
    /// Bundle identifier or a synthesized id.
    pub bundle_id: String,
    /// Bundle/executable path for the icon.
    #[serde(default)]
    pub bundle_path: Option<String>,
    /// Session bytes in.
    pub in_bytes: u64,
    /// Session bytes out.
    pub out_bytes: u64,
    /// Executable path string.
    pub path: String,
    /// Owning user.
    pub user: String,
    /// Code-signing summary.
    pub signature: WireSignature,
    /// openbinary verdict line, or `"not yet analyzed"` when uncached.
    pub openbinary: String,
    /// Top hostnames (already truncated by the daemon).
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// A few representative IP addresses.
    #[serde(default)]
    pub ips: Vec<String>,
    /// Ports / protocols summary strings.
    #[serde(default)]
    pub ports: Vec<String>,
    /// Count of allowed connections.
    pub allowed_count: u32,
    /// Count of denied connections.
    pub denied_count: u32,
    /// Whether network is currently allowed (drives the Block action state).
    pub allowed: bool,
}

/// Footer totals. Mirrors `macwarden-ui`'s `Totals`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct WireTotals {
    /// Session bytes downloaded.
    pub down_bytes: u64,
    /// Session bytes uploaded.
    pub up_bytes: u64,
    /// Trackers blocked this session (live tracker-tier denials).
    pub trackers_blocked: u64,
    /// Total internet connections observed.
    pub connections: u64,
    /// Current aggregate download rate in bytes per second.
    pub down_bps: u64,
    /// Current aggregate upload rate in bytes per second.
    pub up_bps: u64,
}

/// The target of a [`crate::protocol::Request::SetRule`] toggle (R7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleTarget {
    /// Block/unblock all network for an app by its code id.
    App {
        /// Reverse-DNS/bundle-form code id (validated at the boundary).
        code_id: String,
    },
    /// Block/unblock a destination host for every app.
    Domain {
        /// Hostname (validated at the boundary).
        host: String,
    },
    /// Block/unblock a specific host for a specific app.
    AppDomain {
        /// Reverse-DNS/bundle-form code id.
        code_id: String,
        /// Hostname.
        host: String,
    },
}

/// How long a [`crate::protocol::Request::SetRule`] rule persists (R7). Maps to
/// `net::RuleDuration` on the daemon side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireDuration {
    /// Written to `~/.macwarden/net-rules/`, survives restarts.
    Permanent,
    /// In-memory only for the daemon session; writes no file.
    Session,
    /// Written, auto-cleaned after the deadline.
    Until {
        /// Absolute expiry in unix milliseconds (validated future + bounded).
        expiry_ms: u64,
    },
}

/// One entry in a batched [`crate::protocol::Request::SetRules`] mutation (R7):
/// the same shape as a single `SetRule` (target + allow + duration). A batch lets
/// the panel apply an aggregate action — e.g. block/allow every member of the
/// "macOS System" group — as **one** mutation (one ruleset reload, one rate-limit
/// charge) instead of N separate `SetRule` calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireRuleChange {
    /// What to block/unblock.
    pub target: RuleTarget,
    /// `true` allows, `false` blocks.
    pub allow: bool,
    /// How long the rule persists.
    pub duration: WireDuration,
}

/// One active banwatch ban, surfaced to the panel (spec 010 R8). The `ip`
/// travels as a string and is parsed daemon-side; every field carries
/// `#[serde(default)]` so an older panel tolerates a newer daemon adding fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireBan {
    /// The banned source IP, as a string (parsed daemon-side).
    #[serde(default)]
    pub ip: String,
    /// The detector that triggered the ban (`repeat-blocked`, `auth-failure`,
    /// `port-scan`, or `manual`).
    #[serde(default)]
    pub detector: String,
    /// When the ban was applied, in unix milliseconds.
    #[serde(default)]
    pub banned_at_ms: u64,
    /// When the ban expires, in unix milliseconds; `None` = permanent.
    #[serde(default)]
    pub expires_at_ms: Option<u64>,
    /// Prior escalation count at ban time (0 = first offense).
    #[serde(default)]
    pub escalation_count: u32,
    /// Trigger source (a detector id or `manual`).
    #[serde(default)]
    pub source: String,
}

/// Which packet source backs a trace (R8/R12), reported in
/// [`crate::protocol::Response::TraceStarted`] so the panel can be **honest**:
/// a synthetic demo stream is never presented as real capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WireTraceSource {
    /// Real BPF capture — live traffic on a device.
    Live,
    /// Synthetic demo stream: the daemon *can* capture (feature compiled) but
    /// could not open a BPF device — no `access_bpf` group membership / not root.
    DemoNoAccess,
    /// Synthetic demo stream: live capture is not compiled into this daemon
    /// (the `capture-live` feature is off, or a non-macOS build).
    DemoNoCapture,
    /// Unknown — an older daemon that did not report a source. Treated as **not**
    /// live so a demo stream is never mistaken for real capture.
    #[serde(other)]
    #[default]
    Unknown,
}

impl WireTraceSource {
    /// Whether this is a real live capture (drives the panel's honest badge).
    #[must_use]
    pub fn is_live(self) -> bool {
        matches!(self, Self::Live)
    }
}

/// The target of a [`crate::protocol::Request::SetExecPolicy`] request (R7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecTarget {
    /// Deny/allow launch by code id.
    CodeId(String),
    /// Deny/allow launch by signing team id.
    TeamId(String),
}

/// The time window for a [`crate::protocol::Request::GetHistory`] query (R5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HistoryScope {
    /// The last hour (`TimeRange::last_hours(1)`).
    Hour,
    /// Since local midnight (`TimeRange::today()`).
    Today,
    /// The daemon's in-memory session accumulators.
    Session,
}

/// The global firewall mode carried by profile requests/responses (R7). Maps to
/// `net::PolicyMode` on the daemon side.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireMode {
    /// Allow-All: everything is allowed-and-logged unless explicitly denied.
    AllowAll,
    /// Block-All: denied unless something earlier explicitly allows it.
    BlockAll,
}

/// A user-managed allow-list exception on the wire (R7). `ip` travels as a
/// string (CIDR or bare IP) and is parsed daemon-side into an `IpNet`.
///
/// At least one of `app`/`team_id`/`host`/`ip` must be present, and `app` and
/// `team_id` are mutually exclusive -- both enforced at the daemon boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireAllowEntry {
    /// Process code id or path (leading `/`). Mutually exclusive with `team_id`.
    #[serde(default)]
    pub app: Option<String>,
    /// Exact 10-char signing team id. Mutually exclusive with `app`.
    #[serde(default)]
    pub team_id: Option<String>,
    /// Host pattern.
    #[serde(default)]
    pub host: Option<String>,
    /// IP address or CIDR range as a string (parsed daemon-side).
    #[serde(default)]
    pub ip: Option<String>,
    /// Free-form user note.
    #[serde(default)]
    pub note: Option<String>,
}

/// The state of one built-in network group on the wire (R7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireGroupState {
    /// Group name (e.g. `"location-services"`).
    pub name: String,
    /// Human-readable description of what the group means, so the panel's Rules
    /// view can render intent rather than a bare toggle. Defaults to empty for
    /// back-compat with pre-description daemons/panels.
    #[serde(default)]
    pub description: String,
    /// Whether the group is currently enabled (default + overrides applied).
    pub enabled: bool,
    /// Whether the group is enabled by default (before overrides).
    pub default_enabled: bool,
    /// Number of distinct domain patterns the group covers. Defaults to 0 for
    /// back-compat with pre-count daemons/panels.
    #[serde(default)]
    pub domain_count: usize,
}

/// The full policy profile snapshot echoed to the panel (R7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireProfile {
    /// Global mode.
    pub mode: WireMode,
    /// Allow Apple-signed programs (with the graylist carve-out).
    pub allow_apple_programs: bool,
    /// Allow the system resolver process.
    pub allow_dns_traffic: bool,
    /// The built-in groups and their current enabled state.
    #[serde(default)]
    pub groups: Vec<WireGroupState>,
    /// The user's allow-list entries.
    #[serde(default)]
    pub allowlist: Vec<WireAllowEntry>,
}

/// One aggregated history bucket (R5). Carries a coarse start/end ms range so it
/// can grow into finer buckets without a protocol break.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryBucket {
    /// Bucket start in unix milliseconds.
    pub start_ms: u64,
    /// Bucket end in unix milliseconds.
    pub end_ms: u64,
    /// Scoped app code id, or `None` for the machine-wide rollup.
    #[serde(default)]
    pub app_id: Option<String>,
    /// Total connections decided in this bucket.
    pub connections: u64,
    /// Denied connections in this bucket.
    pub denied: u64,
    /// Tracker-tier hits in this bucket.
    pub tracker_hits: u64,
    /// Bytes downloaded in this bucket (from `BandwidthSampled`).
    pub down_bytes: u64,
    /// Bytes uploaded in this bucket (from `BandwidthSampled`).
    pub up_bytes: u64,
}

// ---------------------------------------------------------------------------
// Packet-trace DTOs (R8) — pure serde mirrors of the `crates/capture` types.
//
// `ipc` cannot depend on `crates/capture`, so these mirror its parse/decode
// shapes exactly like [`WireAppRow`] mirrors `macwarden-ui`'s `AppRow`; the
// daemon maps `capture::PacketRecord`/`capture::DecodeTree` → these on the wire.
// The Tier-1 boundary (spec R1) is preserved structurally: there is **no** field
// here for a decrypted application-data body — only handshake metadata and,
// on-demand, the raw frame bytes for the hex view.
//
// The stream is split light/heavy: the live [`crate::protocol::Event::Packet`]
// push carries only [`WirePacketRecord`] (summary + headers + SNI), while the
// full decode tree and raw bytes for a *selected* packet are fetched on demand
// via [`crate::protocol::Request::GetPacketBytes`] → [`WirePacketBytes`]. This
// keeps per-packet stream frames small on a busy app.
// ---------------------------------------------------------------------------

/// Transport-layer protocol on the wire. Mirrors `capture`'s `L4Proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireL4Proto {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol.
    Udp,
    /// ICMP (v4 or v6).
    Icmp,
    /// Address Resolution Protocol (no L4).
    Arp,
    /// A recognised network layer with no handled transport.
    Other,
}

/// Traffic direction relative to the local host. Mirrors `capture`'s
/// `Direction`, with an extra [`WireDirection::Unknown`] for the case where the
/// daemon could not classify locality (e.g. no interface addresses known).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireDirection {
    /// Traffic arriving at this host (`capture`'s `Inbound`).
    In,
    /// Traffic leaving this host (`capture`'s `Outbound`).
    Out,
    /// Locality could not be determined.
    Unknown,
}

/// Best-effort application protocol, a heuristic guess only. Mirrors `capture`'s
/// `AppProto`. Never implies decryption — TLS application data stays opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WireAppProto {
    /// TLS (handshake visible in cleartext; application data is opaque).
    Tls,
    /// DNS over UDP/TCP.
    Dns,
    /// Cleartext HTTP.
    Http,
    /// QUIC (UDP/443) — treated opaquely at Tier 1.
    Quic,
    /// Not identified.
    Unknown,
}

/// The **light** per-packet summary streamed live over
/// [`crate::protocol::Event::Packet`] (R8). Mirrors `capture`'s `PacketRecord`
/// minus its raw bytes, decode tree, and full TLS handshake detail — those are
/// fetched on demand via [`WirePacketBytes`] to keep the stream cheap on a busy
/// app. Carries **no** raw bytes and **no** decrypted body (spec R1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePacketRecord {
    /// Monotonic per-trace sequence number, the key for [`WirePacketBytes`].
    pub seq: u64,
    /// Capture time in unix milliseconds.
    pub timestamp_ms: u64,
    /// Source endpoint rendered as `ip:port` (or `[v6]:port` / bare `ip`).
    pub src: String,
    /// Destination endpoint rendered as `ip:port`.
    pub dst: String,
    /// Transport protocol.
    pub proto: WireL4Proto,
    /// On-wire frame length in bytes.
    pub length: u32,
    /// Direction relative to the local host.
    pub direction: WireDirection,
    /// Best-effort application protocol (port + payload heuristic).
    pub app_proto: WireAppProto,
    /// Resolved domain / TLS Client Hello SNI, when known.
    #[serde(default)]
    pub sni: Option<String>,
    /// Negotiated or offered TLS version label, e.g. `"TLS 1.3"`, when known.
    #[serde(default)]
    pub tls_version: Option<String>,
    /// One-line, Proxyman-style human summary.
    pub summary: String,
}

/// One node in the packet decode tree. Mirrors `capture`'s `DecodeNode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDecodeNode {
    /// Layer label, e.g. `"Ethernet"`, `"IPv4"`, `"TCP"`, `"TLS"`.
    pub label: String,
    /// One-line summary of the layer's salient fields.
    pub summary: String,
    /// The byte range this layer occupies within the raw frame, so the UI can
    /// cross-highlight the hex dump. Contained within the parent's range.
    pub byte_range: std::ops::Range<usize>,
    /// Field name/value pairs for the inspector detail rows.
    #[serde(default)]
    pub fields: Vec<(String, String)>,
    /// Nested layers contained within this one.
    #[serde(default)]
    pub children: Vec<WireDecodeNode>,
}

/// The full decode tree for one packet: a single `Frame` root spanning the whole
/// capture, with layer children beneath it. Mirrors `capture`'s `DecodeTree`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireDecodeTree {
    /// The root `Frame` node.
    pub root: WireDecodeNode,
}

/// The **heavy** on-demand payload for a selected packet (R8), answering
/// [`crate::protocol::Request::GetPacketBytes`]. Carries the raw frame bytes
/// (from which the panel formats the hex dump) and the decode tree.
///
/// When the requested `seq` has aged out of the daemon's bounded ring buffer
/// (R6), [`WirePacketBytes::available`] is `false` and `raw`/`tree` are empty —
/// a graceful "not available", never an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePacketBytes {
    /// The sequence number the client selected.
    pub seq: u64,
    /// Whether the packet was still retained in the ring (R6). `false` → the
    /// `seq` aged out and `raw`/`tree` are empty.
    pub available: bool,
    /// The raw frame bytes, starting at the link layer. Empty when unavailable.
    /// The panel formats the offset/hex/ASCII dump from these bytes.
    #[serde(default)]
    pub raw: Vec<u8>,
    /// The decode tree for the frame, or `None` when unavailable.
    #[serde(default)]
    pub tree: Option<WireDecodeTree>,
}

#[cfg(test)]
#[path = "dto_test.rs"]
mod dto_test;
