//! The top-level [`Request`]/[`Response`]/[`Event`] message enums.
//!
//! The request surface is a **fixed typed enum** — there is no free-form command,
//! path, or query string — so there is no code/command-execution escape hatch
//! (R9). Every variant maps to one daemon capability.

use serde::{Deserialize, Serialize};

use super::dto::{
    ExecTarget, HistoryBucket, HistoryScope, RuleTarget, WireAllowEntry, WireAppRow, WireBan,
    WireDetail, WireDuration, WireMode, WireNetRow, WirePacketBytes, WirePacketRecord,
    WireProcGroup, WireProcRow, WireProfile, WireRuleChange, WireTotals, WireTraceSource,
    WireVerdict,
};
use super::{Capability, ErrorKind};

/// A client→daemon request. The first request on every connection MUST be
/// [`Request::Hello`] (R3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Request {
    /// Handshake: announce the client's protocol and build versions (R3).
    Hello {
        /// The client's [`super::PROTOCOL_VERSION`].
        protocol_version: u32,
        /// Human-readable client build version, for logging/affordances.
        client_version: String,
    },
    /// Live snapshot with verdicts (R4). Driven at ~1 Hz by the panel.
    GetSnapshot,
    /// History buckets over a scope, optionally scoped to one app (R5).
    GetHistory {
        /// The time window.
        scope: HistoryScope,
        /// `None` → machine-wide rollup; `Some(code_id)` → per-app.
        #[serde(default)]
        app_id: Option<String>,
    },
    /// Inspector detail for an app by id (R6).
    GetAppDetail {
        /// The app's code id / stable key.
        id: String,
    },
    /// Inspector detail for a process by id (R6).
    GetProcDetail {
        /// The process stable key.
        id: String,
    },
    /// Inspector detail for a destination by hostname (R6).
    GetDomainDetail {
        /// The destination host.
        host: String,
    },
    /// Block/unblock toggle; hot-reloads the daemon's live `RuleSet` (R7).
    SetRule {
        /// What to block/unblock.
        target: RuleTarget,
        /// `true` allows, `false` blocks.
        allow: bool,
        /// How long the rule persists.
        duration: WireDuration,
    },
    /// Apply a **batch** of block/unblock changes as one mutation (R7): the
    /// daemon applies every entry, then does a single ruleset reload/persist and
    /// replies once with [`Response::RulesAck`]. Used for aggregate actions like
    /// blocking/allowing a whole group. Validated at the boundary: non-empty,
    /// capped, each entry validated like [`Request::SetRule`]; it counts as one
    /// charge against the mutation rate limit.
    SetRules {
        /// The changes to apply, in order.
        rules: Vec<WireRuleChange>,
    },
    /// Prevent-launch policy, capability-gated behind [`Capability::ExecPolicy`]
    /// (R7). Enforcement is later; only the shape and gating are frozen here.
    SetExecPolicy {
        /// What to deny/allow launching.
        target: ExecTarget,
        /// `true` denies launch, `false` clears the deny.
        deny: bool,
    },
    /// Opt this connection into server-push [`Event`] frames (R10).
    Subscribe {
        /// The event kinds to receive.
        kinds: Vec<EventKind>,
    },
    /// Stop server-push events on this connection (R10).
    Unsubscribe,
    /// Read the current policy profile, gated on [`Capability::Policy`] (R7).
    GetProfile,
    /// Set the global mode (Allow-All vs Block-All), hot-reloading the live
    /// rule set (R7).
    SetMode {
        /// The new global mode.
        mode: WireMode,
    },
    /// Toggle "Allow Apple programs" (R7).
    SetAppleAllow {
        /// `true` allows Apple-signed programs (with the graylist carve-out).
        allow: bool,
    },
    /// Toggle "Allow DNS traffic" (R7).
    SetDnsAllow {
        /// `true` allows the system resolver process.
        allow: bool,
    },
    /// Enable or disable a built-in network group durably (R7).
    SetGroupEnabled {
        /// The group name (validated against the built-in set).
        group: String,
        /// `true` enables, `false` disables.
        enabled: bool,
    },
    /// Add an allow-list exception (R7).
    AddAllowListEntry {
        /// The exception to add (validated at the boundary).
        entry: WireAllowEntry,
    },
    /// Remove an allow-list exception, matched by normalized value (R7).
    RemoveAllowListEntry {
        /// The exception to remove.
        entry: WireAllowEntry,
    },
    /// Begin a passive per-app packet trace on this connection (R8).
    /// Capability-gated behind [`Capability::Trace`]; `app_id` is validated at
    /// the boundary via [`crate::validate::validate_app_id`].
    StartTrace {
        /// The target app's code id or executable path.
        app_id: String,
    },
    /// End the active trace on this connection (R8).
    StopTrace,
    /// Fetch the raw bytes + decode tree for one selected packet (R8), keeping
    /// the live [`Event::Packet`] stream light. Answered by
    /// [`Response::PacketBytes`]; an aged-out `seq` yields
    /// [`super::dto::WirePacketBytes::available`] `= false` (R6).
    GetPacketBytes {
        /// The packet's per-trace sequence number.
        seq: u64,
    },
    /// List the active banwatch bans, gated on [`Capability::BanWatch`]
    /// (spec 010 R8). Answered by [`Response::Bans`].
    GetBans,
    /// Manually ban or unban a source IP, gated on [`Capability::BanWatch`]
    /// (spec 010 R8). `ban = false` unbans; `ban = true` manually bans. Both
    /// reload the ban snapshot and the live `RuleSet`. Answered by
    /// [`Response::BanAck`].
    SetBan {
        /// The source IP, as a string (parsed + validated daemon-side).
        ip: String,
        /// `true` bans, `false` unbans.
        ban: bool,
        /// Optional ban duration in seconds (manual ban only); `None` uses the
        /// configured base/escalated ban time.
        #[serde(default)]
        ban_secs: Option<u64>,
        /// Optional detector id to attribute a manual ban to; defaults to
        /// `manual`.
        #[serde(default)]
        detector: Option<String>,
    },
}

/// A daemon→client response. Correlated positionally with the request that
/// produced it (server-push [`Event`]s carry no correlation and are distinct).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Response {
    /// Handshake reply advertising the daemon's version and capabilities (R3).
    Welcome {
        /// The daemon's [`super::PROTOCOL_VERSION`].
        protocol_version: u32,
        /// Human-readable daemon build version.
        daemon_version: String,
        /// Optional features the daemon supports.
        capabilities: Vec<Capability>,
    },
    /// A live snapshot (R4).
    Snapshot {
        /// Apps-tab rows.
        apps: Vec<WireAppRow>,
        /// Network-tab flat destination rows.
        net_rows: Vec<WireNetRow>,
        /// Processes-tab rows.
        procs: Vec<WireProcRow>,
        /// Processes-tab rows grouped by responsible app.
        proc_groups: Vec<WireProcGroup>,
        /// Footer totals.
        totals: WireTotals,
        /// Ruleset generation; increments on each mutation (R7).
        generation: u64,
        /// Age of the underlying live sample in milliseconds, or `None` before
        /// the first sample. Lets the panel detect a wedged sampler (socket
        /// alive but the scan loop frozen) rather than rendering a stale sample
        /// as fresh. `#[serde(default)]` so an older daemon (no field) decodes
        /// as `None` and the panel simply forgoes the signal.
        #[serde(default)]
        sample_age_ms: Option<u64>,
    },
    /// History buckets (R5).
    History {
        /// The aggregated buckets.
        buckets: Vec<HistoryBucket>,
    },
    /// Inspector detail; `None` when the id/host is unknown (R6).
    Detail {
        /// The detail, or `None` for an unknown target.
        detail: Option<WireDetail>,
    },
    /// Acknowledgement of a [`Request::SetRule`] mutation (R7).
    RuleAck {
        /// Whether the rule was applied.
        applied: bool,
        /// The new ruleset generation.
        generation: u64,
        /// The resulting verdict for the target.
        verdict: WireVerdict,
    },
    /// Acknowledgement of a [`Request::SetRules`] batch mutation (R7). Carries no
    /// per-target verdict (a batch spans many targets) — the panel re-reads
    /// verdicts from the next snapshot.
    RulesAck {
        /// Whether the batch was applied (at least one change took effect).
        applied: bool,
        /// The new ruleset generation after the single reload.
        generation: u64,
    },
    /// The current policy profile (R7), answering [`Request::GetProfile`].
    Profile {
        /// The full profile snapshot.
        profile: WireProfile,
    },
    /// Acknowledgement of a profile mutation (R7). Echoes the full new state so
    /// the panel re-renders from truth.
    ProfileAck {
        /// The new ruleset generation.
        generation: u64,
        /// The full profile after the mutation.
        profile: WireProfile,
    },
    /// Acknowledgement that a [`Request::StartTrace`] session was created (R8).
    /// A failure to start (gating, no BPF backend) is reported via
    /// [`Response::Error`] instead.
    TraceStarted {
        /// Whether the trace session was successfully started.
        session_ok: bool,
        /// Which source backs the trace — live BPF capture vs. the synthetic
        /// demo stream (R8). The panel surfaces this so a demo stream is never
        /// shown as real capture. Defaults to [`WireTraceSource::Unknown`] for an
        /// older daemon that didn't report (treated as non-live).
        #[serde(default)]
        source: WireTraceSource,
    },
    /// The raw bytes + decode tree for a selected packet (R8), answering
    /// [`Request::GetPacketBytes`]. When the `seq` has aged out of the daemon's
    /// ring, the payload's `available` flag is `false` (R6) rather than an error.
    PacketBytes(WirePacketBytes),
    /// The active banwatch bans (spec 010 R8), answering [`Request::GetBans`].
    Bans {
        /// The active bans, newest ban first.
        bans: Vec<WireBan>,
    },
    /// Acknowledgement of a [`Request::SetBan`] mutation (spec 010 R8).
    BanAck {
        /// Whether the ban/unban took effect.
        applied: bool,
        /// The new ruleset generation after the reload.
        generation: u64,
    },
    /// A typed error. Malformed input, auth failure, version mismatch, etc.
    Error {
        /// The failure category.
        kind: ErrorKind,
        /// Human-readable detail, for logging/affordances.
        #[serde(default)]
        message: String,
    },
}

/// The kind of server-push [`Event`] a connection can subscribe to (R10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A just-decided flow (for between-tick toasts).
    ConnectionDecided,
    /// Aggregate down/up rate at sub-second cadence.
    RateTick,
    /// A captured packet on an active per-app trace (R8).
    Packet,
    /// A banwatch ban was added or lifted (spec 010 R8) — [`Event::IpBanned`] /
    /// [`Event::IpUnbanned`].
    BanChanged,
}

/// A server-push event frame, interleaved with responses on a subscribed
/// connection (R10). Carries no request correlation id — it is a push.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Event {
    /// A flow was just allowed or blocked.
    ConnectionDecided {
        /// The responsible app's code id.
        app_id: String,
        /// The destination host.
        host: String,
        /// The verdict applied.
        verdict: WireVerdict,
        /// Whether the flow was allowed.
        allowed: bool,
    },
    /// An aggregate rate sample.
    RateTick {
        /// Aggregate download rate in bytes per second.
        down_bps: u64,
        /// Aggregate upload rate in bytes per second.
        up_bps: u64,
    },
    /// A packet captured on the active per-app trace (R8). Carries only the
    /// light [`WirePacketRecord`] summary — **no** raw bytes; those are fetched
    /// on demand via [`Request::GetPacketBytes`].
    Packet(WirePacketRecord),
    /// A source IP was just banned by banwatch (spec 010 R8), pushed under
    /// [`EventKind::BanChanged`].
    IpBanned {
        /// The banned source IP.
        ip: String,
        /// The detector that triggered the ban.
        detector: String,
        /// When the ban expires, in unix milliseconds; `None` = permanent.
        #[serde(default)]
        expires_at_ms: Option<u64>,
    },
    /// A source IP's ban was just lifted (spec 010 R8), pushed under
    /// [`EventKind::BanChanged`].
    IpUnbanned {
        /// The unbanned source IP.
        ip: String,
    },
}

/// An outbound frame on a **subscribed** connection, where server-push
/// [`Event`]s interleave with [`Response`]s to in-flight requests (R8/R10).
///
/// The codec deserializes one line into a single type, so a subscribed client
/// reads `ServerFrame` (not `Response`) to disambiguate the two streams. The
/// pre-subscribe request/response path is unchanged; only after `StartTrace` /
/// [`Request::Subscribe`] does the client switch to reading `ServerFrame`. It is
/// **externally** tagged (not untagged) so a `Response` can never be mistaken
/// for an `Event`. [`Response`] is boxed to keep the two variants similarly
/// sized.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerFrame {
    /// An answer to a client request (e.g. [`Response::PacketBytes`]).
    Response(Box<Response>),
    /// A server-push event (e.g. [`Event::Packet`]).
    Event(Event),
}

#[cfg(test)]
#[path = "message_test.rs"]
mod message_test;
