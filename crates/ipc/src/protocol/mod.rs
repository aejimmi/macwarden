//! The frozen wire protocol: message enums, DTOs, capabilities, error kinds.
//!
//! Serde format is JSON-lines (see [`crate::codec`]). Version compatibility is a
//! single integer ([`PROTOCOL_VERSION`]); within one integer, `#[serde(default)]`
//! on struct fields absorbs additive field drift, so a newer daemon can add a
//! field without breaking an older panel.

mod dto;
mod message;

pub use dto::{
    ExecTarget, HistoryBucket, HistoryScope, RuleTarget, WireAllowEntry, WireAppProto, WireAppRow,
    WireBan, WireDecodeNode, WireDecodeTree, WireDetail, WireDirection, WireDomainRow,
    WireDuration, WireFlow, WireGroupState, WireL4Proto, WireMode, WireNetRow, WirePacketBytes,
    WirePacketRecord, WireProcGroup, WireProcRow, WireProfile, WireRuleChange, WireSignature,
    WireTotals, WireTraceSource, WireVerdict,
};
pub use message::{Event, EventKind, Request, Response, ServerFrame};

use serde::{Deserialize, Serialize};

/// The single integer that gates protocol compatibility. Equal integers are
/// compatible; any difference is incompatible (no minor/patch split). Bump this
/// only for a non-additive change — additive field drift is absorbed by
/// `#[serde(default)]` within one version.
pub const PROTOCOL_VERSION: u32 = 1;

/// An optional daemon feature advertised in [`Response::Welcome`]. The panel
/// feature-detects against this list rather than against version numbers, so a
/// daemon can withhold a feature (e.g. `ExecPolicy` when the ES exec tier is
/// inactive) without a version bump.
///
/// Forward-compatible: an unrecognized capability string deserializes to
/// [`Capability::Unknown`] and is ignored rather than failing the handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// The daemon answers [`Request::GetHistory`] from the metrics store.
    History,
    /// The daemon supports [`Request::Subscribe`] server-push [`Event`]s.
    PushEvents,
    /// The daemon accepts [`Request::SetRule`] mutations.
    Mutations,
    /// The daemon supports [`Request::SetExecPolicy`] (ES exec tier active).
    ExecPolicy,
    /// The daemon fills detail `openbinary` lines from its inventory cache.
    Openbinary,
    /// The daemon answers [`Request::GetProfile`] and the profile mutations
    /// (`SetMode`, `SetGroupEnabled`, allow-list edits, …) and hot-reloads the
    /// live rule set on each (R7).
    Policy,
    /// The daemon has a live BPF capture backend and can serve
    /// [`Request::StartTrace`] / [`Request::GetPacketBytes`] and push
    /// [`Event::Packet`] frames (R8/R12). Advertised only when the daemon
    /// actually has BPF access.
    Trace,
    /// The NetworkExtension content filter is **actually activated and enabled**,
    /// so app/domain block toggles enforce live rather than merely previewing.
    /// Advertised only when the daemon's `systemextensionsctl` probe reports the
    /// filter live (spec 009 R2/R3) — never on ambiguity, so the panel's honesty
    /// hint is trustworthy.
    NetworkEnforcement,
    /// The daemon runs the banwatch scanner-protection engine and answers
    /// [`Request::GetBans`] / [`Request::SetBan`], pushing [`Event::IpBanned`] /
    /// [`Event::IpUnbanned`] under [`EventKind::BanChanged`] (spec 010 R8).
    BanWatch,
    /// An unrecognized capability from a newer daemon — ignored by the panel.
    #[serde(other)]
    Unknown,
}

/// The failure category carried by [`Response::Error`]. Forward-compatible: an
/// unrecognized kind from a newer daemon deserializes to [`ErrorKind::Unknown`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// The frame was not valid JSON or failed boundary validation (R9).
    BadRequest,
    /// The peer failed the R2 uid / code-signature authentication.
    Unauthorized,
    /// A non-`Hello` request arrived on a version-mismatched connection (R3).
    VersionMismatch,
    /// The requested feature is not advertised in this daemon's capabilities.
    Unsupported,
    /// The per-connection request rate limit was exceeded (R9).
    RateLimited,
    /// The daemon is temporarily at capacity (the connection cap is full) and
    /// dropped this peer. Transient — the client should back off and retry
    /// rather than treat it as a hard failure (R1/R9).
    Unavailable,
    /// The request was well-formed but refused (e.g. exec-deny of a critical
    /// binary, R7), or an internal daemon error occurred.
    Refused,
    /// An unrecognized error kind from a newer daemon.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
#[path = "mod_test.rs"]
mod mod_test;
