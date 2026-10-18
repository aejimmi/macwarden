//! Exhaustive `ipc` wire-DTO → `model.rs` mapping (R3 of the daemon-ipc spec).
//!
//! `ipc` cannot depend on `macwarden-ui`, so this is the panel-side half of the
//! contract the DTO doc-comments freeze. Every `model.rs` field has a DTO source
//! here; the only shape change is `Option<String>` → `Option<PathBuf>` (paths
//! travel as UTF-8 on the wire, converted back with [`PathBuf::from`]). Derived
//! `model.rs` methods — `AppRow::monogram`, `ProcRow::monogram`,
//! `ProcGroup::{monogram, is_group}` — are computed, not stored, so they have no
//! DTO source and are not mapped.

use std::path::PathBuf;

use ipc::protocol::{
    WireAppRow, WireDetail, WireDomainRow, WireFlow, WireNetRow, WireProcGroup, WireProcRow,
    WireSignature, WireTotals, WireVerdict,
};

use super::model::{
    AppRow, Detail, DomainRow, Flow, NetRow, ProcGroup, ProcRow, Signature, Totals, Verdict,
};

/// Convert an optional wire path string into an optional [`PathBuf`]. The one
/// shape change between the wire DTOs and `model.rs`.
fn opt_path(value: Option<String>) -> Option<PathBuf> {
    value.map(PathBuf::from)
}

/// Map a [`WireVerdict`] onto the panel [`Verdict`] (one-to-one).
#[must_use]
pub fn verdict(wire: WireVerdict) -> Verdict {
    match wire {
        WireVerdict::Allow => Verdict::Allow,
        WireVerdict::Blocked => Verdict::Blocked,
        WireVerdict::Tracker => Verdict::Tracker,
    }
}

/// Map a [`WireSignature`] onto the panel [`Signature`] (one-to-one).
#[must_use]
pub fn signature(wire: WireSignature) -> Signature {
    match wire {
        WireSignature::Apple => Signature::Apple,
        WireSignature::DevId(team) => Signature::DevId(team),
        WireSignature::Unsigned => Signature::Unsigned,
    }
}

/// Map a [`WireFlow`] onto the panel [`Flow`] (one-to-one).
#[must_use]
pub fn flow(wire: WireFlow) -> Flow {
    match wire {
        WireFlow::Active(bps) => Flow::Active(bps),
        WireFlow::Session(bytes) => Flow::Session(bytes),
        WireFlow::Zero => Flow::Zero,
        WireFlow::Idle => Flow::Idle,
    }
}

/// Map a [`WireDomainRow`] onto a panel [`DomainRow`].
#[must_use]
pub fn domain_row(wire: WireDomainRow) -> DomainRow {
    DomainRow {
        host: wire.host,
        country: wire.country,
        verdict: verdict(wire.verdict),
        rate_bps: wire.rate_bps,
        total_bytes: wire.total_bytes,
        sockets: wire.sockets,
        allowed: wire.allowed,
    }
}

/// Map a [`WireAppRow`] onto a panel [`AppRow`]. `monogram()` is derived and has
/// no DTO source.
#[must_use]
pub fn app_row(wire: WireAppRow) -> AppRow {
    AppRow {
        id: wire.id,
        name: wire.name,
        bundle_path: opt_path(wire.bundle_path),
        allowed: wire.allowed,
        known_bad: wire.known_bad,
        is_system: wire.is_system,
        down_bytes: wire.down_bytes,
        up_bytes: wire.up_bytes,
        flow: flow(wire.flow),
        domains: wire.domains.into_iter().map(domain_row).collect(),
    }
}

/// Map a [`WireNetRow`] onto a panel [`NetRow`].
#[must_use]
pub fn net_row(wire: WireNetRow) -> NetRow {
    NetRow {
        app_name: wire.app_name,
        app_path: opt_path(wire.app_path),
        domain: domain_row(wire.domain),
    }
}

/// Map a [`WireProcRow`] onto a panel [`ProcRow`]. `monogram()` is derived.
#[must_use]
pub fn proc_row(wire: WireProcRow) -> ProcRow {
    ProcRow {
        id: wire.id,
        name: wire.name,
        bundle_path: opt_path(wire.bundle_path),
        cpu: wire.cpu,
        mem_bytes: wire.mem_bytes,
        net_bps: wire.net_bps,
        net_bytes: wire.net_bytes,
        stats_known: wire.stats_known,
    }
}

/// Map a [`WireProcGroup`] onto a panel [`ProcGroup`]. `monogram()`/`is_group()`
/// are derived.
#[must_use]
pub fn proc_group(wire: WireProcGroup) -> ProcGroup {
    ProcGroup {
        id: wire.id,
        name: wire.name,
        bundle_path: opt_path(wire.bundle_path),
        cpu: wire.cpu,
        mem_bytes: wire.mem_bytes,
        net_bps: wire.net_bps,
        net_bytes: wire.net_bytes,
        stats_known: wire.stats_known,
        procs: wire.procs.into_iter().map(proc_row).collect(),
    }
}

/// Map a [`WireDetail`] onto a panel [`Detail`].
#[must_use]
pub fn detail(wire: WireDetail) -> Detail {
    Detail {
        name: wire.name,
        bundle_id: wire.bundle_id,
        bundle_path: opt_path(wire.bundle_path),
        in_bytes: wire.in_bytes,
        out_bytes: wire.out_bytes,
        path: wire.path,
        user: wire.user,
        signature: signature(wire.signature),
        openbinary: wire.openbinary,
        hostnames: wire.hostnames,
        ips: wire.ips,
        ports: wire.ports,
        allowed_count: wire.allowed_count,
        denied_count: wire.denied_count,
        allowed: wire.allowed,
    }
}

/// Map a [`WireTotals`] onto panel [`Totals`] (one-to-one).
#[must_use]
pub fn totals(wire: WireTotals) -> Totals {
    Totals {
        down_bytes: wire.down_bytes,
        up_bytes: wire.up_bytes,
        trackers_blocked: wire.trackers_blocked,
        connections: wire.connections,
        down_bps: wire.down_bps,
        up_bps: wire.up_bps,
    }
}

#[cfg(test)]
#[path = "map_test.rs"]
mod map_test;
