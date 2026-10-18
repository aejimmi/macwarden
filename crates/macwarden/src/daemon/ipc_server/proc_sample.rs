//! Per-process CPU and memory sampling via `sysinfo`, persisted across snapshots.
//!
//! `nettop` (the daemon's connection source) reports bytes but not CPU or
//! memory, so a daemon-backed panel showed every process at 0% CPU / 0 B — the
//! panel's own `LiveSource` had real numbers from `sysinfo`, the daemon path did
//! not. This sampler holds one long-lived [`System`] and refreshes it on the scan
//! cadence, mapping each pid to its live CPU percent and resident memory so the
//! snapshot builder can stamp them onto the proc rows and groups.
//!
//! # The double-refresh requirement
//!
//! `sysinfo` derives per-process CPU from the delta between two refreshes taken
//! at least [`MINIMUM_CPU_UPDATE_INTERVAL`] apart; refreshing faster reports 0%.
//! An earlier panel bug had CPU stuck at 0 from refreshing too fast. The sampler
//! defends against this by refreshing only when that interval has elapsed since
//! the last refresh — a sample that arrives too soon reuses the last refresh's
//! values (stale, but never a spurious 0). The baseline refresh happens at
//! construction, so the first *due* sample already carries a real CPU delta.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use sysinfo::{MINIMUM_CPU_UPDATE_INTERVAL, ProcessRefreshKind, ProcessesToUpdate, System};

/// A pid's live resource sample.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProcStat {
    /// CPU usage percent (may exceed 100 when a process spans multiple cores).
    /// Meaningful only when [`Self::stats_known`] is `true`.
    pub cpu: f32,
    /// Resident memory in bytes. Meaningful only when [`Self::stats_known`].
    pub mem_bytes: u64,
    /// Whether CPU/memory were actually readable (`mem_bytes > 0`). The
    /// unprivileged daemon can't read task info for root-owned / hardened-runtime
    /// processes, so those report `false` and the panel renders "—". The uid,
    /// however, *is* readable for every process, so [`Self::user`] is still
    /// resolved — which is why user and stats are tracked independently.
    pub stats_known: bool,
    /// Owning username, resolved from the process uid at sample time (so the
    /// detail path never pays a per-request lookup). `None` when the uid is
    /// unknown or unresolvable (process gone / uid absent from the users table).
    pub user: Option<String>,
}

/// A long-lived `sysinfo` sampler refreshed on the scan cadence.
///
/// One instance lives for the daemon's lifetime (owned by the scanner) so CPU
/// deltas accumulate across snapshots rather than resetting each request.
pub struct ProcSampler {
    inner: Mutex<Inner>,
}

/// The guarded sampler state: the persistent system and its last refresh instant.
struct Inner {
    system: System,
    last_refresh: Option<Instant>,
}

impl std::fmt::Debug for ProcSampler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcSampler").finish_non_exhaustive()
    }
}

impl Default for ProcSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcSampler {
    /// Build a sampler and take the baseline refresh. CPU reads as the delta from
    /// this point on the next *due* [`Self::sample`].
    #[must_use]
    pub fn new() -> Self {
        let mut system = System::new();
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::everything(),
        );
        Self {
            inner: Mutex::new(Inner {
                system,
                last_refresh: Some(Instant::now()),
            }),
        }
    }

    /// Map each live pid to its current CPU percent, resident memory, a
    /// `stats_known` flag, and its owning username.
    ///
    /// CPU/memory readability is flagged (not filtered): `memory() == 0` means
    /// `sysinfo`'s `task_for_pid` failed — the unprivileged daemon cannot read
    /// task info for root-owned or hardened-runtime processes — so `stats_known`
    /// is `false` and the panel renders "—" instead of a fabricated `0`. The uid,
    /// by contrast, is basic process info readable for *every* process, so the
    /// username still resolves (`root` for system daemons); user is kept even when
    /// stats are not, which is why they are separate fields.
    ///
    /// Refreshes only when [`MINIMUM_CPU_UPDATE_INTERVAL`] has elapsed since the
    /// last refresh, so a burst of snapshots never collapses CPU to 0; a sample
    /// arriving too soon reuses the prior refresh's still-valid values. A
    /// poisoned lock yields an empty map (all stats degrade to "unknown").
    #[must_use]
    pub fn sample(&self) -> HashMap<u32, ProcStat> {
        let Ok(mut inner) = self.inner.lock() else {
            return HashMap::new();
        };
        let due = inner
            .last_refresh
            .is_none_or(|at| at.elapsed() >= MINIMUM_CPU_UPDATE_INTERVAL);
        if due {
            inner.system.refresh_processes_specifics(
                ProcessesToUpdate::All,
                true,
                ProcessRefreshKind::everything(),
            );
            inner.last_refresh = Some(Instant::now());
        }
        inner
            .system
            .processes()
            .iter()
            .map(|(pid, proc)| {
                let pid = pid.as_u32();
                let mem_bytes = proc.memory();
                // The uid is readable for every process (even root-owned) via
                // sysctl, unlike task info — so the owner resolves regardless of
                // whether cpu/mem could be read.
                let user = super::proc_owner::owner_username(pid);
                (
                    pid,
                    ProcStat {
                        cpu: proc.cpu_usage(),
                        mem_bytes,
                        // Zero resident memory ⇒ task info unreadable ⇒ unknown.
                        stats_known: mem_bytes > 0,
                        user,
                    },
                )
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "proc_sample_test.rs"]
mod proc_sample_test;
