//! The [`PanelSource`] abstraction that feeds the panel.
//!
//! Two implementations ship in v0: [`super::demo::DemoSource`] (deterministic
//! fake stream, the default) and the macOS-only `LiveProcSource` (real process
//! list). A daemon-backed source can slot in behind the same trait later.

use std::path::PathBuf;
use std::sync::Arc;

use ipc::protocol::{RuleTarget, WireAllowEntry, WireMode, WireProfile};

use super::model::{AppRow, Detail, NetRow, ProcGroup, ProcRow, Totals};
use crate::state::Route;

/// A factory the panel calls on a timer while running on the read-only fallback
/// source. Each call attempts one fresh daemon connect+handshake; a `Some`
/// result is a healthy [`super::daemon::DaemonSource`] the panel hot-swaps in,
/// so a daemon that comes up after launch is adopted without a restart. `None`
/// means the daemon is still unreachable — keep serving the fallback.
pub type DaemonRetry = Box<dyn FnMut() -> Option<Box<dyn PanelSource>>>;

/// A cloneable, `Send + Sync` handle for resolving inspector details and
/// applying rule mutations off the GPUI render thread.
///
/// The panel resolves the inspector detail from a background task on every
/// route push and once per refresh tick. Sources whose detail and mutation
/// calls are cheap and non-blocking (demo, `nettop` live) return `None` from
/// [`PanelSource::detail_backend`] — the panel then resolves them inline on
/// that task. [`super::daemon::DaemonSource`] returns a handle wrapping its
/// command channel, so its blocking socket round-trip runs on the background
/// executor rather than pinning the render thread for up to the query timeout.
pub trait DetailBackend: Send + Sync {
    /// Resolve the inspector [`Detail`] for a pushed [`Route`], if it still
    /// exists. Called from the panel's background fetch task.
    fn detail(&self, route: &Route) -> Option<Detail>;

    /// Apply a block/unblock mutation, returning whether a live policy backend
    /// actually applied it (so the panel can reconcile its optimistic toggle).
    fn set_rule(&self, target: &RuleTarget, allow: bool) -> bool;

    /// Apply a **batch** of block/unblock changes as one mutation (e.g. a
    /// whole-group toggle), returning whether the daemon applied it. The default
    /// falls back to applying each change individually, so sources that don't
    /// implement batching still work.
    fn set_rules(&self, changes: &[(RuleTarget, bool)]) -> bool {
        let mut applied = false;
        for (target, allow) in changes {
            applied |= self.set_rule(target, *allow);
        }
        applied
    }
}

/// A cloneable, `Send + Sync` handle for reading and mutating the daemon's
/// policy profile (R8) off the GPUI render thread.
///
/// Every call is a blocking socket round-trip serialized on the daemon worker's
/// one connection, so the panel moves it onto its background executor exactly
/// like [`DetailBackend`]. Each mutation echoes the full [`WireProfile`] the
/// daemon committed (from its `ProfileAck`), so the panel reconciles its
/// optimistic edit against ground truth; `None` means the daemon rejected the
/// mutation or the connection was lost, and the caller should re-fetch.
///
/// Only [`super::daemon::DaemonSource`] with the `Policy` capability exposes one
/// (via [`PanelSource::policy_backend`]); demo / `nettop` live sources return
/// `None`, so the panel renders the policy controls disabled.
pub trait PolicyBackend: Send + Sync {
    /// Read the current policy profile.
    fn get_profile(&self) -> Option<WireProfile>;

    /// Set the global Allow-All / Block-All mode; echoes the new profile.
    fn set_mode(&self, mode: WireMode) -> Option<WireProfile>;

    /// Toggle "Allow Apple programs"; echoes the new profile.
    fn set_apple_allow(&self, allow: bool) -> Option<WireProfile>;

    /// Toggle "Allow DNS traffic"; echoes the new profile.
    fn set_dns_allow(&self, allow: bool) -> Option<WireProfile>;

    /// Enable/disable a built-in network group; echoes the new profile.
    fn set_group_enabled(&self, group: String, enabled: bool) -> Option<WireProfile>;

    /// Add an allow-list exception; echoes the new profile (or `None` when the
    /// daemon rejects the entry, e.g. an invalid host).
    fn add_allow_entry(&self, entry: WireAllowEntry) -> Option<WireProfile>;

    /// Remove an allow-list exception by normalized value; echoes the new profile.
    fn remove_allow_entry(&self, entry: WireAllowEntry) -> Option<WireProfile>;
}

/// A cloneable, `Send + Sync` handle for starting a per-app packet trace (R11).
///
/// A trace runs over a **dedicated** `ipc` connection, separate from the
/// snapshot worker, so the live packet push never contends with the ~1 Hz
/// snapshot polling. [`Self::start_trace`] opens that connection (via the
/// source's connect factory), sends `Subscribe{[Packet]}` + `StartTrace`, and
/// returns a [`super::trace::TraceSession`] the panel drains and queries off the
/// render thread. Only sources that can actually capture return one:
/// [`super::daemon::DaemonSource`] gated on [`ipc::protocol::Capability::Trace`],
/// and the demo source's synthetic stream.
#[cfg(unix)]
pub trait TraceBackend: Send + Sync {
    /// Begin a trace for `app_id`, or `None` if the session cannot be started
    /// (connection lost, capture unavailable).
    fn start_trace(&self, app_id: &str) -> Option<super::trace::TraceSession>;
}

/// A snapshot provider for the panel. Implementations own their state and
/// advance it on [`PanelSource::tick`] (called at ~1 Hz by the view).
pub trait PanelSource {
    /// Short human label for the active source (`demo` / `live`).
    fn name(&self) -> &'static str;

    /// Whether this source reflects the real machine rather than demo data.
    /// Drives honesty affordances (rate footer, "since launch" scopes).
    fn is_live(&self) -> bool {
        false
    }

    /// Whether network block toggles enforce **live** rather than merely
    /// previewing. `true` only when the source is backed by a daemon that
    /// advertises [`ipc::protocol::Capability::NetworkEnforcement`] — i.e. the
    /// NetworkExtension content filter is genuinely activated and enabled (spec
    /// 009 R4). The default is `false`: demo and `nettop`-live sources have no
    /// enforcement backend, so the panel keeps its "preview only" honesty hint.
    fn enforcement_active(&self) -> bool {
        false
    }

    /// Advance the simulation / re-sample the system by one step.
    fn tick(&mut self);

    /// A monotonic version that changes **only** when the displayed snapshot
    /// content changes. `None` (the default) means the source cannot tell, so
    /// the panel always re-renders on its refresh tick. Live sources whose data
    /// is often idle override this so the panel can skip a full window
    /// layout+paint for a tick whose snapshot is byte-for-byte unchanged.
    fn content_version(&self) -> Option<u64> {
        None
    }

    /// Current Apps-tab rows, most active first.
    fn apps(&self) -> Vec<AppRow>;

    /// The Apps-tab row count. The default clones the row vector via
    /// [`Self::apps`]; live sources override this to read the cached length
    /// directly, so the header count does not deep-clone every render.
    fn app_count(&self) -> usize {
        self.apps().len()
    }

    /// Current Network-tab flat destination rows.
    fn net_rows(&self) -> Vec<NetRow>;

    /// Current Processes-tab rows.
    fn procs(&self) -> Vec<ProcRow>;

    /// Current Processes-tab rows grouped by responsible app. The default wraps
    /// each process as its own one-member group; the live source overrides this
    /// to roll helpers up under their owning app.
    fn proc_groups(&self) -> Vec<ProcGroup> {
        self.procs().into_iter().map(ProcGroup::singleton).collect()
    }

    /// The Processes-tab group count. The default clones the group vector via
    /// [`Self::proc_groups`]; live sources override this to read the cached
    /// length directly, so the header count does not deep-clone every render.
    fn proc_group_count(&self) -> usize {
        self.proc_groups().len()
    }

    /// Footer totals.
    fn totals(&self) -> Totals;

    /// Build the inspector detail for an app by its id, if it still exists.
    fn app_detail(&self, id: &str) -> Option<Detail>;

    /// Build the inspector detail for a process by its id.
    fn proc_detail(&self, id: &str) -> Option<Detail>;

    /// Build the inspector detail for a destination by hostname.
    fn domain_detail(&self, host: &str) -> Option<Detail>;

    /// Unique executable paths of the binaries this source currently knows are
    /// running. Feeds the background openbinary sweep; the default is empty so
    /// non-live sources (demo) never trigger network work.
    fn binary_paths(&self) -> Vec<PathBuf> {
        Vec::new()
    }

    /// Push a block/unblock mutation to a live policy backend, returning whether
    /// a live backend applied it. The default (demo, `nettop` live) returns
    /// `false` — they have no daemon to mutate, so the panel keeps its
    /// local-only override state. `DaemonSource` overrides this to send a
    /// `SetRule` request over the IPC connection.
    fn set_rule(&self, _target: &RuleTarget, _allow: bool) -> bool {
        false
    }

    /// A cloneable, `Send + Sync` handle the panel can move onto its background
    /// executor to resolve details and apply rules off the render thread. The
    /// default returns `None`: demo and `nettop` live detail calls are cheap
    /// clones, so the panel resolves them inline on its fetch task instead.
    /// `DaemonSource` overrides this to expose its command channel, moving the
    /// blocking socket round-trip off the render thread.
    fn detail_backend(&self) -> Option<Arc<dyn DetailBackend>> {
        None
    }

    /// A cloneable, `Send + Sync` handle for reading and mutating the daemon's
    /// policy profile off the render thread (R8). The default returns `None`:
    /// demo and `nettop` live sources have no daemon to drive, so the panel
    /// renders the mode / allow-list / group controls disabled.
    /// [`super::daemon::DaemonSource`] overrides this to expose its command
    /// channel when the daemon advertises [`ipc::protocol::Capability::Policy`].
    fn policy_backend(&self) -> Option<Arc<dyn PolicyBackend>> {
        None
    }

    /// A cloneable handle for starting a per-app packet trace (R11), or `None`
    /// when the source cannot capture. The panel gates the "Trace" action on
    /// this: the demo source always offers a synthetic stream, and
    /// [`super::daemon::DaemonSource`] offers one only when the daemon advertises
    /// [`ipc::protocol::Capability::Trace`].
    #[cfg(unix)]
    fn trace_backend(&self) -> Option<Arc<dyn TraceBackend>> {
        None
    }
}
