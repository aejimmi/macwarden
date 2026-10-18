//! Source-selection status (R8): which source the panel picked and why.
//!
//! The concrete wiring — connecting the socket, building a `DaemonSource`, or
//! falling back to the macOS-only `LiveSource` — lives in the `ui` module (it
//! needs the platform sources). What lives here is the *pure* decision surface:
//! a status enum the panel header can read, and [`selection_status`], which maps
//! an `ipc` [`Selection`] onto that status. Keeping the mapping pure means every
//! branch is unit-testable on Linux CI without a socket, root, or `LiveSource`.

use ipc::client::Selection;

/// Which source backs the panel, surfaced so the header can show it (R8). The
/// panel decides presentation; this only names the outcome and carries the
/// daemon version for the "out of date" affordance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceSelection {
    /// The daemon was reachable and version-compatible — live verdicts,
    /// history, and mutations are all real.
    Daemon {
        /// The daemon's build version.
        daemon_version: String,
    },
    /// The daemon was absent or untrusted — the panel uses the `nettop`
    /// `LiveSource` fallback (verdict `Allow` only, session-scope history).
    Fallback,
    /// The daemon was reachable but protocol-incompatible — the panel falls
    /// back read-only and surfaces a "daemon out of date" affordance.
    Incompatible {
        /// The daemon's build version, for the affordance.
        daemon_version: String,
    },
    /// The deterministic demo stream, only under an explicit `--demo` flag.
    Demo,
}

impl SourceSelection {
    /// A short label for the header / logs.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            SourceSelection::Daemon { .. } => "daemon",
            SourceSelection::Fallback => "live",
            SourceSelection::Incompatible { .. } => "live (daemon out of date)",
            SourceSelection::Demo => "demo",
        }
    }

    /// Whether the picked source is the live daemon.
    #[must_use]
    pub fn is_daemon(&self) -> bool {
        matches!(self, SourceSelection::Daemon { .. })
    }
}

/// Map an `ipc` [`Selection`] onto a [`SourceSelection`] status (R8). Pure — the
/// caller turns the status into a concrete boxed source. `--demo` is decided
/// before any connection, so it never appears here.
#[must_use]
pub fn selection_status<C>(selection: &Selection<C>) -> SourceSelection {
    match selection {
        Selection::Client(handle) => SourceSelection::Daemon {
            daemon_version: handle.daemon_version().to_string(),
        },
        Selection::Unavailable | Selection::Untrusted => SourceSelection::Fallback,
        Selection::Incompatible { daemon_version } => SourceSelection::Incompatible {
            daemon_version: daemon_version.clone(),
        },
    }
}

#[cfg(test)]
#[path = "select_test.rs"]
mod select_test;
