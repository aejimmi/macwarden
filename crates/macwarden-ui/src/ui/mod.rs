//! GPUI view layer (macOS-only).
//!
//! The [`Panel`](panel::Panel) entity owns the pure view-model state and a
//! boxed [`PanelSource`](crate::data::source::PanelSource); the tab and detail
//! renderers are split across the sibling modules to stay under the 500-line
//! file limit. gpui-component is deliberately not used — the few controls the
//! panel needs live in [`widgets`].

mod allowlist;
mod apps_tab;
mod body;
mod detail;
mod detail_ob;
mod detail_sections;
mod enforce;
mod ensure;
mod filter;
mod header;
mod icons;
mod live;
mod live_build;
mod panel;
mod policy;
mod policy_menu;
mod procs_tab;
mod rollup;
mod rules_view;
mod statusbar;
mod theme;
mod trace_detail;
mod trace_list;
mod trace_view;
mod widgets;

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use ipc::client::{ExpectedOwner, Selection, connect};

use crate::data::daemon::DaemonSource;
use crate::data::demo::DemoSource;
use crate::data::select::{SourceSelection, selection_status};
use crate::data::source::{DaemonRetry, PanelSource};
use live::LiveSource;

/// The root daemon's Unix-socket path (R1). The panel authenticates the daemon
/// by requiring this socket to be root-owned under a root-only-writable parent.
const ROOT_DAEMON_SOCKET: &str = "/var/run/macwarden/macwarden.sock";

/// A daemon socket candidate: its path and the owner the panel requires it to
/// have (R2 client-side check).
struct SocketCandidate {
    path: PathBuf,
    owner: ExpectedOwner,
}

/// Candidate daemon sockets in preference order: the user-agent socket
/// (`~/.macwarden/macwarden.sock`, owned by this user) first — it needs no root
/// and is the default deployment while the root LaunchDaemon path is pending —
/// then the root socket at `/var/run`.
fn socket_candidates() -> Vec<SocketCandidate> {
    use std::os::unix::fs::MetadataExt;

    let mut candidates = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let home = PathBuf::from(home);
        // The user-agent socket must be owned by whoever owns $HOME (this user);
        // read that uid from $HOME's metadata rather than a `geteuid` syscall.
        if let Ok(uid) = std::fs::metadata(&home).map(|m| m.uid()) {
            candidates.push(SocketCandidate {
                path: home.join(".macwarden/macwarden.sock"),
                owner: ExpectedOwner::Uid(uid),
            });
        }
    }
    candidates.push(SocketCandidate {
        path: PathBuf::from(ROOT_DAEMON_SOCKET),
        owner: ExpectedOwner::Root,
    });
    candidates
}

/// Launch the panel. The default prefers the macwarden daemon and falls back to
/// the `nettop` live source when it is absent or version-incompatible; pass
/// `demo = true` for the deterministic demo stream (screenshots, offline dev).
pub fn launch(demo: bool) {
    let (source, selection) = if demo {
        (
            Box::new(DemoSource::new()) as Box<dyn PanelSource>,
            SourceSelection::Demo,
        )
    } else {
        build_source()
    };
    tracing::info!(source = selection.label(), "macwarden-ui: source selected");
    // Only the real (non-demo) panel retries the daemon: if the panel launched
    // on the read-only fallback (daemon absent/slow at start), it keeps trying in
    // the background and hot-swaps to the daemon source once it is healthy.
    let retry: Option<DaemonRetry> = if demo {
        None
    } else {
        let version = env!("CARGO_PKG_VERSION");
        Some(Box::new(move || retry_daemon_source(version)))
    };
    panel::open(source, retry);
}

/// One background daemon-reconnect attempt for the panel's fallback retry.
///
/// Runs a single [`connect_daemon`] round and, on a successful handshake, returns
/// a fresh [`DaemonSource`] boxed for the panel to adopt. `None` when the daemon
/// is still unreachable or version-incompatible — the panel keeps its fallback.
fn retry_daemon_source(version: &str) -> Option<Box<dyn PanelSource>> {
    match connect_daemon(version) {
        DaemonAttempt::Connected(source, selection) => {
            tracing::info!(
                source = selection.label(),
                "macwarden-ui: daemon reachable; hot-swapping off the fallback source"
            );
            Some(source)
        }
        DaemonAttempt::Incompatible(_) | DaemonAttempt::Absent => None,
    }
}

/// The outcome of one round of daemon-connection attempts across all socket
/// candidates.
enum DaemonAttempt {
    /// A candidate handshook and version-matched — the live source is ready.
    Connected(Box<dyn PanelSource>, SourceSelection),
    /// A candidate was reachable but protocol-incompatible — a daemon exists
    /// (so don't auto-spawn), fall back read-only with the "out of date" status.
    Incompatible(SourceSelection),
    /// No candidate socket was reachable — the daemon is absent.
    Absent,
}

/// Try the daemon first (R8); if none is reachable, auto-ensure one (dev mode)
/// before falling back to the `nettop` [`LiveSource`]. Returns the boxed source
/// paired with the [`SourceSelection`] status the header can surface.
fn build_source() -> (Box<dyn PanelSource>, SourceSelection) {
    let version = env!("CARGO_PKG_VERSION");
    match connect_daemon(version) {
        DaemonAttempt::Connected(source, status) => return (source, status),
        DaemonAttempt::Incompatible(status) => return (Box::new(LiveSource::new()), status),
        DaemonAttempt::Absent => {}
    }

    // No daemon reachable. Auto-ensure one for a single-launch dev UX: spawn the
    // sibling `macwarden serve` detached, then poll the socket. The daemon
    // persists after the panel quits — a firewall keeps running (see `ensure`).
    if ensure::spawn_daemon() {
        if let DaemonAttempt::Connected(source, status) = poll_daemon(version) {
            return (source, status);
        }
        tracing::warn!("spawned daemon did not come up in time; using nettop live fallback");
    }

    (Box::new(LiveSource::new()), SourceSelection::Fallback)
}

/// One round of connection attempts across every socket candidate (R8). Returns
/// the first live [`DaemonSource`], else records whether any candidate was
/// merely incompatible (a daemon exists) versus fully absent.
fn connect_daemon(version: &str) -> DaemonAttempt {
    let mut incompatible: Option<SourceSelection> = None;
    for candidate in socket_candidates() {
        if !candidate.path.exists() {
            continue;
        }
        let selection = connect(candidate.path.clone(), candidate.owner, version);
        let status = selection_status(&selection);
        match selection {
            Selection::Client(handle) => {
                let reconnect =
                    reconnect_closure(candidate.path.clone(), candidate.owner, version.to_string());
                // A second, independent connect factory for per-app traces: each
                // trace runs on its own dedicated `ipc` connection (R11).
                let trace_connect =
                    reconnect_closure(candidate.path, candidate.owner, version.to_string());
                match DaemonSource::from_handle(handle, reconnect, trace_connect) {
                    Ok(source) => return DaemonAttempt::Connected(Box::new(source), status),
                    Err(e) => {
                        tracing::warn!(%e, "daemon source failed to start; using live fallback");
                    }
                }
            }
            Selection::Incompatible { .. } => incompatible = Some(status),
            Selection::Unavailable | Selection::Untrusted => {}
        }
    }
    match incompatible {
        Some(status) => DaemonAttempt::Incompatible(status),
        None => DaemonAttempt::Absent,
    }
}

/// Poll for a freshly spawned daemon to bind its socket and finish its
/// handshake: retry [`connect_daemon`] with a short fixed backoff for up to ~5s.
fn poll_daemon(version: &str) -> DaemonAttempt {
    const ATTEMPTS: u32 = 25;
    const BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);
    for _ in 0..ATTEMPTS {
        std::thread::sleep(BACKOFF);
        if let DaemonAttempt::Connected(source, status) = connect_daemon(version) {
            return DaemonAttempt::Connected(source, status);
        }
    }
    DaemonAttempt::Absent
}

/// Build the `DaemonSource` reconnect closure: re-run connect+handshake against
/// the same socket and yield a fresh post-handshake stream, or `None` when the
/// daemon is unreachable or incompatible.
fn reconnect_closure(
    path: PathBuf,
    owner: ExpectedOwner,
    version: String,
) -> Box<dyn FnMut() -> Option<UnixStream> + Send> {
    Box::new(
        move || match connect(path.clone(), owner, version.clone()) {
            Selection::Client(handle) => Some(handle.into_connection()),
            _ => None,
        },
    )
}
