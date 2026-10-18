//! Socket binding and the accept loop (R1, R2, R9).
//!
//! Binds a `SOCK_STREAM` Unix socket with `0600` perms after an unlink-then-bind
//! and a parent-directory ownership check, then accepts connections, authenticates
//! each peer via the injected [`PeerVerifier`] (the uid pre-gate today; the macOS
//! code-signature check grafts into the same trait), and hands authorized peers
//! to a bounded pool of per-connection threads. The loop is non-blocking so it
//! polls the shutdown flag and exits cleanly on SIGTERM/SIGINT.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use ipc::codec::write_message;
use ipc::protocol::{ErrorKind, Response};
use ipc::server::{PeerVerifier, verify_stream};
use tracing::{debug, error, info, warn};

use super::conn::serve_connection;
use super::error::{Result, ServerError};
use super::state::ServerState;

/// Maximum concurrent connections (R1/R9). Sized so a brief burst of panel
/// reconnects (each pinning a handler thread until its read timeout) cannot
/// exhaust the pool and deafen the daemon.
const MAX_CONNECTIONS: usize = 32;

/// How often the non-blocking accept loop polls the shutdown flag.
const ACCEPT_POLL: Duration = Duration::from_millis(200);

/// Bind the server socket: unlink-then-bind, `0600`, parent-ownership check (R1).
///
/// Refuses to bind if the parent directory is not owned by the daemon's euid,
/// which is what makes a root-path socket unforgeable by a non-root process.
pub fn bind_socket(path: &Path) -> Result<UnixListener> {
    let parent = path
        .parent()
        .ok_or_else(|| ServerError::Socket("socket path has no parent".to_owned()))?;
    std::fs::create_dir_all(parent).map_err(|e| ServerError::Socket(e.to_string()))?;
    // `~/.macwarden/` holds the ban list, DNS cache, rules, and metrics — keep the
    // base dir owner-only so no other local user can traverse into it.
    net::secure_dir(parent);

    let meta = std::fs::metadata(parent).map_err(|e| ServerError::Socket(e.to_string()))?;
    if meta.uid() != current_euid() {
        return Err(ServerError::ParentOwnership);
    }

    // Singleton guard: never steal the path from a *live* daemon. If something
    // accepts a connection on this socket, a daemon is already running — refuse
    // to bind so this instance exits and the panel connects to the existing one.
    // Only a stale socket (connect refused / not found) is safe to unlink.
    if UnixStream::connect(path).is_ok() {
        return Err(ServerError::AlreadyRunning(path.display().to_string()));
    }
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(ServerError::Socket(e.to_string())),
    }

    let listener = UnixListener::bind(path).map_err(|e| ServerError::Socket(e.to_string()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| ServerError::Socket(e.to_string()))?;
    // TODO(root-daemon): when running as root, chown the socket to the served
    // console user's uid so only that uid can connect (R1/R2). As a user agent
    // the 0600 owner is already the served uid.
    info!(path = %path.display(), "IPC server listening");
    Ok(listener)
}

/// Run the accept loop until `shutdown` is set (R1/R2).
pub fn run_accept_loop<V: PeerVerifier>(
    listener: &UnixListener,
    verifier: &V,
    state: &Arc<ServerState>,
    shutdown: &AtomicBool,
) -> Result<()> {
    listener
        .set_nonblocking(true)
        .map_err(|e| ServerError::Socket(e.to_string()))?;
    let active = Arc::new(AtomicUsize::new(0));

    while !shutdown.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                accept_one(stream, verifier, state, &active);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
            }
            Err(e) => {
                warn!(error = %e, "accept failed");
                thread::sleep(ACCEPT_POLL);
            }
        }
    }
    debug!("IPC accept loop shutting down");
    Ok(())
}

/// Authenticate one accepted peer and dispatch it, honoring the concurrency cap.
fn accept_one<V: PeerVerifier>(
    stream: UnixStream,
    verifier: &V,
    state: &Arc<ServerState>,
    active: &Arc<AtomicUsize>,
) {
    // Accepted streams inherit the listener's non-blocking mode; the connection
    // handler wants a blocking stream with a read timeout.
    if let Err(e) = stream.set_nonblocking(false) {
        debug!(error = %e, "failed to set blocking mode");
        return;
    }

    if let Err(e) = verify_stream(&stream, verifier) {
        debug!(error = %e, "peer authentication failed");
        reject(stream);
        return;
    }

    if active.load(Ordering::Acquire) >= MAX_CONNECTIONS {
        // Never drop silently: tell the peer we are at capacity so it backs off
        // and retries instead of seeing a bare EOF and churn-reconnecting.
        debug!("connection cap reached; replying Unavailable and dropping peer");
        busy(stream);
        return;
    }

    active.fetch_add(1, Ordering::AcqRel);
    let state = Arc::clone(state);
    let active = Arc::clone(active);
    thread::spawn(move || {
        // The slot guard decrements on every exit path — including a panic
        // unwinding out of `serve_connection` — so a handler panic can never
        // permanently leak a connection slot and deafen the daemon.
        let _slot = SlotGuard(active);
        if catch_unwind(AssertUnwindSafe(|| serve_connection(stream, &state))).is_err() {
            error!("connection handler panicked; slot reclaimed");
        }
    });
}

/// Decrements the active-connection counter on drop, so the slot is reclaimed on
/// every handler exit path, including a panic (RAII over the concurrency cap).
struct SlotGuard(Arc<AtomicUsize>);

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Write an `Unauthorized` frame to a rejected peer, then drop the stream (R2).
fn reject(mut stream: UnixStream) {
    let frame = Response::Error {
        kind: ErrorKind::Unauthorized,
        message: "peer not authorized".to_owned(),
    };
    let _ = write_message(&mut stream, &frame);
}

/// Write an `Unavailable` frame to a peer turned away at the connection cap, then
/// drop the stream. The client reads a typed "busy" signal instead of a bare EOF.
fn busy(mut stream: UnixStream) {
    let frame = Response::Error {
        kind: ErrorKind::Unavailable,
        message: "daemon at connection capacity; retry shortly".to_owned(),
    };
    let _ = write_message(&mut stream, &frame);
}

/// The daemon's effective uid.
#[must_use]
#[allow(unsafe_code)]
pub fn current_euid() -> u32 {
    // SAFETY: `geteuid` is always safe — it takes no arguments, reads no memory,
    // and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(all(test, unix))]
#[path = "accept_test.rs"]
mod accept_test;
