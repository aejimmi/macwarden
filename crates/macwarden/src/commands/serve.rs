//! `macwarden serve` — run the daemon IPC server in the foreground.
//!
//! Binds the user-agent Unix socket and serves the GPUI panel until SIGTERM or
//! SIGINT. This is the standalone entry point for the Phase 10 IPC server; the
//! same server is also started alongside the enforcement loop by `macwarden
//! watch` (see [`crate::commands::monitor`]).

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use anyhow::{Context, Result};

use crate::daemon::ipc_server::{self, ServerConfig};

/// Run the IPC server foreground until a termination signal arrives.
pub fn run() -> Result<()> {
    let shutdown = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(sig, Arc::clone(&shutdown))
            .context("failed to register signal handler")?;
    }

    let config = ServerConfig::user_agent()?;
    // Fast pre-check for nicer messaging: if a live daemon already answers on the
    // socket, say so and exit before printing the "listening" banner. The
    // authoritative, race-safe guard is still the connect-probe inside
    // `ipc_server::serve` (which also handles a socket that appears between here
    // and the bind).
    if UnixStream::connect(&config.socket_path).is_ok() {
        println!(
            "macwarden: daemon already running on {}; leaving it in place",
            config.socket_path.display()
        );
        return Ok(());
    }
    println!(
        "macwarden IPC server — listening on {}",
        config.socket_path.display()
    );
    println!("Press Ctrl+C to stop.\n");
    ipc_server::serve(&config, &shutdown)
}
