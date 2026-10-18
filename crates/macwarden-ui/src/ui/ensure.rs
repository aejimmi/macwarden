//! Dev-mode daemon auto-ensure (macOS).
//!
//! At this stage the daemon runs as the *user* on `~/.macwarden/macwarden.sock`
//! (no root, ES enforcement still a placeholder), so the panel can start it
//! itself — "just open the panel" instead of a two-terminal dance. The panel and
//! the daemon are the **same binary**: when no daemon is reachable, the panel
//! re-invokes its own executable ([`std::env::current_exe`]) with the `serve`
//! subcommand, detached, and polls for the socket. The daemon deliberately
//! **outlives** the panel: a firewall keeps running after the panel's ✕ hides it
//! and after Quit. A future signed build installs `macwarden serve` as a
//! LaunchDaemon (via SMAppService) which replaces this dev auto-spawn.
//!
//! Singleton is enforced by the daemon's own bind path, not here: before binding
//! it probes the socket with a connect, and if a live daemon answers it exits
//! with an "already running" status instead of stealing the path — so a spawned
//! duplicate steps aside and the panel connects to the existing daemon. We never
//! kill an existing daemon.

use std::path::Path;
use std::process::{Command, Stdio};

/// Build the detached `<bin> serve` command.
///
/// Pure — configures but does not spawn — so the arg wiring and stdio/process
/// group setup are unit-testable without launching a process. The child is
/// placed in its own process group ([`CommandExt::process_group`]) with all
/// stdio redirected to `/dev/null`, so terminal signals aimed at the panel don't
/// reach it and it isn't tied to the panel's console.
#[must_use]
fn daemon_command(bin: &Path) -> Command {
    use std::os::unix::process::CommandExt;

    let mut cmd = Command::new(bin);
    cmd.arg("serve")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .process_group(0);
    cmd
}

/// Spawn `macwarden serve` detached so the panel becomes a single launch.
///
/// The daemon is the same binary as the panel, so we re-invoke our own
/// executable ([`std::env::current_exe`]) with the `serve` subcommand. We do
/// **not** wait on it — it is meant to outlive the panel, and when the panel
/// exits the child reparents to `launchd`, which reaps it (no zombie). Returns
/// `true` when a process was launched; `false` when the current executable
/// cannot be resolved or the spawn failed, in which case the caller stays on the
/// read-only `nettop` source.
#[must_use]
pub(crate) fn spawn_daemon() -> bool {
    let bin = match std::env::current_exe() {
        Ok(bin) => bin,
        Err(e) => {
            tracing::warn!(
                %e,
                "could not resolve the current executable to spawn `macwarden serve`; \
                 running read-only (nettop live source). Start `macwarden serve` manually."
            );
            return false;
        }
    };

    match daemon_command(&bin).spawn() {
        Ok(child) => {
            tracing::info!(
                bin = %bin.display(),
                pid = child.id(),
                "spawned `macwarden serve` (dev auto-ensure; daemon persists after panel quits)"
            );
            true
        }
        Err(e) => {
            tracing::warn!(%e, bin = %bin.display(), "failed to spawn macwarden daemon; running read-only");
            false
        }
    }
}

#[cfg(test)]
#[path = "ensure_test.rs"]
mod ensure_test;
