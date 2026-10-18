//! Best-effort filesystem hardening for macwarden's on-disk state.
//!
//! Rule files, the policy config, and the shield config all live under
//! `~/.macwarden/` and describe what this host allows, blocks, and observes on
//! the network — sensitive enough that no other local user should read them.
//! These helpers tighten a directory to `0700` and a file to `0600` on Unix; on
//! other platforms they are no-ops. A refused chmod is logged, never fatal — a
//! config that wrote must still be usable even if the permission tweak fails.

use std::path::Path;

use tracing::warn;

/// Tighten `dir` to `0700` (owner-only access) on Unix; no-op elsewhere.
pub fn secure_dir(dir: &Path) {
    set_mode(dir, 0o700, "dir");
}

/// Tighten `file` to `0600` (owner-only read/write) on Unix; no-op elsewhere.
pub fn secure_file(file: &Path) {
    set_mode(file, 0o600, "file");
}

/// Apply `mode` to `path`, logging a warning on failure. `kind` is only used for
/// the log message.
fn set_mode(path: &Path, mode: u32, kind: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
            warn!(path = %path.display(), %e, "failed to set {mode:o} on {kind}");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode, kind);
    }
}

#[cfg(test)]
#[path = "fsperm_test.rs"]
mod fsperm_test;
