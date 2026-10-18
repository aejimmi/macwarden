//! Etch-backed crash-safe active-ban store under `~/.macwarden/banwatch/`.
//!
//! Three collections: active bans keyed by `(ip, detector)`, per-IP escalation
//! counters (each carrying its last-ban timestamp so counts can decay), and a
//! metadata map holding the on-disk schema version. Writes go through etch's
//! immediate-mode WAL (each write fsyncs), so no reader ever observes a partial
//! state and the file survives a crash.
//!
//! The **read** path ([`active_ban_ips`]) is total and panic-free: a missing,
//! truncated, or hostile store yields an empty ban set with a `warn!`, never a
//! panic and never a partial deserialize that could ban a garbage IP. It is what
//! `net::loader` calls to compose per-IP Deny rules — the one shared source of
//! truth the daemon and NE core both read.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use etchdb::{Replayable, Store, Transactable, WalBackend};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::error::{BanwatchError, Result};
use crate::now_secs;
use crate::record::{BanCount, BanRecord};

/// Subdirectory of `~/.macwarden/` holding the ban store WAL.
pub const STORE_DIRNAME: &str = "banwatch";

/// On-disk schema version. Bumped when a collection's value layout changes.
pub const SCHEMA_VERSION: u64 = 1;

/// Metadata key under which [`SCHEMA_VERSION`] is persisted.
const SCHEMA_VERSION_KEY: &str = "schema_version";

/// The etch WAL type alias used throughout the engine.
pub type BanStore = Store<BanState, WalBackend<BanState>>;

/// Persistent ban state backed by etch WAL.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Replayable, Transactable)]
pub struct BanState {
    /// Active bans keyed by `(ip, detector)`.
    #[etch(collection = 0)]
    pub bans: HashMap<(IpAddr, String), BanRecord>,
    /// Per-IP escalation counters keyed by IP.
    #[etch(collection = 1)]
    pub ban_counts: HashMap<IpAddr, BanCount>,
    /// Store metadata (schema version, etc.).
    #[etch(collection = 2)]
    pub meta: HashMap<String, u64>,
}

/// The ban-store directory within `base_dir` (`base_dir/banwatch/`).
#[must_use]
pub fn store_dir(base_dir: &Path) -> PathBuf {
    base_dir.join(STORE_DIRNAME)
}

/// Open (or create) the WAL-backed ban store at `dir`, stamping a fresh store
/// with [`SCHEMA_VERSION`] and rejecting an incompatible one.
///
/// # Errors
///
/// Returns [`BanwatchError::Store`] if the WAL cannot be opened or written, or
/// the persisted schema version is incompatible.
pub fn open_store(dir: &Path) -> Result<BanStore> {
    std::fs::create_dir_all(dir)
        .map_err(|e| BanwatchError::Store(format!("creating store dir {}: {e}", dir.display())))?;
    let store = BanStore::open_wal(dir.to_path_buf())
        .map_err(|e| BanwatchError::Store(format!("opening ban store WAL: {e}")))?;
    verify_or_stamp_schema(&store)?;
    // The ban list is sensitive (which addresses this host has flagged): lock the
    // store dir to 0700 and its WAL/snapshot files to 0600 so no other local user
    // can read it.
    secure_store_dir(dir);
    Ok(store)
}

/// Best-effort tighten `dir` to `0700` and every file within it to `0600`
/// (Unix only). Failures are logged, never fatal — a store that opened must
/// still serve even if a chmod is refused.
pub(crate) fn secure_store_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
            warn!(path = %dir.display(), error = %e, "failed to set 0700 on store dir");
        }
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file()
                && let Err(e) =
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            {
                warn!(path = %path.display(), error = %e, "failed to set 0600 on store file");
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Verify the persisted schema version, stamping a fresh store and rejecting an
/// incompatible one.
fn verify_or_stamp_schema(store: &BanStore) -> Result<()> {
    let (version, has_data) = {
        let state = store.read();
        let has_data = !state.bans.is_empty() || !state.ban_counts.is_empty();
        (state.meta.get(SCHEMA_VERSION_KEY).copied(), has_data)
    };
    match version {
        Some(v) if v == SCHEMA_VERSION => Ok(()),
        Some(v) => Err(BanwatchError::Store(format!(
            "persisted schema version {v} != supported {SCHEMA_VERSION}"
        ))),
        None if has_data => Err(BanwatchError::Store(
            "persisted state predates schema versioning (incompatible legacy WAL)".to_owned(),
        )),
        None => store
            .write(|tx| {
                tx.meta.put(SCHEMA_VERSION_KEY.to_owned(), SCHEMA_VERSION);
                Ok(())
            })
            .map_err(|e| BanwatchError::Store(format!("stamping schema version: {e}"))),
    }
}

/// Read the currently-active (unexpired) banned IPs from the store at
/// `base_dir`, deduplicated. **Total and panic-free** — this is the read surface
/// `net::loader` composes into the live `RuleSet`.
///
/// Any failure (missing dir, corrupt WAL, incompatible schema) yields an empty
/// vec with a `warn!` so a broken store fails open to "no bans" rather than
/// tearing down rule composition.
#[must_use]
pub fn active_ban_ips(base_dir: &Path) -> Vec<IpAddr> {
    let dir = store_dir(base_dir);
    if !dir.exists() {
        return Vec::new();
    }
    let store = match BanStore::open_wal(dir) {
        Ok(store) => store,
        Err(e) => {
            warn!(error = %e, "ban store unreadable; composing zero bans");
            return Vec::new();
        }
    };
    let now = now_secs();
    let mut ips: Vec<IpAddr> = store
        .read()
        .bans
        .values()
        .filter(|rec| rec.is_active_at(now))
        .map(|rec| rec.ip)
        .collect();
    ips.sort_unstable();
    ips.dedup();
    ips
}

/// Read all currently-active ban records from the store at `base_dir`, sorted
/// by IP then detector. Total and panic-free, like [`active_ban_ips`].
#[must_use]
pub fn active_ban_records(base_dir: &Path) -> Vec<BanRecord> {
    let dir = store_dir(base_dir);
    if !dir.exists() {
        return Vec::new();
    }
    let store = match BanStore::open_wal(dir) {
        Ok(store) => store,
        Err(e) => {
            warn!(error = %e, "ban store unreadable; returning zero bans");
            return Vec::new();
        }
    };
    let now = now_secs();
    let mut records: Vec<BanRecord> = store
        .read()
        .bans
        .values()
        .filter(|rec| rec.is_active_at(now))
        .cloned()
        .collect();
    records.sort_by(|a, b| a.ip.cmp(&b.ip).then_with(|| a.detector.cmp(&b.detector)));
    records
}

#[cfg(test)]
#[path = "persist_test.rs"]
mod persist_test;
