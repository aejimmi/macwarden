//! Persisted UI preferences in `~/.macwarden/ui-prefs.json`.
//!
//! Currently just the live-data [`RefreshRate`]. Mirrors the openbinary cache's
//! JSON persistence (best-effort: a missing or corrupt file falls back to
//! defaults, and a write failure is logged, never fatal). The rate is stored as
//! a stable string key so the file survives enum reordering or additions.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::state::RefreshRate;

/// The on-disk shape. `refresh_rate` is optional so an older or partial file
/// still parses, and unknown values decode to the default.
#[derive(Serialize, Deserialize, Default)]
struct StoredPrefs {
    #[serde(default)]
    refresh_rate: Option<String>,
}

/// `~/.macwarden/ui-prefs.json`, or `None` when `$HOME` is unset.
fn prefs_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".macwarden/ui-prefs.json"))
}

/// Load the persisted refresh rate; a missing/unset-`$HOME`/corrupt file yields
/// [`RefreshRate::default`].
#[must_use]
pub fn load_refresh_rate() -> RefreshRate {
    let Some(contents) = prefs_path().and_then(|p| std::fs::read_to_string(p).ok()) else {
        return RefreshRate::default();
    };
    decode(&contents)
}

/// Persist the refresh rate. Best-effort — a write failure is logged, not fatal.
pub fn save_refresh_rate(rate: RefreshRate) {
    let Some(path) = prefs_path() else {
        return;
    };
    let json = encode(rate);
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = std::fs::write(&path, json) {
        tracing::debug!(%e, "failed to persist ui prefs");
    }
}

/// Serialize a rate to the on-disk JSON body. Pure, so it is unit-testable
/// without touching `$HOME`.
fn encode(rate: RefreshRate) -> String {
    let stored = StoredPrefs {
        refresh_rate: Some(rate.as_key().to_string()),
    };
    serde_json::to_string_pretty(&stored).unwrap_or_default()
}

/// Parse a rate from an on-disk JSON body; a corrupt or partial body yields the
/// default. Pure, so it is unit-testable without touching `$HOME`.
fn decode(contents: &str) -> RefreshRate {
    let parsed: StoredPrefs = serde_json::from_str(contents).unwrap_or_default();
    parsed
        .refresh_rate
        .map_or_else(RefreshRate::default, |key| RefreshRate::from_key(&key))
}

#[cfg(test)]
#[path = "prefs_test.rs"]
mod prefs_test;
