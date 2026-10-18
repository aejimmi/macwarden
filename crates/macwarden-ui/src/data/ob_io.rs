//! Filesystem I/O for the openbinary cache: `~/.macwarden/config.toml` parsing
//! and the `~/.macwarden/ui-obcache.json` persistence layer.
//!
//! Kept out of the parent module so `openbinary.rs` stays under the file-size
//! limit. Everything here is a descendant of the `openbinary` module, so it can
//! see the parent's private [`super::Entry`] / [`super::ObState`] types.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

use serde::{Deserialize, Serialize};

use super::{DEFAULT_ENDPOINT, Entry, ObState, ObVerdict};

/// Resolved `[openbinary]` configuration, read once at cache construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObConfig {
    /// The API endpoint (trailing slash trimmed).
    pub endpoint: String,
    /// Whether unknown binaries upload automatically. Absent key = `true`.
    pub auto_upload: bool,
}

impl Default for ObConfig {
    fn default() -> Self {
        Self {
            endpoint: DEFAULT_ENDPOINT.to_owned(),
            auto_upload: true,
        }
    }
}

/// Parse the `[openbinary]` section from a `config.toml` body.
///
/// A missing file, section, or key falls back to defaults: the built-in
/// endpoint and `auto_upload = true` (the product default — unknown binaries
/// upload unless the user explicitly opts out).
#[must_use]
pub fn parse_config(contents: &str) -> ObConfig {
    let table = contents.parse::<toml::Table>().ok();
    let section = table.as_ref().and_then(|t| t.get("openbinary")?.as_table());
    let endpoint = section
        .and_then(|s| s.get("endpoint")?.as_str())
        .map_or_else(
            || DEFAULT_ENDPOINT.to_owned(),
            |s| s.trim_end_matches('/').to_owned(),
        );
    let auto_upload = section
        .and_then(|s| s.get("auto_upload")?.as_bool())
        .unwrap_or(true);
    ObConfig {
        endpoint,
        auto_upload,
    }
}

/// Read `~/.macwarden/config.toml`; any failure yields [`ObConfig::default`].
#[must_use]
pub fn resolve_config() -> ObConfig {
    let Some(home) = std::env::var_os("HOME") else {
        return ObConfig::default();
    };
    let path = PathBuf::from(home).join(".macwarden/config.toml");
    let Ok(contents) = std::fs::read_to_string(path) else {
        return ObConfig::default();
    };
    parse_config(&contents)
}

/// Persisted form of a settled entry (Known / Unknown / `TooLarge`).
#[derive(Serialize, Deserialize)]
pub struct PersistEntry {
    pub sha256: String,
    pub mtime_secs: Option<u64>,
    /// `None` marks a 404 (not in the database); `Some` is a known verdict.
    pub verdict: Option<ObVerdict>,
    pub title: Option<String>,
    pub summary: Option<String>,
    /// Set when the file exceeds the auto-upload size cap (skipped by sweeps).
    #[serde(default)]
    pub too_large: bool,
}

#[derive(Default, Serialize, Deserialize)]
pub struct Persisted {
    pub entries: HashMap<String, PersistEntry>,
}

/// Fold a live entry into its persisted form, or `None` for non-terminal states
/// (Pending / Uploading / Analyzing / Error are never written to disk).
pub fn to_persist(e: &Entry) -> Option<PersistEntry> {
    let sha256 = e.sha256.clone()?;
    let (verdict, title, summary, too_large) = match &e.state {
        ObState::Known {
            verdict,
            title,
            summary,
        } => (Some(*verdict), title.clone(), summary.clone(), false),
        ObState::Unknown => (None, None, None, false),
        ObState::TooLarge => (None, None, None, true),
        _ => return None,
    };
    Some(PersistEntry {
        sha256,
        mtime_secs: e.mtime.and_then(system_time_to_secs),
        verdict,
        title,
        summary,
        too_large,
    })
}

/// Reconstruct a live entry from its persisted form.
pub fn from_persist(p: PersistEntry) -> Entry {
    let state = if p.too_large {
        ObState::TooLarge
    } else {
        match p.verdict {
            Some(verdict) => ObState::Known {
                verdict,
                title: p.title,
                summary: p.summary,
            },
            None => ObState::Unknown,
        }
    };
    Entry {
        state,
        sha256: Some(p.sha256),
        mtime: p.mtime_secs.map(secs_to_system_time),
        at: Instant::now(),
    }
}

/// Load the persisted cache; a missing or corrupt file yields `None`.
pub fn load_persisted(path: &Path) -> Option<HashMap<PathBuf, Entry>> {
    let contents = std::fs::read_to_string(path).ok()?;
    let parsed: Persisted = serde_json::from_str(&contents).ok()?;
    Some(
        parsed
            .entries
            .into_iter()
            .map(|(k, v)| (PathBuf::from(k), from_persist(v)))
            .collect(),
    )
}

/// Write the snapshot, creating the parent directory as needed.
pub fn save_persisted(path: &Path, snapshot: &Persisted) {
    let Ok(json) = serde_json::to_string(snapshot) else {
        return;
    };
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(e) = std::fs::write(path, json) {
        tracing::debug!(%e, "failed to persist openbinary cache");
    }
}

/// `~/.macwarden/ui-obcache.json`, or `None` when `$HOME` is unset.
pub fn save_path() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".macwarden/ui-obcache.json"))
}

pub fn system_time_to_secs(t: SystemTime) -> Option<u64> {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

pub fn secs_to_system_time(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs)
}
