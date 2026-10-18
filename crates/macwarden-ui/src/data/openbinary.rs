//! openbinary verdict cache and lookup client (cross-platform).
//!
//! This is the panel's bridge to the shared `openbinary-agent-core` SDK. It
//! owns three concerns, all free of GPUI and platform APIs so the whole module
//! compiles and unit-tests on any target:
//!
//! - **Config resolution** — reads `~/.macwarden/config.toml` `[openbinary]`
//!   (`endpoint` + `auto_upload`), falling back to built-in defaults.
//! - **Response parsing** — folds a `GET /binary/{sha}` JSON document into a
//!   small [`ObState`] the UI can render without knowing the wire shape.
//! - **A shared verdict cache** — keyed by binary path, populated by inspector
//!   requests and the background [`sweep`](super::sweep) worker, persisted to
//!   `~/.macwarden/ui-obcache.json`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[path = "ob_io.rs"]
mod io;
#[path = "ob_lookup.rs"]
mod lookup;
pub use io::{ObConfig, parse_config, resolve_config};
pub(crate) use io::{Persisted, load_persisted, save_path, save_persisted, to_persist};

/// Default public API endpoint. Overrides the SDK's own default so the panel
/// targets the same host as the `macwarden` CLI unless a config override exists.
pub const DEFAULT_ENDPOINT: &str = "https://api.openbinary.ai/api/v1";

/// How long a failed lookup is cached before another attempt is allowed — the
/// guard against a per-tick retry storm when the endpoint is unreachable.
const ERROR_TTL: Duration = Duration::from_secs(300);

/// The panel's self-imposed auto-upload size cap. The server accepts up to
/// 256 MB, but the panel never silently pushes multi-hundred-megabyte binaries;
/// oversized files cache as [`ObState::TooLarge`] and offer a manual upload.
pub const MAX_AUTO_UPLOAD_BYTES: u64 = 100 * 1024 * 1024;

/// The ceiling for an explicit ("upload anyway") request — the server's cap.
const MAX_MANUAL_UPLOAD_BYTES: u64 = 256 * 1024 * 1024;

/// Whether a file is small enough to upload automatically.
#[must_use]
pub fn within_auto_cap(size: u64) -> bool {
    size <= MAX_AUTO_UPLOAD_BYTES
}

/// The verdict label reported under `/binary/verdict/label`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ObVerdict {
    /// Analysed and considered safe.
    Benign,
    /// Analysed with suspicious traits.
    Suspicious,
    /// Confirmed malicious.
    Malicious,
    /// Probably malicious.
    LikelyMalicious,
    /// Analysed but inconclusive.
    NotEnoughEvidence,
    /// A label the panel doesn't recognise (forward-compatibility).
    Unrecognized,
}

/// The semantic severity of a verdict — the single mapping the UI colours from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObTone {
    /// Accent green — benign.
    Good,
    /// Amber — suspicious.
    Warn,
    /// Red — malicious / likely malicious.
    Bad,
    /// Dim — inconclusive or unrecognised.
    Neutral,
}

impl ObVerdict {
    /// Parse a wire label (`benign`, `likely_malicious`, ...).
    #[must_use]
    pub fn from_label(label: &str) -> Self {
        match label {
            "benign" => Self::Benign,
            "suspicious" => Self::Suspicious,
            "malicious" => Self::Malicious,
            "likely_malicious" => Self::LikelyMalicious,
            "not_enough_evidence" => Self::NotEnoughEvidence,
            _ => Self::Unrecognized,
        }
    }

    /// Human-readable label for the inspector.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Benign => "benign",
            Self::Suspicious => "suspicious",
            Self::Malicious => "malicious",
            Self::LikelyMalicious => "likely malicious",
            Self::NotEnoughEvidence => "not enough evidence",
            Self::Unrecognized => "analyzed",
        }
    }

    /// The semantic tone the UI colours from.
    #[must_use]
    pub fn tone(self) -> ObTone {
        match self {
            Self::Benign => ObTone::Good,
            Self::Suspicious => ObTone::Warn,
            Self::Malicious | Self::LikelyMalicious => ObTone::Bad,
            Self::NotEnoughEvidence | Self::Unrecognized => ObTone::Neutral,
        }
    }
}

/// The cache state for one binary, as rendered by the inspector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObState {
    /// A hash + lookup is in flight.
    Pending,
    /// An explicit upload + analysis is in flight (inspector-driven).
    Uploading,
    /// Uploaded by the background sweep; awaiting server analysis. Re-checked
    /// lazily via `GET` on a later sweep pass rather than a held poll loop.
    Analyzing,
    /// The endpoint returned 404 — not in the openbinary database.
    Unknown,
    /// The file exceeds the auto-upload cap; a manual upload is still offered.
    TooLarge,
    /// A verdict is known.
    Known {
        /// The verdict label.
        verdict: ObVerdict,
        /// A short human title, if the server supplied one.
        title: Option<String>,
        /// A one-line summary, if the server supplied one.
        summary: Option<String>,
    },
    /// The lookup failed (offline / parse error).
    Error,
}

impl ObState {
    /// The known verdict, if any (drives row badges).
    #[must_use]
    pub fn verdict(&self) -> Option<ObVerdict> {
        match self {
            Self::Known { verdict, .. } => Some(*verdict),
            _ => None,
        }
    }

    /// Whether a background task is currently in flight for this entry.
    #[must_use]
    pub fn in_flight(&self) -> bool {
        matches!(self, Self::Pending | Self::Uploading)
    }
}

/// Fold a `GET /binary/{sha}` document into a [`ObState::Known`].
///
/// The live wire format nests the analysis under a top-level `binary` object;
/// this tolerates both the nested and a flat shape. Title falls back through
/// `title` → `fingerprint.name` → code-signing identifier so a useful name
/// still shows when the server leaves `title` null.
#[must_use]
pub fn parse_known(doc: &Value) -> ObState {
    let obj = doc.get("binary").unwrap_or(doc);
    let verdict = obj
        .pointer("/verdict/label")
        .and_then(Value::as_str)
        .map_or(ObVerdict::NotEnoughEvidence, ObVerdict::from_label);
    ObState::Known {
        verdict,
        title: title_of(obj),
        summary: non_empty(obj.get("summary").and_then(Value::as_str)),
    }
}

fn title_of(obj: &Value) -> Option<String> {
    non_empty(obj.get("title").and_then(Value::as_str))
        .or_else(|| non_empty(obj.pointer("/fingerprint/name").and_then(Value::as_str)))
        .or_else(|| {
            non_empty(
                obj.pointer("/code_signature/code_directory/identifier")
                    .and_then(Value::as_str),
            )
        })
}

fn non_empty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// One cache entry: the state, the hash and file mtime it was computed for
/// (for staleness detection), and when it was recorded (for the error TTL).
#[derive(Clone)]
pub(crate) struct Entry {
    pub(crate) state: ObState,
    pub(crate) sha256: Option<String>,
    pub(crate) mtime: Option<SystemTime>,
    pub(crate) at: Instant,
}

impl Entry {
    fn flight(state: ObState, mtime: Option<SystemTime>) -> Self {
        Self {
            state,
            sha256: None,
            mtime,
            at: Instant::now(),
        }
    }

    /// An in-flight entry that already knows the binary's hash (e.g. an
    /// auto-upload after a 404), so the inspector can link out while it uploads.
    fn flight_with_sha(state: ObState, sha256: String, mtime: Option<SystemTime>) -> Self {
        Self {
            state,
            sha256: Some(sha256),
            mtime,
            at: Instant::now(),
        }
    }

    fn terminal(state: ObState, sha256: Option<String>, mtime: Option<SystemTime>) -> Self {
        Self {
            state,
            sha256,
            mtime,
            at: Instant::now(),
        }
    }
}

struct Inner {
    entries: HashMap<PathBuf, Entry>,
}

struct Shared {
    inner: Mutex<Inner>,
    endpoint: String,
    auto_upload: bool,
    save_path: PathBuf,
}

/// A shared, thread-safe openbinary verdict cache.
///
/// Cloneable and cheap to share: all state lives behind an `Arc`. Reads
/// ([`ObCache::get`]) are lock-and-clone; lookups ([`ObCache::request`]) and
/// uploads ([`ObCache::identify`]) run on detached background threads so the
/// synchronous SDK never touches the render loop. The background
/// [`sweep`](super::sweep) worker records settled states via [`ObCache::record`].
#[derive(Clone)]
pub struct ObCache {
    shared: Arc<Shared>,
}

impl ObCache {
    /// Build the cache: resolve config, load `~/.macwarden/ui-obcache.json`
    /// (corrupt or missing file starts fresh), and return a ready cache.
    #[must_use]
    pub fn load() -> Self {
        let config = resolve_config();
        let save_path = save_path();
        let entries = save_path
            .as_ref()
            .and_then(|p| load_persisted(p))
            .unwrap_or_default();
        Self::from_parts(config, save_path.unwrap_or_default(), entries)
    }

    fn from_parts(config: ObConfig, save_path: PathBuf, entries: HashMap<PathBuf, Entry>) -> Self {
        Self {
            shared: Arc::new(Shared {
                inner: Mutex::new(Inner { entries }),
                endpoint: config.endpoint,
                auto_upload: config.auto_upload,
                save_path,
            }),
        }
    }

    /// The resolved API endpoint.
    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.shared.endpoint
    }

    /// Whether unknown binaries upload automatically (config `auto_upload`).
    #[must_use]
    pub fn auto_upload(&self) -> bool {
        self.shared.auto_upload
    }

    /// Read the cached state for a binary path, if one exists. Never fetches.
    #[must_use]
    pub fn get(&self, key: &Path) -> Option<ObState> {
        let inner = self.shared.inner.lock().ok()?;
        inner.entries.get(key).map(|e| e.state.clone())
    }

    /// Read the cached SHA-256 for a binary path, if the lookup has settled and
    /// recorded one. Drives the "open the binary's openbinary.ai page" link in
    /// the inspector — the URL is `.../binary/<sha256>`. Never fetches.
    #[must_use]
    pub fn sha256(&self, key: &Path) -> Option<String> {
        let inner = self.shared.inner.lock().ok()?;
        inner.entries.get(key).and_then(|e| e.sha256.clone())
    }

    /// Ensure a lookup is scheduled for `key`. Idempotent: returns immediately
    /// when a task is in flight, a fresh terminal result exists (same file
    /// mtime), or an error is still within its TTL. Re-fetches when the file's
    /// mtime has changed since the cached result. On a 404 with `auto_upload`
    /// enabled, the lookup thread continues into upload + poll automatically.
    pub fn request(&self, key: &Path) {
        let Some(exe) = resolve_exe(key) else {
            return;
        };
        let cur_mtime = file_mtime(&exe);
        {
            let Ok(mut inner) = self.shared.inner.lock() else {
                return;
            };
            if let Some(e) = inner.entries.get(key) {
                if e.state.in_flight() {
                    return;
                }
                if e.state == ObState::Error && e.at.elapsed() < ERROR_TTL {
                    return;
                }
                let terminal = is_terminal(&e.state);
                if terminal && e.mtime == cur_mtime {
                    return;
                }
            }
            inner.entries.insert(
                key.to_path_buf(),
                Entry::flight(ObState::Pending, cur_mtime),
            );
        }
        let shared = Arc::clone(&self.shared);
        let key = key.to_path_buf();
        spawn("ob-lookup", move || {
            lookup::run_lookup(&shared, &key, &exe, cur_mtime);
        });
    }

    /// Explicitly upload `key` for analysis, then poll and refresh — the action
    /// behind the inspector's manual "Identify" / "Upload anyway" button. Unlike
    /// the auto path this ignores the [`MAX_AUTO_UPLOAD_BYTES`] cap (bounded only
    /// by the server's ceiling).
    pub fn identify(&self, key: &Path) {
        let Some(exe) = resolve_exe(key) else {
            return;
        };
        let cur_mtime = file_mtime(&exe);
        {
            let Ok(mut inner) = self.shared.inner.lock() else {
                return;
            };
            if inner.entries.get(key).is_some_and(|e| e.state.in_flight()) {
                return;
            }
            inner.entries.insert(
                key.to_path_buf(),
                Entry::flight(ObState::Uploading, cur_mtime),
            );
        }
        let shared = Arc::clone(&self.shared);
        let key = key.to_path_buf();
        spawn("ob-upload", move || {
            lookup::run_identify(&shared, &key, &exe, cur_mtime);
        });
    }

    /// Record a settled state for `key` from the background sweep. Terminal
    /// states (Known / Unknown / `TooLarge`) persist; transient ones do not.
    pub(crate) fn record(
        &self,
        key: &Path,
        state: ObState,
        sha: Option<String>,
        mtime: Option<SystemTime>,
    ) {
        store(&self.shared, key, Entry::terminal(state, sha, mtime));
    }
}

fn is_terminal(state: &ObState) -> bool {
    matches!(
        state,
        ObState::Known { .. } | ObState::Unknown | ObState::TooLarge
    )
}

/// Commit an entry and persist the cache (IO happens outside the lock).
fn store(shared: &Arc<Shared>, key: &Path, entry: Entry) {
    let snapshot = {
        let Ok(mut inner) = shared.inner.lock() else {
            return;
        };
        inner.entries.insert(key.to_path_buf(), entry);
        persist_snapshot(&inner)
    };
    if !shared.save_path.as_os_str().is_empty() {
        save_persisted(&shared.save_path, &snapshot);
    }
}

fn persist_snapshot(inner: &Inner) -> Persisted {
    let entries = inner
        .entries
        .iter()
        .filter_map(|(k, e)| Some((k.to_string_lossy().into_owned(), to_persist(e)?)))
        .collect();
    Persisted { entries }
}

/// Resolve the actual Mach-O to hash from a row/inspector key: a plain file is
/// used directly; a `.app` bundle resolves to its `Contents/MacOS` executable.
#[must_use]
pub fn resolve_exe(path: &Path) -> Option<PathBuf> {
    if path.is_file() {
        return Some(path.to_path_buf());
    }
    if path.extension().is_some_and(|e| e == "app") {
        return exe_in_bundle(path);
    }
    None
}

fn exe_in_bundle(bundle: &Path) -> Option<PathBuf> {
    let macos = bundle.join("Contents/MacOS");
    if let Some(stem) = bundle.file_stem() {
        let candidate = macos.join(stem);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    std::fs::read_dir(&macos)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_file())
}

fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// The file's size in bytes, or `None` when it can't be stat'd.
#[must_use]
pub fn file_size(path: &Path) -> Option<u64> {
    std::fs::metadata(path).ok().map(|m| m.len())
}

/// Spawn a named detached worker; a failure to start is logged, not fatal.
fn spawn(name: &str, f: impl FnOnce() + Send + 'static) {
    if let Err(e) = std::thread::Builder::new().name(name.into()).spawn(f) {
        tracing::warn!(%e, name, "openbinary worker thread failed to start");
    }
}

#[cfg(test)]
#[path = "openbinary_test.rs"]
mod openbinary_test;
