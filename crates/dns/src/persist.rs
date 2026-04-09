//! Crash-safe DNS cache persistence via etchdb + periodic flush.
//!
//! The [`DnsCacheStore`] wraps a [`DnsCache`] with an etchdb WAL-backed
//! store. A background thread flushes the in-memory cache to disk every
//! 60 seconds. On startup, persisted entries are loaded into the LRU cache
//! with TTL adjusted for elapsed time.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use etchdb::{Replayable, Store, Transactable, WalBackend};
use serde::{Deserialize, Serialize};

use crate::cache::DnsCache;

// ---------------------------------------------------------------------------
// Flush interval
// ---------------------------------------------------------------------------

/// Default interval between periodic flushes.
const FLUSH_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Etch state
// ---------------------------------------------------------------------------

/// Etch-backed persistent state for DNS cache.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Replayable, Transactable)]
pub struct DnsCacheDb {
    /// Persisted entries keyed by IP address string.
    #[etch(collection = 0)]
    pub entries: BTreeMap<String, DnsCacheEntry>,
}

/// A single persisted DNS cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsCacheEntry {
    /// IP address as string (stored redundantly for iteration).
    pub ip: String,
    /// Resolved hostname.
    pub hostname: String,
    /// Original TTL in seconds.
    pub ttl_secs: u64,
    /// Epoch seconds when this entry was persisted.
    pub saved_at: u64,
}

// ---------------------------------------------------------------------------
// DnsCacheStore
// ---------------------------------------------------------------------------

/// DNS cache with crash-safe etchdb persistence and periodic flush.
///
/// The in-memory [`DnsCache`] is the source of truth for lookups.
/// A background thread periodically snapshots the cache to etchdb.
/// On drop, the stop flag is set and the flush thread exits.
pub struct DnsCacheStore {
    /// The in-memory LRU cache (fast lookups).
    cache: DnsCache,
    /// Etchdb WAL store.
    store: Arc<Store<DnsCacheDb, WalBackend<DnsCacheDb>>>,
    /// Signal to stop the flush thread.
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl DnsCacheStore {
    /// Open (or create) a persistent DNS cache store.
    ///
    /// Loads any persisted entries into the LRU cache, then starts
    /// a background flush thread.
    ///
    /// # Errors
    ///
    /// Returns an error if the etchdb store cannot be opened.
    pub fn open(dir: PathBuf, cache: DnsCache) -> Result<Self, PersistError> {
        std::fs::create_dir_all(&dir).map_err(PersistError::Io)?;

        let store = Store::<DnsCacheDb, WalBackend<DnsCacheDb>>::open_wal(dir)
            .map_err(|e| PersistError::Store(format!("failed to open etch store: {e}")))?;

        let store = Arc::new(store);

        // Load persisted entries into the LRU cache.
        let loaded = load_from_store(&store, &cache);
        if loaded > 0 {
            tracing::info!(loaded, "loaded DNS cache entries from disk");
        }

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

        // Spawn periodic flush thread.
        let flush_cache = cache.clone();
        let flush_store = Arc::clone(&store);
        let flush_stop = Arc::clone(&stop);
        thread::Builder::new()
            .name("dns-cache-flush".into())
            .spawn(move || flush_loop(&flush_cache, &flush_store, &flush_stop))
            .map_err(PersistError::Io)?;

        Ok(Self { cache, store, stop })
    }

    /// Get a reference to the underlying LRU cache.
    pub fn cache(&self) -> &DnsCache {
        &self.cache
    }

    /// Flush the current cache state to etchdb immediately.
    ///
    /// Called automatically by the background thread every 60s.
    /// Can also be called manually (e.g., on graceful shutdown).
    pub fn flush(&self) -> Result<usize, PersistError> {
        flush_to_store(&self.store, &self.cache)
    }
}

impl Drop for DnsCacheStore {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // Best-effort final flush.
        if let Err(e) = self.flush() {
            tracing::warn!(%e, "final DNS cache flush failed");
        }
    }
}

// ---------------------------------------------------------------------------
// Flush logic
// ---------------------------------------------------------------------------

/// Background loop: flush every `FLUSH_INTERVAL` until stop is signaled.
fn flush_loop(
    cache: &DnsCache,
    store: &Arc<Store<DnsCacheDb, WalBackend<DnsCacheDb>>>,
    stop: &Arc<std::sync::atomic::AtomicBool>,
) {
    while !stop.load(std::sync::atomic::Ordering::Relaxed) {
        thread::sleep(FLUSH_INTERVAL);
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            break;
        }
        match flush_to_store(store, cache) {
            Ok(count) => {
                if count > 0 {
                    tracing::debug!(count, "flushed DNS cache to disk");
                }
            }
            Err(e) => {
                tracing::warn!(%e, "DNS cache flush failed");
            }
        }
    }
}

/// Write all non-expired cache entries to etchdb, replacing previous state.
fn flush_to_store(
    store: &Store<DnsCacheDb, WalBackend<DnsCacheDb>>,
    cache: &DnsCache,
) -> Result<usize, PersistError> {
    let snapshots = cache.entries();
    let now = now_epoch_secs();
    let count = snapshots.len();

    store
        .write(|tx| {
            // Upsert all current entries. Stale entries from previous
            // flushes are filtered by TTL on the next load.
            for snap in &snapshots {
                let ip_str = snap.ip.to_string();
                tx.entries.put(
                    ip_str.clone(),
                    DnsCacheEntry {
                        ip: ip_str,
                        hostname: snap.hostname.clone(),
                        ttl_secs: snap.remaining.as_secs(),
                        saved_at: now,
                    },
                );
            }
            Ok(())
        })
        .map_err(|e| PersistError::Store(format!("etch write failed: {e}")))?;

    Ok(count)
}

/// Load entries from etchdb into the LRU cache, discarding expired ones.
fn load_from_store(store: &Store<DnsCacheDb, WalBackend<DnsCacheDb>>, cache: &DnsCache) -> usize {
    let state = store.read();
    let now = now_epoch_secs();
    let mut loaded = 0usize;

    for entry in state.entries.values() {
        let elapsed = now.saturating_sub(entry.saved_at);
        let remaining = entry.ttl_secs.saturating_sub(elapsed);
        if remaining == 0 {
            continue;
        }
        let Ok(ip) = entry.ip.parse::<IpAddr>() else {
            continue;
        };
        cache.insert(ip, entry.hostname.clone(), Duration::from_secs(remaining));
        loaded += 1;
    }

    loaded
}

/// Current time as seconds since UNIX epoch.
fn now_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ---------------------------------------------------------------------------
// Legacy JSON support (kept for migration / testing)
// ---------------------------------------------------------------------------

/// Save all non-expired cache entries to a JSON file.
///
/// Kept for backward compatibility and testing. Prefer [`DnsCacheStore`]
/// for production use.
pub fn save(cache: &DnsCache, path: &std::path::Path) -> Result<usize, PersistError> {
    #[derive(Serialize)]
    struct CacheFile {
        version: u32,
        saved_at: u64,
        entries: Vec<PersistedJson>,
    }
    #[derive(Serialize)]
    struct PersistedJson {
        ip: IpAddr,
        hostname: String,
        ttl_secs: u64,
        remaining_secs: u64,
    }

    let entries: Vec<PersistedJson> = cache
        .entries()
        .into_iter()
        .map(|snap| PersistedJson {
            ip: snap.ip,
            hostname: snap.hostname,
            ttl_secs: snap.ttl.as_secs(),
            remaining_secs: snap.remaining.as_secs(),
        })
        .collect();
    let count = entries.len();
    let file = CacheFile {
        version: 1,
        saved_at: now_epoch_secs(),
        entries,
    };
    let json = serde_json::to_string_pretty(&file).map_err(PersistError::Serialize)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(PersistError::Io)?;
    }
    std::fs::write(path, json).map_err(PersistError::Io)?;
    Ok(count)
}

/// Load cache entries from a JSON file.
///
/// Kept for backward compatibility and testing. Prefer [`DnsCacheStore`]
/// for production use.
pub fn load(cache: &DnsCache, path: &std::path::Path) -> Result<usize, PersistError> {
    #[derive(Deserialize)]
    struct CacheFile {
        version: u32,
        saved_at: u64,
        entries: Vec<PersistedJson>,
    }
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct PersistedJson {
        ip: IpAddr,
        hostname: String,
        ttl_secs: u64,
        remaining_secs: u64,
    }

    if !path.is_file() {
        return Ok(0);
    }
    let raw = std::fs::read_to_string(path).map_err(PersistError::Io)?;
    let file: CacheFile = serde_json::from_str(&raw).map_err(PersistError::Deserialize)?;
    if file.version != 1 {
        return Err(PersistError::UnsupportedVersion(file.version));
    }
    let elapsed_since_save = now_epoch_secs().saturating_sub(file.saved_at);
    let mut loaded = 0usize;
    for entry in file.entries {
        let remaining = entry.remaining_secs.saturating_sub(elapsed_since_save);
        if remaining == 0 {
            continue;
        }
        cache.insert(entry.ip, entry.hostname, Duration::from_secs(remaining));
        loaded += 1;
    }
    Ok(loaded)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from DNS cache persistence.
#[derive(Debug)]
pub enum PersistError {
    /// I/O error.
    Io(std::io::Error),
    /// Etchdb store error.
    Store(String),
    /// JSON serialization error.
    Serialize(serde_json::Error),
    /// JSON deserialization error.
    Deserialize(serde_json::Error),
    /// Unsupported file version.
    UnsupportedVersion(u32),
}

impl std::fmt::Display for PersistError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "dns cache I/O error: {e}"),
            Self::Store(msg) => write!(f, "dns cache store error: {msg}"),
            Self::Serialize(e) => write!(f, "dns cache serialize error: {e}"),
            Self::Deserialize(e) => write!(f, "dns cache deserialize error: {e}"),
            Self::UnsupportedVersion(v) => {
                write!(f, "dns cache file version {v} not supported")
            }
        }
    }
}

impl std::error::Error for PersistError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Serialize(e) | Self::Deserialize(e) => Some(e),
            Self::Store(_) | Self::UnsupportedVersion(_) => None,
        }
    }
}
