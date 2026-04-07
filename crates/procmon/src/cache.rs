//! LRU cache for code signing lookups.
//!
//! Code signing verification is expensive (disk I/O + crypto). This cache
//! stores results keyed on `(pid, path)` -- PID alone is not safe due to
//! PID reuse. Entries expire after a configurable TTL.
//!
//! This module is NOT platform-gated -- it is a pure Rust data structure
//! that compiles and tests anywhere.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::types::CodeSigningInfo;

/// LRU cache for code signing verification results.
///
/// Keyed on `(pid, path)` to guard against PID reuse. Entries have
/// a TTL after which they are considered stale.
#[derive(Debug)]
pub struct CodeSigningCache {
    /// Cached entries.
    entries: HashMap<(u32, PathBuf), CacheEntry>,
    /// Maximum number of entries before eviction.
    max_entries: usize,
    /// Time-to-live for each entry.
    ttl: Duration,
}

/// A cached code signing result with its insertion timestamp.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// The cached signing info.
    info: CodeSigningInfo,
    /// When this entry was inserted.
    inserted_at: Instant,
}

impl CodeSigningCache {
    /// Create a new cache with the given capacity and TTL.
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::with_capacity(max_entries),
            max_entries,
            ttl,
        }
    }

    /// Look up cached code signing info for a process.
    ///
    /// Returns `None` if the entry is missing or expired.
    pub fn get(&self, pid: u32, path: &Path) -> Option<&CodeSigningInfo> {
        let key = (pid, path.to_path_buf());
        self.entries.get(&key).and_then(|entry| {
            if entry.inserted_at.elapsed() < self.ttl {
                Some(&entry.info)
            } else {
                None
            }
        })
    }

    /// Insert a code signing result into the cache.
    ///
    /// If the cache is at capacity, expired entries are evicted first.
    /// If still at capacity after eviction, the oldest entry is removed.
    pub fn insert(&mut self, pid: u32, path: PathBuf, info: CodeSigningInfo) {
        if self.entries.len() >= self.max_entries {
            self.evict_expired();
        }

        // If still at capacity, remove the oldest entry
        if self.entries.len() >= self.max_entries {
            self.evict_oldest();
        }

        self.entries.insert(
            (pid, path),
            CacheEntry {
                info,
                inserted_at: Instant::now(),
            },
        );
    }

    /// Remove all expired entries.
    pub fn evict_expired(&mut self) {
        let ttl = self.ttl;
        self.entries
            .retain(|_, entry| entry.inserted_at.elapsed() < ttl);
    }

    /// The number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove the oldest entry from the cache.
    fn evict_oldest(&mut self) {
        if let Some(oldest_key) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.inserted_at)
            .map(|(key, _)| key.clone())
        {
            self.entries.remove(&oldest_key);
        }
    }
}

#[cfg(test)]
#[path = "cache_test.rs"]
mod cache_test;
