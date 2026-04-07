//! Thread-safe LRU cache mapping IP addresses to hostnames.
//!
//! Entries expire based on TTL. Default capacity: 10,000 entries.
//! LRU eviction: when at capacity, the least-recently-used entry is
//! evicted on insert. Expired entries are removed lazily on lookup.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Default cache capacity.
const DEFAULT_CAPACITY: usize = 10_000;

/// A single cached DNS entry.
struct CacheEntry {
    hostname: String,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    /// Returns `true` if this entry has expired.
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() >= self.ttl
    }
}

/// Internal cache state behind the lock.
struct Inner {
    map: HashMap<IpAddr, CacheEntry>,
    /// LRU order: front = most recently used, back = least recently used.
    order: VecDeque<IpAddr>,
    capacity: usize,
}

impl Inner {
    fn new(capacity: usize) -> Self {
        Self {
            map: HashMap::with_capacity(capacity),
            order: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    /// Move `ip` to the front of the LRU order.
    /// Removes any existing occurrence first (O(n) scan, acceptable at 10K).
    fn promote(&mut self, ip: &IpAddr) {
        if let Some(pos) = self.order.iter().position(|k| k == ip) {
            self.order.remove(pos);
        }
        self.order.push_front(*ip);
    }

    /// Evict the least-recently-used entry (back of deque).
    fn evict_lru(&mut self) {
        if let Some(ip) = self.order.pop_back() {
            self.map.remove(&ip);
        }
    }

    /// Remove an entry by IP from both map and order.
    fn remove(&mut self, ip: &IpAddr) {
        self.map.remove(ip);
        if let Some(pos) = self.order.iter().position(|k| k == ip) {
            self.order.remove(pos);
        }
    }
}

/// Thread-safe LRU cache mapping IP addresses to hostnames.
///
/// Two insertion paths:
/// - [`DnsCache::insert`] -- direct insertion (from ES events with known hostname)
/// - Future: from parsed DNS response packets via the sniffer
///
/// Entries expire based on TTL. Default capacity: 10,000 entries.
/// Clone is cheap -- it clones the inner `Arc`.
#[derive(Clone)]
pub struct DnsCache {
    inner: Arc<RwLock<Inner>>,
}

impl DnsCache {
    /// Create a new cache with the default capacity (10,000).
    pub fn new_default() -> Self {
        Self::new(DEFAULT_CAPACITY)
    }

    /// Create a new cache with the given maximum capacity.
    ///
    /// A capacity of 0 is silently upgraded to 1.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Arc::new(RwLock::new(Inner::new(capacity))),
        }
    }

    /// Insert or update an entry mapping `ip` to `hostname` with the given TTL.
    ///
    /// If the cache is at capacity and this is a new key, the least-recently-used
    /// entry is evicted first.
    pub fn insert(&self, ip: IpAddr, hostname: String, ttl: Duration) {
        let mut inner = self
            .inner
            .write()
            .expect("dns cache lock poisoned on insert");

        let is_new = !inner.map.contains_key(&ip);

        // Evict LRU if at capacity and inserting a new key.
        if is_new && inner.map.len() >= inner.capacity {
            inner.evict_lru();
        }

        inner.map.insert(
            ip,
            CacheEntry {
                hostname,
                inserted_at: Instant::now(),
                ttl,
            },
        );
        inner.promote(&ip);
    }

    /// Look up the hostname for `ip`.
    ///
    /// Returns `None` if the entry is missing or expired.
    /// Expired entries are removed on lookup (lazy eviction).
    /// A successful lookup promotes the entry to most-recently-used.
    pub fn lookup(&self, ip: &IpAddr) -> Option<String> {
        let mut inner = self
            .inner
            .write()
            .expect("dns cache lock poisoned on lookup");

        let entry = inner.map.get(ip)?;

        if entry.is_expired() {
            // Remove expired entry -- drop the borrow before mutating.
            let ip_owned = *ip;
            inner.remove(&ip_owned);
            return None;
        }

        let hostname = entry.hostname.clone();
        inner.promote(ip);
        Some(hostname)
    }

    /// Number of entries currently in the cache (including expired but not yet evicted).
    pub fn len(&self) -> usize {
        let inner = self.inner.read().expect("dns cache lock poisoned on len");
        inner.map.len()
    }

    /// Returns `true` if the cache contains no entries.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Maximum number of entries this cache can hold.
    pub fn capacity(&self) -> usize {
        let inner = self
            .inner
            .read()
            .expect("dns cache lock poisoned on capacity");
        inner.capacity
    }

    /// Remove all entries from the cache.
    pub fn clear(&self) {
        let mut inner = self
            .inner
            .write()
            .expect("dns cache lock poisoned on clear");
        inner.map.clear();
        inner.order.clear();
    }
}

impl std::fmt::Debug for DnsCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read().expect("dns cache lock poisoned on debug");
        f.debug_struct("DnsCache")
            .field("len", &inner.map.len())
            .field("capacity", &inner.capacity)
            .finish()
    }
}
