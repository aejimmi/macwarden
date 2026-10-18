//! Background reverse-DNS cache for the daemon's live-connection scanner.
//!
//! Reverse DNS (`dns_lookup::lookup_addr`) is **blocking** and can stall for
//! seconds on a non-responsive PTR authority. The snapshot build sits on the
//! panel's request hot path behind a ~2s read timeout, so it must never resolve
//! inline. This module decouples the two:
//!
//! - The scanner calls [`RdnsResolver::resolve`] per destination IP. It is
//!   **non-blocking**: a cache hit returns the name (or a cached negative);
//!   a miss enqueues the IP for background resolution and returns `None`, so
//!   the row shows the bare IP until a later tick fills the name in. Names
//!   appear progressively across snapshots — smooth, never blocking.
//! - A single background worker thread drains the queue, runs the shared
//!   [`super::super::super::commands::net::net_rdns::reverse_lookup`] (the same
//!   `lookup_addr` + `is_garbage_rdns` filtering the CLI uses), and stores the
//!   result — including negatives, so a garbage/absent PTR is not retried every
//!   tick.
//!
//! The cache is bounded by [`MAX_ENTRIES`]; once full, new misses are neither
//! enqueued nor cached, so memory cannot grow without limit over long uptimes.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Mutex, MutexGuard, PoisonError};

use tracing::warn;

use crate::commands::net::net_rdns::reverse_lookup;

/// Upper bound on cached IP→name entries (positive + negative), matching the
/// scanner's retained-destination ceiling. Far above a typical machine's count.
const MAX_ENTRIES: usize = 4096;

/// The outcome of probing the cache for an IP.
#[derive(Debug, PartialEq, Eq)]
enum Probe {
    /// The IP is cached: `Some(name)` resolved, `None` a cached negative.
    Hit(Option<String>),
    /// A fresh miss just marked pending — the caller should enqueue the IP.
    Enqueue,
    /// A miss already pending, or the cache is full — do nothing.
    Skip,
}

/// Shared, thread-safe cache state. Held behind an `Arc` so the scanner (any
/// number of clones) and the single worker observe the same map.
#[derive(Debug, Default)]
struct Inner {
    /// `IpAddr` → resolved name (`Some`) or cached negative (`None`).
    cache: Mutex<HashMap<IpAddr, Option<String>>>,
    /// IPs enqueued but not yet resolved, so a slow lookup is not re-enqueued
    /// on every scan tick while it is still in flight.
    pending: Mutex<HashSet<IpAddr>>,
}

impl Inner {
    /// Non-blocking cache probe. Locks cache then pending in a fixed order so it
    /// cannot deadlock against [`Self::store`], which takes the same order.
    fn probe(&self, ip: IpAddr) -> Probe {
        let cache = lock(&self.cache);
        if let Some(name) = cache.get(&ip) {
            return Probe::Hit(name.clone());
        }
        let mut pending = lock(&self.pending);
        if pending.contains(&ip) {
            return Probe::Skip;
        }
        if cache.len().saturating_add(pending.len()) >= MAX_ENTRIES {
            return Probe::Skip;
        }
        pending.insert(ip);
        Probe::Enqueue
    }

    /// Record a resolution result (positive or negative) and clear its pending
    /// mark. Bounded: a full cache drops the result rather than growing.
    fn store(&self, ip: IpAddr, name: Option<String>) {
        let mut cache = lock(&self.cache);
        if cache.len() < MAX_ENTRIES {
            cache.insert(ip, name);
        }
        let mut pending = lock(&self.pending);
        pending.remove(&ip);
    }
}

/// A cheap-to-clone handle to the background reverse-DNS cache.
///
/// Cloning shares the same cache and worker (the `Arc` and the `Sender` are
/// both shared), so the scanner may be cloned freely without spawning extra
/// threads. The worker exits cleanly once every clone is dropped.
#[derive(Debug, Clone)]
pub struct RdnsResolver {
    inner: std::sync::Arc<Inner>,
    tx: Sender<IpAddr>,
}

impl Default for RdnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl RdnsResolver {
    /// Build a resolver with an empty cache and spawn its background worker.
    #[must_use]
    pub fn new() -> Self {
        let inner = std::sync::Arc::new(Inner::default());
        let (tx, rx) = channel::<IpAddr>();
        spawn_worker(std::sync::Arc::clone(&inner), rx);
        Self { inner, tx }
    }

    /// Resolve `ip` to a hostname without ever blocking.
    ///
    /// Returns the cached name on a hit, or `None` on a miss — enqueueing the IP
    /// for the background worker so a later call can return the name. Cached
    /// negatives (no/garbage PTR) also return `None` but are not re-enqueued.
    #[must_use]
    pub fn resolve(&self, ip: IpAddr) -> Option<String> {
        match self.inner.probe(ip) {
            Probe::Hit(name) => name,
            Probe::Enqueue => {
                if self.tx.send(ip).is_err() {
                    warn!("rdns worker gone; reverse resolution disabled");
                }
                None
            }
            Probe::Skip => None,
        }
    }
}

/// Spawn the single worker that drains the queue and populates the cache.
///
/// Each `recv` blocks until an IP arrives; the worker resolves it (the only
/// blocking call in this module) and stores the result. When every [`Sender`]
/// clone is dropped, `recv` returns `Err` and the thread exits.
fn spawn_worker(inner: std::sync::Arc<Inner>, rx: Receiver<IpAddr>) {
    let build = std::thread::Builder::new()
        .name("rdns-resolver".into())
        .spawn(move || {
            while let Ok(ip) = rx.recv() {
                let name = reverse_lookup(ip);
                inner.store(ip, name);
            }
        });
    if let Err(e) = build {
        warn!(error = %e, "rdns worker thread not started; hostnames disabled");
    }
}

/// Lock a mutex, recovering the guard from a poisoned lock rather than panicking
/// — a poisoned rDNS cache is non-critical and degrades to bare-IP display.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
#[path = "rdns_cache_test.rs"]
mod rdns_cache_test;
