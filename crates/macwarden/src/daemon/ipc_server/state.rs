//! Shared server state: the `Arc`-swappable live rule set and injected sources.
//!
//! The live [`net::RuleSet`] lives behind a `RwLock<Arc<RuleSet>>`: readers
//! (snapshot builds) take the read lock only long enough to clone the cheap
//! `Arc`, so evaluation happens lock-free on a stable snapshot; a mutation
//! (R7) builds a fresh rule set off-lock, then swaps the `Arc` and bumps the
//! `generation` under the write lock — an atomic, contention-free replace at
//! personal-tool volume. This is the standard "atomics/RwLock over a lock in the
//! hot path" shape: the read path never blocks on the rare write.
//!
//! Every impure dependency (connection scanner, metrics store, inventory) is
//! injected, so the handlers are pure functions over this state and unit-test
//! without a socket, root, or the real macOS backends.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use inventory::InventoryStore;
use ipc::protocol::Capability;
use metrics::MetricsStore;
use net::{NetworkRule, RuleSet};

use super::banwatch_svc::BanwatchService;
use super::error::{Result, ServerError};
use super::ruleset::build_live_ruleset;
use super::snapshot::{ConnectionScanner, LiveConn};

/// A `Session`-duration rule tracked in memory (never written to disk, R7).
pub type SessionRule = NetworkRule;

/// An `Until`-duration rule file to auto-clean once its deadline passes (R7).
#[derive(Debug, Clone)]
struct ExpiringRule {
    path: PathBuf,
    expiry_ms: u64,
}

/// The daemon IPC server's shared state (R11).
pub struct ServerState {
    /// The daemon's human-readable build version (for `Welcome`).
    pub daemon_version: String,
    /// Advertised capabilities (R3).
    pub capabilities: Vec<Capability>,
    /// Daemon start time in unix ms (the `Session` history window, R5).
    pub session_start_ms: i64,
    /// Where `Permanent`/`Until` rule files live (`~/.macwarden/net-rules/`).
    rules_dir: PathBuf,
    /// The live, `Arc`-swappable rule set (R7).
    ruleset: RwLock<Arc<RuleSet>>,
    /// Increments on every successful mutation (R4/R7).
    generation: AtomicU64,
    /// In-memory `Session` rules, re-applied on every reload.
    session_rules: Mutex<Vec<SessionRule>>,
    /// `Until` rule files awaiting auto-clean.
    expiring: Mutex<Vec<ExpiringRule>>,
    /// Monotonic id source for in-memory rules (offset above file-rule ids).
    next_rule_id: AtomicU64,
    /// The live-connection scanner (R4).
    scanner: Arc<dyn ConnectionScanner>,
    /// The metrics store for history (R5); `None` disables `History`.
    metrics: Option<Arc<Mutex<MetricsStore>>>,
    /// The inventory store for openbinary passthrough (R6); `None` disables it.
    inventory: Option<Arc<InventoryStore>>,
    /// Count of live packet-trace sessions across all connections, bounding
    /// concurrent captures so panels cannot spawn them without limit (R9).
    active_traces: Arc<AtomicUsize>,
    /// The latest connection sample, refreshed continuously by the background
    /// sampler ([`super::run_sampler`]). Request handlers read this instead of
    /// running a multi-second `nettop` scan inline — so `GetSnapshot` and the
    /// detail queries answer in milliseconds regardless of scan cost (R4/R6).
    /// Empty until the first sample lands, so handlers answer empty snapshots
    /// during cold start (prompt cold-start behavior).
    latest_conns: RwLock<Arc<Vec<LiveConn>>>,
    /// Unix-ms timestamp of the most recent stored sample (`0` = none yet).
    /// Exposed as a sample age in the snapshot so the panel can flag a wedged
    /// sampler (a frozen live view) instead of showing stale data as if live.
    sampled_at_ms: AtomicU64,
    /// The banwatch scanner-protection engine (spec 010); `None` disables the
    /// `BanWatch` capability and its handlers.
    banwatch: Option<Arc<BanwatchService>>,
}

impl ServerState {
    /// Assemble state from injected sources and build the initial rule set.
    pub fn new(
        daemon_version: String,
        capabilities: Vec<Capability>,
        rules_dir: PathBuf,
        scanner: Arc<dyn ConnectionScanner>,
        metrics: Option<Arc<Mutex<MetricsStore>>>,
        inventory: Option<Arc<InventoryStore>>,
    ) -> Result<Self> {
        // No banwatch engine is attached yet (`with_banwatch` runs after `new`),
        // so the initial set carries no bans; the caller reloads once the engine
        // is attached to seed persisted bans from its in-memory set.
        let ruleset = build_live_ruleset(&rules_dir, &[], &[])?;
        Ok(Self {
            daemon_version,
            capabilities,
            session_start_ms: now_ms(),
            rules_dir,
            ruleset: RwLock::new(Arc::new(ruleset)),
            generation: AtomicU64::new(0),
            session_rules: Mutex::new(Vec::new()),
            expiring: Mutex::new(Vec::new()),
            next_rule_id: AtomicU64::new(900_000),
            scanner,
            metrics,
            inventory,
            active_traces: Arc::new(AtomicUsize::new(0)),
            latest_conns: RwLock::new(Arc::new(Vec::new())),
            sampled_at_ms: AtomicU64::new(0),
            banwatch: None,
        })
    }

    /// Attach the banwatch service (spec 010), consuming and returning `self`
    /// so the caller can wire it in before `Arc`-wrapping the state.
    #[must_use]
    pub fn with_banwatch(mut self, banwatch: Option<Arc<BanwatchService>>) -> Self {
        self.banwatch = banwatch;
        self
    }

    /// The banwatch service handle, if the engine is enabled.
    pub fn banwatch(&self) -> Option<&Arc<BanwatchService>> {
        self.banwatch.as_ref()
    }

    /// Store a fresh connection sample from the background sampler. Handlers read
    /// [`Self::latest_conns`] without ever scanning inline (R4/R6).
    pub fn store_conns(&self, conns: Vec<LiveConn>) {
        if let Ok(mut guard) = self.latest_conns.write() {
            *guard = Arc::new(conns);
        }
        // Stamp the sample time after the swap so an observed age never predates
        // the data it describes.
        self.sampled_at_ms
            .store(now_ms().max(0) as u64, Ordering::Release);
    }

    /// Age of the latest connection sample in milliseconds, or `None` if no
    /// sample has landed yet. A large or growing age signals a wedged sampler —
    /// the panel uses it to mark the live view stale rather than trusting it.
    #[must_use]
    pub fn sample_age_ms(&self) -> Option<u64> {
        let stamped = self.sampled_at_ms.load(Ordering::Acquire);
        if stamped == 0 {
            return None;
        }
        Some((now_ms().max(0) as u64).saturating_sub(stamped))
    }

    /// A cheap `Arc` clone of the latest connection sample (empty until the first
    /// background sample lands).
    pub fn latest_conns(&self) -> Arc<Vec<LiveConn>> {
        match self.latest_conns.read() {
            Ok(guard) => Arc::clone(&guard),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// The shared live-trace-session counter, used to bound concurrent captures
    /// (R9). The trace session holds a slot guard that decrements it on drop.
    pub fn active_traces(&self) -> &Arc<AtomicUsize> {
        &self.active_traces
    }

    /// The rules directory (`~/.macwarden/net-rules/`).
    pub fn rules_dir(&self) -> &std::path::Path {
        &self.rules_dir
    }

    /// A cheap clone of the current live rule set (read path never blocks a
    /// writer for longer than the `Arc` clone).
    pub fn ruleset(&self) -> Arc<RuleSet> {
        match self.ruleset.read() {
            Ok(guard) => Arc::clone(&guard),
            // A poisoned lock still yields the last-good rule set.
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    /// The current ruleset generation (R4/R7).
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Allocate a fresh in-memory rule id (offset above file-rule ids).
    pub fn next_rule_id(&self) -> u64 {
        self.next_rule_id.fetch_add(1, Ordering::Relaxed)
    }

    /// The injected connection scanner.
    pub fn scanner(&self) -> &Arc<dyn ConnectionScanner> {
        &self.scanner
    }

    /// The metrics store handle, if history is enabled.
    pub fn metrics(&self) -> Option<&Arc<Mutex<MetricsStore>>> {
        self.metrics.as_ref()
    }

    /// The inventory store handle, if openbinary passthrough is enabled.
    pub fn inventory(&self) -> Option<&Arc<InventoryStore>> {
        self.inventory.as_ref()
    }

    /// Push a `Session`-duration rule into the in-memory set (R7).
    pub fn add_session_rule(&self, rule: SessionRule) {
        if let Ok(mut rules) = self.session_rules.lock() {
            rules.push(rule);
        }
    }

    /// Drop `Session` rules whose destination + process match `predicate` (R7).
    /// Returns the number removed.
    pub fn remove_session_rules(&self, mut predicate: impl FnMut(&SessionRule) -> bool) -> usize {
        let Ok(mut rules) = self.session_rules.lock() else {
            return 0;
        };
        let before = rules.len();
        rules.retain(|r| !predicate(r));
        before - rules.len()
    }

    /// Register an `Until` rule file for auto-clean at its deadline (R7).
    pub fn track_expiring(&self, path: PathBuf, expiry_ms: u64) {
        if let Ok(mut list) = self.expiring.lock() {
            list.push(ExpiringRule { path, expiry_ms });
        }
    }

    /// Atomically rebuild and swap the live rule set, then bump the generation
    /// (R7). Purges any `Until` files past their deadline first so a stale-deny
    /// cannot outlive its window across a reload.
    pub fn reload(&self) -> Result<u64> {
        self.purge_expired();
        let session = self
            .session_rules
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        // Snapshot the active-ban IP set from the in-memory engine (the engine
        // lock is taken and released inside `active_ban_ips`, before we compose
        // or take the ruleset lock). Never reopens the etch store, so the reload
        // cannot tear against a WAL compaction.
        let banned = self
            .banwatch
            .as_ref()
            .map(|bw| bw.active_ban_ips())
            .unwrap_or_default();
        let fresh = build_live_ruleset(&self.rules_dir, &session, &banned)?;
        let fresh = Arc::new(fresh);
        let mut guard = self
            .ruleset
            .write()
            .map_err(|_| ServerError::Reload("ruleset lock poisoned".to_owned()))?;
        *guard = fresh;
        let next_gen = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        Ok(next_gen)
    }

    /// Remove `Until` rule files whose deadline has passed.
    fn purge_expired(&self) {
        let now = now_ms().max(0) as u64;
        let Ok(mut list) = self.expiring.lock() else {
            return;
        };
        list.retain(|rule| {
            if rule.expiry_ms <= now {
                let _ = std::fs::remove_file(&rule.path);
                false
            } else {
                true
            }
        });
    }
}

/// Current unix time in milliseconds.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}
