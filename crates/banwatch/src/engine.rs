//! The ban-state engine: the single owner of failure accounting and bans.
//!
//! Typed [`Signal`]s go in (from the detectors); [`BanEvent`]s come out (for
//! metrics + IPC push). All mutable state — the per-`(ip, detector)` failure
//! ring buffers and the etch-backed ban set — lives behind this one owner, so
//! the daemon serializes access with a single `Mutex` while the *enforcement*
//! read path (`net::loader` → [`crate::persist::active_ban_ips`]) reads the
//! shared etch store directly, never taking that lock.
//!
//! Every entry point is total: an ignored / already-banned IP is a no-op; a
//! persist failure is logged and yields no event rather than a panic.

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use tracing::warn;

use crate::ban_calc::{BanParams, calc_ban_time};
use crate::config::{BanwatchConfig, CONFIG_FILENAME, DetectorParams};
use crate::error::Result;
use crate::ignore::IgnoreSet;
use crate::persist::{self, BanStore};
use crate::record::{BanCount, BanEvent, BanRecord, BanSource, DETECTOR_MANUAL, Signal};
use crate::ring::CircularTimestamps;

/// A `(source_ip, detector_id)` failure-accounting key.
type FailKey = (IpAddr, String);

/// The ban-state engine.
pub struct Engine {
    config: BanwatchConfig,
    detector_params: HashMap<&'static str, DetectorParams>,
    ban_params: BanParams,
    ignore: IgnoreSet,
    store: Arc<BanStore>,
    failures: HashMap<FailKey, CircularTimestamps>,
}

impl Engine {
    /// Open the engine for a `~/.macwarden/` base directory: load
    /// `banwatch.toml` and open the etch ban store under `banwatch/`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::BanwatchError::Store`] if the ban store cannot be
    /// opened (config loading itself never fails — it falls open to defaults).
    pub fn open(base_dir: &Path) -> Result<Self> {
        let config = BanwatchConfig::load(&base_dir.join(CONFIG_FILENAME));
        let store = Arc::new(persist::open_store(&persist::store_dir(base_dir))?);
        Ok(Self::new(store, config))
    }

    /// Assemble an engine over an already-open store and resolved config
    /// (the seam tests inject through).
    #[must_use]
    pub fn new(store: Arc<BanStore>, config: BanwatchConfig) -> Self {
        let detector_params = config.detector_params();
        let ban_params = BanParams {
            ban_time: config.ban_time,
            increment: config.ban_time_increment,
            multipliers: config.ban_time_multipliers.clone(),
            maxtime: config.ban_time_maxtime,
        };
        let ignore = IgnoreSet::new(&config.ignoreip);
        Self {
            config,
            detector_params,
            ban_params,
            ignore,
            store,
            failures: HashMap::new(),
        }
    }

    /// Register the host's own addresses for the `ignore_self` guard.
    pub fn set_self_addrs(&mut self, addrs: Vec<IpAddr>) {
        if self.config.ignore_self {
            self.ignore.set_self_addrs(addrs);
        }
    }

    /// The shared ban store handle — the read surface `net::loader` composes.
    #[must_use]
    pub fn store(&self) -> &Arc<BanStore> {
        &self.store
    }

    /// The resolved configuration.
    #[must_use]
    pub fn config(&self) -> &BanwatchConfig {
        &self.config
    }

    /// Record one failure signal, returning a [`BanEvent::Banned`] when it trips
    /// the detector's `max_retry`-within-`find_time` threshold.
    #[must_use]
    pub fn record(&mut self, signal: &Signal, now: i64) -> Option<BanEvent> {
        if !self.config.enabled {
            return None;
        }
        let params = self.detector_params.get(signal.detector)?;
        if !params.enabled {
            return None;
        }
        if self.ignore.contains(signal.ip) {
            return None;
        }
        let (capacity, find_time) = (params.max_retry as usize, params.find_time);
        let key: FailKey = (signal.ip, signal.detector.to_owned());
        if self.is_banned(&key, now) {
            return None;
        }
        let ring = self
            .failures
            .entry(key)
            .or_insert_with(|| CircularTimestamps::new(capacity));
        ring.push(now);
        if !ring.threshold_reached(find_time) {
            return None;
        }
        ring.clear();
        let source = BanSource::from_detector(signal.detector);
        self.apply_ban(signal.ip, signal.detector, source, None, now)
    }

    /// Manually ban `ip`, overriding the failure counter (operator action over
    /// IPC). `ban_secs` overrides the computed duration; `None` uses the base /
    /// escalated ban time. Bypasses `ignoreip` by design — an explicit operator
    /// ban is trusted.
    #[must_use]
    pub fn manual_ban(&mut self, ip: IpAddr, ban_secs: Option<i64>, now: i64) -> Option<BanEvent> {
        self.apply_ban(ip, DETECTOR_MANUAL, BanSource::Manual, ban_secs, now)
    }

    /// Manually unban `ip`: drop every active ban for it across detectors and
    /// clear its failure buffers. Returns one [`BanEvent::Unbanned`] per removed
    /// ban.
    #[must_use]
    pub fn manual_unban(&mut self, ip: IpAddr, _now: i64) -> Vec<BanEvent> {
        let keys: Vec<FailKey> = self
            .store
            .read()
            .bans
            .keys()
            .filter(|(banned_ip, _)| *banned_ip == ip)
            .cloned()
            .collect();
        self.failures.retain(|(fip, _), _| *fip != ip);
        self.delete_bans(&keys)
    }

    /// Periodic sweep: unban expired bans, decay stale escalation counts, and
    /// prune stale failure buffers. Returns the unban events produced.
    #[must_use]
    pub fn sweep(&mut self, now: i64) -> Vec<BanEvent> {
        let events = self.expire_bans(now);
        self.decay_counts(now);
        self.prune_failures(now);
        events
    }

    /// All currently-active ban records, sorted by IP then detector.
    #[must_use]
    pub fn active_bans(&self, now: i64) -> Vec<BanRecord> {
        let mut records: Vec<BanRecord> = self
            .store
            .read()
            .bans
            .values()
            .filter(|rec| rec.is_active_at(now))
            .cloned()
            .collect();
        records.sort_by(|a, b| a.ip.cmp(&b.ip).then_with(|| a.detector.cmp(&b.detector)));
        records
    }

    // -- internals ----------------------------------------------------------

    /// Whether `key` currently maps to an active ban.
    fn is_banned(&self, key: &FailKey, now: i64) -> bool {
        self.store
            .read()
            .bans
            .get(key)
            .is_some_and(|rec| rec.is_active_at(now))
    }

    /// Persist a ban for `(ip, detector)` and return the event (or `None` if the
    /// write failed — logged, never panicked).
    fn apply_ban(
        &mut self,
        ip: IpAddr,
        detector: &str,
        source: BanSource,
        ban_secs: Option<i64>,
        now: i64,
    ) -> Option<BanEvent> {
        let count = self.store.read().ban_counts.get(&ip).map_or(0, |b| b.count);
        let dur = ban_secs.unwrap_or_else(|| calc_ban_time(count, &self.ban_params));
        // `saturating_add` so a huge `ban_secs` yields a far-future expiry (clamped
        // to `i64::MAX`) rather than panicking in debug or wrapping to a negative,
        // silently-expired "ban" in release. `dur < 0` still means "permanent".
        let expires_at = if dur < 0 {
            None
        } else {
            Some(now.saturating_add(dur))
        };
        let record = BanRecord {
            ip,
            detector: detector.to_owned(),
            banned_at: now,
            expires_at,
            escalation_count: count,
            source,
        };
        let key: FailKey = (ip, detector.to_owned());
        let written = record.clone();
        if let Err(e) = self.store.write(|tx| {
            tx.bans.put(key, record);
            tx.ban_counts.put(
                ip,
                BanCount {
                    count: count + 1,
                    last_ban: now,
                },
            );
            Ok(())
        }) {
            warn!(%ip, detector, error = %e, "ban persist failed; not banned");
            return None;
        }
        Some(BanEvent::Banned(written))
    }

    /// Delete the given ban keys, emitting one unban event per successful delete.
    fn delete_bans(&mut self, keys: &[FailKey]) -> Vec<BanEvent> {
        if keys.is_empty() {
            return Vec::new();
        }
        if let Err(e) = self.store.write(|tx| {
            for key in keys {
                tx.bans.delete(key);
            }
            Ok(())
        }) {
            warn!(error = %e, "unban persist failed; bans left in place");
            return Vec::new();
        }
        keys.iter()
            .map(|(ip, detector)| BanEvent::Unbanned {
                ip: *ip,
                detector: detector.clone(),
            })
            .collect()
    }

    /// Delete every ban whose expiry has passed.
    fn expire_bans(&mut self, now: i64) -> Vec<BanEvent> {
        let expired: Vec<FailKey> = self
            .store
            .read()
            .bans
            .iter()
            .filter(|(_, rec)| !rec.is_active_at(now))
            .map(|(key, _)| key.clone())
            .collect();
        self.delete_bans(&expired)
    }

    /// Reset escalation counts whose most recent ban predates the decay window,
    /// bounding the `ban_counts` map. `ban_count_decay <= 0` disables decay.
    fn decay_counts(&mut self, now: i64) {
        let decay = self.config.ban_count_decay;
        if decay <= 0 {
            return;
        }
        let stale: Vec<IpAddr> = self
            .store
            .read()
            .ban_counts
            .iter()
            .filter(|(_, bc)| bc.last_ban < now - decay)
            .map(|(ip, _)| *ip)
            .collect();
        if stale.is_empty() {
            return;
        }
        if let Err(e) = self.store.write(|tx| {
            for ip in &stale {
                tx.ban_counts.delete(ip);
            }
            Ok(())
        }) {
            warn!(error = %e, "escalation-count decay persist failed");
        }
    }

    /// Drop failure buffers whose newest timestamp already fell outside the
    /// detector's window (or whose detector no longer exists), bounding memory.
    fn prune_failures(&mut self, now: i64) {
        let params = &self.detector_params;
        self.failures
            .retain(|(_, detector), ring| match params.get(detector.as_str()) {
                Some(p) => ring
                    .newest()
                    .is_none_or(|newest| newest >= now - p.find_time),
                None => false,
            });
    }
}

#[cfg(test)]
#[path = "engine_test.rs"]
mod engine_test;
