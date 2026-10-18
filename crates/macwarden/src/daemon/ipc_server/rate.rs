//! Per-tick byte-rate deltas from cumulative `nettop` counters.
//!
//! `nettop` reports **cumulative** per-connection byte counters (kernel socket
//! totals, monotonic across `nettop` invocations). A totals view alone leaves
//! the panel's "Live" scope and Processes `NET` column flat, so this module
//! turns those totals into live rates the way the panel's old `LiveSource` did:
//! remember each key's previous cumulative bytes and the instant they were read,
//! and on the next sample divide the delta by the elapsed wall-clock time.
//!
//! # Robustness
//!
//! - **Counter resets** (a connection closing and its key being reused, a new
//!   pid, or a wrap) make the current cumulative value *smaller* than the
//!   remembered one. That is not real throughput, so the rate floors to `0`.
//! - **Sampling cadence.** `nettop` is sampled on a cadence, and two snapshot
//!   requests can arrive back-to-back; a near-zero elapsed would explode the
//!   rate. Below [`MIN_INTERVAL`] the previous rate is reused and the baseline
//!   is *not* advanced, so the next due sample still measures a real interval.
//! - **Bounded memory.** Only keys present in the latest sample are retained, so
//!   the map tracks the live connection set, never growing without bound.
//!
//! The tracker is generic over the key and takes the clock instant as a
//! parameter, so the delta math is exercised deterministically in tests without
//! `nettop`, root, or real sleeps.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// Minimum elapsed time before a fresh rate is computed. A sample arriving
/// sooner reuses the last rate rather than dividing by a near-zero interval.
const MIN_INTERVAL: Duration = Duration::from_millis(500);

/// The remembered baseline for one key: cumulative counters, when they were
/// read, and the last rate computed from them.
#[derive(Debug, Clone, Copy)]
struct Baseline {
    in_bytes: u64,
    out_bytes: u64,
    at: Instant,
    in_bps: u64,
    out_bps: u64,
}

/// Tracks cumulative byte counters per key and derives per-second rates.
#[derive(Debug)]
pub struct RateTracker<K> {
    prev: HashMap<K, Baseline>,
}

impl<K> Default for RateTracker<K> {
    fn default() -> Self {
        Self {
            prev: HashMap::new(),
        }
    }
}

impl<K: Eq + Hash + Clone> RateTracker<K> {
    /// Fold the current cumulative sample in and return each key's `(in_bps,
    /// out_bps)`. `sample` carries `(key, cumulative_in, cumulative_out)` triples;
    /// duplicate keys within one sample are summed. Only sampled keys are
    /// retained, so a departed connection stops being tracked.
    #[must_use]
    pub fn observe(&mut self, sample: &[(K, u64, u64)], now: Instant) -> HashMap<K, (u64, u64)> {
        let mut agg: HashMap<K, (u64, u64)> = HashMap::with_capacity(sample.len());
        for (key, in_bytes, out_bytes) in sample {
            let entry = agg.entry(key.clone()).or_insert((0, 0));
            entry.0 = entry.0.saturating_add(*in_bytes);
            entry.1 = entry.1.saturating_add(*out_bytes);
        }

        let mut rates = HashMap::with_capacity(agg.len());
        let mut next: HashMap<K, Baseline> = HashMap::with_capacity(agg.len());
        for (key, (in_bytes, out_bytes)) in agg {
            let baseline = advance(self.prev.get(&key), in_bytes, out_bytes, now);
            rates.insert(key.clone(), (baseline.in_bps, baseline.out_bps));
            next.insert(key, baseline);
        }
        self.prev = next;
        rates
    }
}

/// Compute the next baseline for a key from its prior one (if any). Reuses the
/// cached rate when the sample arrives before [`MIN_INTERVAL`], so a burst of
/// requests never divides a delta by a near-zero interval.
fn advance(prior: Option<&Baseline>, in_bytes: u64, out_bytes: u64, now: Instant) -> Baseline {
    let Some(prior) = prior else {
        return Baseline {
            in_bytes,
            out_bytes,
            at: now,
            in_bps: 0,
            out_bps: 0,
        };
    };
    let elapsed = now.saturating_duration_since(prior.at);
    if elapsed < MIN_INTERVAL {
        return *prior;
    }
    let secs = elapsed.as_secs_f64();
    Baseline {
        in_bytes,
        out_bytes,
        at: now,
        in_bps: bps(prior.in_bytes, in_bytes, secs),
        out_bps: bps(prior.out_bytes, out_bytes, secs),
    }
}

/// Bytes-per-second from a cumulative counter delta over `secs`.
///
/// A shrinking counter (reset / wrap / reused key) or a non-positive interval
/// yields `0` rather than a bogus spike.
#[must_use]
fn bps(prev: u64, cur: u64, secs: f64) -> u64 {
    if secs <= 0.0 || cur < prev {
        return 0;
    }
    ((cur - prev) as f64 / secs) as u64
}

#[cfg(test)]
#[path = "rate_test.rs"]
mod rate_test;
