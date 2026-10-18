//! Tests for the cumulative-counter → rate delta math.
#![allow(clippy::float_cmp)]

use std::time::Duration;

use super::*;

fn at(base: Instant, ms: u64) -> Instant {
    base + Duration::from_millis(ms)
}

#[test]
fn test_first_observation_has_zero_rate() {
    let mut tracker: RateTracker<&str> = RateTracker::default();
    let t0 = Instant::now();
    let rates = tracker.observe(&[("a", 1000, 500)], t0);
    assert_eq!(rates.get("a"), Some(&(0, 0)), "no baseline yet → rate 0");
}

#[test]
fn test_delta_over_one_second_is_bytes_per_second() {
    let mut tracker: RateTracker<&str> = RateTracker::default();
    let t0 = Instant::now();
    let _ = tracker.observe(&[("a", 1000, 500)], t0);
    let rates = tracker.observe(&[("a", 4000, 2500)], at(t0, 1000));
    assert_eq!(
        rates.get("a"),
        Some(&(3000, 2000)),
        "3000 in / 2000 out over 1s"
    );
}

#[test]
fn test_half_second_delta_scales_to_per_second() {
    let mut tracker: RateTracker<&str> = RateTracker::default();
    let t0 = Instant::now();
    let _ = tracker.observe(&[("a", 0, 0)], t0);
    // 1000 bytes over 500ms → 2000 B/s.
    let rates = tracker.observe(&[("a", 1000, 0)], at(t0, 500));
    assert_eq!(rates.get("a"), Some(&(2000, 0)));
}

#[test]
fn test_counter_reset_floors_rate_to_zero() {
    let mut tracker: RateTracker<&str> = RateTracker::default();
    let t0 = Instant::now();
    let _ = tracker.observe(&[("a", 9000, 9000)], t0);
    // Current < previous (socket closed, key reused) → not real throughput.
    let rates = tracker.observe(&[("a", 10, 10)], at(t0, 1000));
    assert_eq!(rates.get("a"), Some(&(0, 0)));
}

#[test]
fn test_sub_interval_sample_reuses_prior_rate() {
    let mut tracker: RateTracker<&str> = RateTracker::default();
    let t0 = Instant::now();
    let _ = tracker.observe(&[("a", 0, 0)], t0);
    // Establish a real rate at 1s: 1000 B/s in.
    let _ = tracker.observe(&[("a", 1000, 0)], at(t0, 1000));
    // A sample only 100ms later is below MIN_INTERVAL → reuse the last rate,
    // never divide by the tiny interval.
    let rates = tracker.observe(&[("a", 1100, 0)], at(t0, 1100));
    assert_eq!(rates.get("a"), Some(&(1000, 0)), "cached rate reused");
    // And the baseline was not advanced: measuring from 1s again over the full
    // second still yields a real rate.
    let rates = tracker.observe(&[("a", 3000, 0)], at(t0, 2000));
    assert_eq!(rates.get("a"), Some(&(2000, 0)), "baseline held at 1s mark");
}

#[test]
fn test_duplicate_keys_in_one_sample_are_summed() {
    let mut tracker: RateTracker<&str> = RateTracker::default();
    let t0 = Instant::now();
    let _ = tracker.observe(&[("a", 0, 0)], t0);
    let rates = tracker.observe(&[("a", 100, 0), ("a", 400, 0)], at(t0, 1000));
    assert_eq!(rates.get("a"), Some(&(500, 0)), "500 total over 1s");
}

#[test]
fn test_departed_key_is_dropped_from_tracking() {
    let mut tracker: RateTracker<&str> = RateTracker::default();
    let t0 = Instant::now();
    let _ = tracker.observe(&[("a", 0, 0), ("b", 0, 0)], t0);
    // Only "a" appears next tick; "b" must be forgotten (bounded memory).
    let _ = tracker.observe(&[("a", 1000, 0)], at(t0, 1000));
    // "b" reappears with a fresh baseline, so its first rate is 0 again.
    let rates = tracker.observe(&[("b", 5000, 0)], at(t0, 2000));
    assert_eq!(rates.get("b"), Some(&(0, 0)), "b restarts as a new key");
}
