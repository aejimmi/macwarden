#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

#[test]
fn test_threshold_full_within_window() {
    let mut ring = CircularTimestamps::new(3);
    ring.push(100);
    ring.push(150);
    assert!(!ring.threshold_reached(60), "not full yet");
    ring.push(160);
    assert!(ring.is_full());
    assert!(ring.threshold_reached(60), "span 60 <= find_time 60");
}

#[test]
fn test_threshold_not_reached_below_capacity() {
    let mut ring = CircularTimestamps::new(3);
    ring.push(100);
    ring.push(101);
    assert!(!ring.threshold_reached(600), "only 2 of 3");
}

#[test]
fn test_threshold_outside_window() {
    let mut ring = CircularTimestamps::new(2);
    ring.push(100);
    ring.push(800);
    assert!(ring.is_full());
    assert!(!ring.threshold_reached(600), "span 700 > 600");
}

#[test]
fn test_overwrites_oldest_never_grows() {
    let mut ring = CircularTimestamps::new(2);
    for ts in [10, 20, 30, 40] {
        ring.push(ts);
    }
    assert_eq!(ring.len(), 2);
    assert_eq!(ring.capacity(), 2);
    assert_eq!(ring.oldest(), Some(30));
    assert_eq!(ring.newest(), Some(40));
}

#[test]
fn test_sliding_window_ages_out() {
    // A fresh newest with an aged oldest fails threshold, but once the old
    // entry is overwritten the recent span passes.
    let mut ring = CircularTimestamps::new(3);
    ring.push(0);
    ring.push(1000);
    ring.push(1001);
    assert!(!ring.threshold_reached(60), "oldest=0 too far");
    ring.push(1002); // overwrites ts=0
    assert!(ring.threshold_reached(60), "1000..1002 within 60");
}

#[test]
fn test_clear_resets() {
    let mut ring = CircularTimestamps::new(2);
    ring.push(1);
    ring.push(2);
    ring.clear();
    assert!(ring.is_empty());
    assert_eq!(ring.oldest(), None);
    assert!(!ring.threshold_reached(0));
}

#[test]
fn test_zero_capacity_is_inert() {
    let mut ring = CircularTimestamps::new(0);
    ring.push(1);
    assert!(ring.is_empty());
    assert!(!ring.threshold_reached(i64::MAX));
}
