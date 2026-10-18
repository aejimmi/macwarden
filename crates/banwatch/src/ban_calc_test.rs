#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

fn params() -> BanParams {
    BanParams {
        ban_time: 100,
        increment: true,
        multipliers: vec![1, 2, 4, 8],
        maxtime: 1_000,
    }
}

#[test]
fn test_first_ban_is_base() {
    assert_eq!(calc_ban_time(0, &params()), 100);
}

#[test]
fn test_escalation_multiplies() {
    let p = params();
    assert_eq!(calc_ban_time(1, &p), 200);
    assert_eq!(calc_ban_time(2, &p), 400);
    assert_eq!(calc_ban_time(3, &p), 800);
}

#[test]
fn test_capped_at_maxtime() {
    let p = params();
    // count 3 -> 800, but a bigger multiplier would exceed the cap.
    let capped = BanParams {
        multipliers: vec![1, 100],
        ..p
    };
    assert_eq!(
        calc_ban_time(1, &capped),
        1_000,
        "100*100=10000 capped to 1000"
    );
}

#[test]
fn test_count_beyond_table_clamps_to_last() {
    let p = params();
    // count 9 clamps to index 3 (multiplier 8) -> 800.
    assert_eq!(calc_ban_time(9, &p), 800);
}

#[test]
fn test_increment_disabled_always_base() {
    let p = BanParams {
        increment: false,
        ..params()
    };
    assert_eq!(calc_ban_time(0, &p), 100);
    assert_eq!(calc_ban_time(5, &p), 100);
}

#[test]
fn test_permanent_base_passes_through() {
    let p = BanParams {
        ban_time: -1,
        ..params()
    };
    assert_eq!(calc_ban_time(3, &p), -1);
}

#[test]
fn test_empty_multipliers_use_power_of_two() {
    let p = BanParams {
        multipliers: vec![],
        maxtime: 0,
        ..params()
    };
    assert_eq!(calc_ban_time(0, &p), 100);
    assert_eq!(calc_ban_time(2, &p), 400);
    assert_eq!(calc_ban_time(3, &p), 800);
}

#[test]
fn test_no_cap_when_maxtime_zero() {
    let p = BanParams {
        multipliers: vec![1, 1000],
        maxtime: 0,
        ..params()
    };
    assert_eq!(calc_ban_time(1, &p), 100_000);
}
