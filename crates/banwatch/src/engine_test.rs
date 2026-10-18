#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]
use super::*;

use std::net::{IpAddr, Ipv4Addr};

use tempfile::TempDir;

use crate::config::{BanwatchConfig, DetectorParams};
use crate::persist::{open_store, store_dir};
use crate::record::{BanEvent, DETECTOR_REPEAT_BLOCKED, Signal};

fn ip(d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(203, 0, 113, d))
}

fn sig(d: u8) -> Signal {
    Signal::new(ip(d), DETECTOR_REPEAT_BLOCKED)
}

/// A config with a fast repeat-blocked detector (3 fails / 100 s) and small bans.
fn test_config() -> BanwatchConfig {
    let mut cfg = BanwatchConfig::default();
    cfg.ban_time = 100;
    cfg.ban_time_increment = true;
    cfg.ban_time_multipliers = vec![1, 2, 4];
    cfg.ban_time_maxtime = 1_000;
    cfg.ban_count_decay = 10_000;
    cfg.repeat_blocked = DetectorParams {
        enabled: true,
        max_retry: 3,
        find_time: 100,
    };
    cfg
}

fn engine_with(cfg: BanwatchConfig) -> (TempDir, Engine) {
    let dir = TempDir::new().unwrap();
    let store = open_store(&store_dir(dir.path())).unwrap();
    (dir, Engine::new(std::sync::Arc::new(store), cfg))
}

#[test]
fn test_bans_at_max_retry_within_find_time() {
    let (_d, mut eng) = engine_with(test_config());
    assert!(eng.record(&sig(1), 100).is_none());
    assert!(eng.record(&sig(1), 110).is_none(), "2 of 3");
    let event = eng.record(&sig(1), 120).expect("3rd fail bans");
    match event {
        BanEvent::Banned(rec) => {
            assert_eq!(rec.ip, ip(1));
            assert_eq!(rec.expires_at, Some(220), "base 100 from now=120");
        }
        BanEvent::Unbanned { .. } => panic!("expected ban, got unban"),
    }
}

#[test]
fn test_below_threshold_no_ban() {
    let (_d, mut eng) = engine_with(test_config());
    let _ = eng.record(&sig(1), 100);
    let _ = eng.record(&sig(1), 110);
    assert!(eng.active_bans(120).is_empty(), "2 of 3 -> no ban");
}

#[test]
fn test_failures_outside_window_age_out() {
    let (_d, mut eng) = engine_with(test_config());
    let _ = eng.record(&sig(1), 100);
    let _ = eng.record(&sig(1), 110);
    // Third failure far past find_time: oldest ages out, no ban.
    assert!(eng.record(&sig(1), 100_000).is_none());
    assert!(eng.active_bans(100_001).is_empty());
}

#[test]
fn test_escalation_on_repeat_bans() {
    let (_d, mut eng) = engine_with(test_config());
    // First ban at t=120, expires 220.
    for t in [100, 110, 120] {
        let _ = eng.record(&sig(1), t);
    }
    // Sweep past expiry to unban.
    let ev = eng.sweep(300);
    assert!(matches!(ev.as_slice(), [BanEvent::Unbanned { .. }]));
    // Second offense escalates: multiplier[1]=2 -> 200 s.
    for t in [300, 310, 320] {
        let _ = eng.record(&sig(1), t);
    }
    let bans = eng.active_bans(320);
    assert_eq!(bans.len(), 1);
    assert_eq!(bans[0].expires_at, Some(520), "escalated 200 from 320");
    assert_eq!(bans[0].escalation_count, 1);
}

#[test]
fn test_increment_disabled_stays_base() {
    let mut cfg = test_config();
    cfg.ban_time_increment = false;
    let (_d, mut eng) = engine_with(cfg);
    for t in [100, 110, 120] {
        let _ = eng.record(&sig(1), t);
    }
    let _ = eng.sweep(300);
    for t in [300, 310, 320] {
        let _ = eng.record(&sig(1), t);
    }
    let bans = eng.active_bans(320);
    assert_eq!(bans[0].expires_at, Some(420), "still base 100");
}

#[test]
fn test_decay_resets_escalation() {
    let mut cfg = test_config();
    cfg.ban_count_decay = 500;
    let (_d, mut eng) = engine_with(cfg);
    for t in [100, 110, 120] {
        let _ = eng.record(&sig(1), t);
    }
    let _ = eng.sweep(300); // unban
    // Quiet longer than decay window, then sweep: escalation count resets.
    let _ = eng.sweep(1_000);
    for t in [1_000, 1_010, 1_020] {
        let _ = eng.record(&sig(1), t);
    }
    let bans = eng.active_bans(1_020);
    assert_eq!(bans[0].escalation_count, 0, "re-bans from zero after decay");
    assert_eq!(bans[0].expires_at, Some(1_120));
}

#[test]
fn test_ignoreip_never_bans() {
    let mut cfg = test_config();
    cfg.ignoreip = vec!["203.0.113.0/24".to_owned()];
    let (_d, mut eng) = engine_with(cfg);
    for t in [100, 110, 120, 130] {
        assert!(eng.record(&sig(9), t).is_none());
    }
    assert!(eng.active_bans(130).is_empty());
}

#[test]
fn test_disabled_detector_no_ban() {
    let mut cfg = test_config();
    cfg.repeat_blocked.enabled = false;
    let (_d, mut eng) = engine_with(cfg);
    for t in [100, 110, 120] {
        assert!(eng.record(&sig(1), t).is_none());
    }
}

#[test]
fn test_master_disabled_no_ban() {
    let mut cfg = test_config();
    cfg.enabled = false;
    let (_d, mut eng) = engine_with(cfg);
    for t in [100, 110, 120] {
        assert!(eng.record(&sig(1), t).is_none());
    }
}

#[test]
fn test_already_banned_does_not_recount() {
    let (_d, mut eng) = engine_with(test_config());
    for t in [100, 110, 120] {
        let _ = eng.record(&sig(1), t);
    }
    // Further failures while banned produce no new event.
    assert!(eng.record(&sig(1), 130).is_none());
    assert_eq!(eng.active_bans(130).len(), 1);
}

#[test]
fn test_manual_ban_and_unban() {
    let (_d, mut eng) = engine_with(test_config());
    let ev = eng.manual_ban(ip(7), Some(500), 1_000).unwrap();
    match ev {
        BanEvent::Banned(rec) => {
            assert_eq!(rec.expires_at, Some(1_500));
            assert_eq!(rec.source, crate::record::BanSource::Manual);
        }
        BanEvent::Unbanned { .. } => panic!("expected ban, got unban"),
    }
    let unbans = eng.manual_unban(ip(7), 1_100);
    assert_eq!(unbans.len(), 1);
    assert!(eng.active_bans(1_100).is_empty());
}

#[test]
fn test_manual_ban_bypasses_ignore() {
    let mut cfg = test_config();
    cfg.ignoreip = vec!["203.0.113.0/24".to_owned()];
    let (_d, mut eng) = engine_with(cfg);
    // A signal is ignored, but an explicit manual ban still applies.
    assert!(eng.manual_ban(ip(9), Some(300), 100).is_some());
    assert_eq!(eng.active_bans(100).len(), 1);
}

#[test]
fn test_sweep_expires_and_persists() {
    let (_d, mut eng) = engine_with(test_config());
    for t in [100, 110, 120] {
        let _ = eng.record(&sig(1), t);
    }
    assert_eq!(eng.active_bans(200).len(), 1);
    let events = eng.sweep(500);
    assert_eq!(events.len(), 1);
    assert!(eng.active_bans(500).is_empty());
    // The store no longer holds the ban.
    assert!(eng.store().read().bans.is_empty());
}

#[test]
fn test_persist_survives_engine_reopen() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    {
        let store = open_store(&store_dir(base)).unwrap();
        let mut eng = Engine::new(std::sync::Arc::new(store), test_config());
        for t in [100, 110, 120] {
            let _ = eng.record(&sig(1), t);
        }
        assert_eq!(eng.active_bans(120).len(), 1);
    }
    // Reopen the store (simulated daemon restart): the ban is still there.
    let store = open_store(&store_dir(base)).unwrap();
    let eng = Engine::new(std::sync::Arc::new(store), test_config());
    let bans = eng.active_bans(150);
    assert_eq!(bans.len(), 1, "ban survives restart");
    assert_eq!(bans[0].ip, ip(1));
}

#[test]
fn test_active_ban_ips_reads_engine_writes() {
    let dir = TempDir::new().unwrap();
    let base = dir.path();
    let store = open_store(&store_dir(base)).unwrap();
    let mut eng = Engine::new(std::sync::Arc::new(store), test_config());
    // Use wall-clock timestamps so the ban is still active when the shared
    // read surface (which filters by the real clock) opens a second handle
    // while the engine's store is still live — the concurrent-open path
    // net::loader relies on.
    let now = crate::now_secs();
    for t in [now, now + 1, now + 2] {
        let _ = eng.record(&sig(4), t);
    }
    assert_eq!(eng.active_bans(now + 2).len(), 1, "engine banned");
    let ips = crate::active_ban_ips(base);
    assert!(
        ips.contains(&ip(4)),
        "loader read surface sees the live ban"
    );
}

#[test]
fn test_manual_ban_huge_duration_saturates_not_overflows() {
    // A caller-supplied `ban_secs` near `i64::MAX` must not panic (debug) or wrap
    // to a negative, immediately-expired expiry (release). It clamps to a
    // far-future expiry via `saturating_add`.
    let (_d, mut eng) = engine_with(test_config());
    let now = 1_000_000_000;
    let event = eng
        .manual_ban(ip(9), Some(i64::MAX), now)
        .expect("manual ban applies");
    match event {
        BanEvent::Banned(rec) => {
            let exp = rec
                .expires_at
                .expect("finite huge duration yields an expiry");
            assert_eq!(exp, i64::MAX, "huge duration saturates to i64::MAX");
            assert!(
                exp > now,
                "expiry is far in the future, never negative/past"
            );
            // The ban is genuinely active now (not silently expired).
            assert!(rec.is_active_at(now + 1));
        }
        BanEvent::Unbanned { .. } => panic!("expected ban"),
    }
    // And it is enforced: the active set and loader surface both report it.
    assert_eq!(eng.active_bans(now + 1).len(), 1, "huge ban is active");
}

#[test]
fn test_manual_ban_negative_duration_is_permanent() {
    // A negative duration still means "permanent" (no expiry), unchanged.
    let (_d, mut eng) = engine_with(test_config());
    let event = eng.manual_ban(ip(8), Some(-1), 500).expect("applies");
    match event {
        BanEvent::Banned(rec) => assert_eq!(rec.expires_at, None, "negative = permanent"),
        BanEvent::Unbanned { .. } => panic!("expected ban"),
    }
}
