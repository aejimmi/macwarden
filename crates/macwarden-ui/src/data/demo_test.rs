#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

#[test]
fn test_demo_has_expected_apps() {
    let src = DemoSource::new();
    let apps = src.apps();
    assert!(apps.iter().any(|a| a.name == "Google Chrome"));
    assert!(apps.iter().any(|a| a.name == "Safari"));
    assert!(apps.iter().any(|a| a.name == "telemetryd"));
    assert!(apps.len() >= 6);
}

#[test]
fn test_tick_accumulates_totals_for_allowed_apps() {
    let mut src = DemoSource::new();
    let before = src.totals();
    src.tick();
    let after = src.totals();
    assert!(after.down_bytes > before.down_bytes);
    assert!(after.connections >= before.connections);
}

#[test]
fn test_totals_stay_bounded_and_match_app_sum() {
    let mut src = DemoSource::new();
    for _ in 0..2_000 {
        src.tick();
    }
    let totals = src.totals();
    let app_down: u64 = src.apps().iter().map(|a| a.down_bytes).sum();
    // Footer agrees with the Apps tab under the Today scope.
    assert_eq!(totals.down_bytes, app_down);
    // Never runs off into GB territory after thousands of ticks.
    assert!(totals.down_bytes < 1_000_000_000, "{}", totals.down_bytes);
}

#[test]
fn test_flow_reflects_app_state_after_ticks() {
    let mut src = DemoSource::new();
    for _ in 0..10 {
        src.tick();
    }
    let apps = src.apps();
    let chrome = apps
        .iter()
        .find(|a| a.name == "Google Chrome")
        .expect("chrome");
    assert!(matches!(chrome.flow, Flow::Active(_)));
    let telemetry = apps
        .iter()
        .find(|a| a.name == "telemetryd")
        .expect("telemetryd");
    assert_eq!(telemetry.flow, Flow::Zero);
    // Idle apps never light up their live domain rates.
    let spotify = apps.iter().find(|a| a.name == "Spotify").expect("spotify");
    assert!(spotify.domains.iter().all(|d| d.rate_bps == 0));
}

#[test]
fn test_blocked_app_domains_stay_zero_rate() {
    let mut src = DemoSource::new();
    for _ in 0..5 {
        src.tick();
    }
    let photoshop = src
        .apps()
        .into_iter()
        .find(|a| a.name == "Photoshop")
        .expect("photoshop present");
    assert!(!photoshop.allowed);
    assert!(photoshop.domains.iter().all(|d| d.rate_bps == 0));
}

#[test]
fn test_net_rows_sorted_by_rate_desc() {
    let mut src = DemoSource::new();
    src.tick();
    let rows = src.net_rows();
    assert!(!rows.is_empty());
    for pair in rows.windows(2) {
        assert!(pair[0].domain.rate_bps >= pair[1].domain.rate_bps);
    }
}

#[test]
fn test_app_detail_counts_verdicts() {
    let src = DemoSource::new();
    let detail = src.app_detail("com.google.Chrome").expect("chrome detail");
    assert_eq!(detail.name, "Google Chrome");
    // Chrome has 2 trackers among its 4 domains.
    assert_eq!(detail.denied_count, 2);
    assert_eq!(detail.allowed_count, 2);
}

#[test]
fn test_app_detail_missing_returns_none() {
    let src = DemoSource::new();
    assert!(src.app_detail("does.not.exist").is_none());
}

#[test]
fn test_domain_detail_lists_using_apps() {
    let src = DemoSource::new();
    let detail = src.domain_detail("googlevideo.com").expect("domain detail");
    assert!(detail.user.contains("Google Chrome"));
}

#[test]
fn test_proc_detail_falls_back_to_system_process() {
    let src = DemoSource::new();
    let detail = src.proc_detail("WindowServer").expect("windowserver");
    assert_eq!(detail.name, "WindowServer");
    assert_eq!(detail.signature, Signature::Apple);
}

#[test]
fn test_signature_for_apple_prefix() {
    let src = DemoSource::new();
    let detail = src.app_detail("com.apple.Safari").expect("safari");
    assert_eq!(detail.signature, Signature::Apple);
}
