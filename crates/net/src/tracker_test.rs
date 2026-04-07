#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::matcher::BreakageRisk;

#[test]
fn test_load_builtin_tracker_db() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");

    // All four categories must be present.
    assert!(db.category(TrackerCategory::Advertising).is_some());
    assert!(db.category(TrackerCategory::Analytics).is_some());
    assert!(db.category(TrackerCategory::Fingerprinting).is_some());
    assert!(db.category(TrackerCategory::Social).is_some());

    // Each category must have at least one domain.
    for cat in [
        TrackerCategory::Advertising,
        TrackerCategory::Analytics,
        TrackerCategory::Fingerprinting,
        TrackerCategory::Social,
    ] {
        let data = db.category(cat).expect("category should exist");
        assert!(
            !data.domains.is_empty(),
            "category {cat} should have domains"
        );
    }
}

#[test]
fn test_tracker_lookup_exact() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");

    let m = db
        .lookup("google-analytics.com")
        .expect("should match google-analytics.com");
    assert_eq!(m.category, TrackerCategory::Analytics);
    assert_eq!(m.domain.pattern, "google-analytics.com");
}

#[test]
fn test_tracker_lookup_subdomain() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");

    // "sdk.mixpanel.com" should match the "mixpanel.com" entry.
    let m = db
        .lookup("sdk.mixpanel.com")
        .expect("should match subdomain of mixpanel.com");
    assert_eq!(m.category, TrackerCategory::Analytics);
    assert!(
        m.domain.pattern.contains("mixpanel"),
        "matched pattern should be mixpanel, got: {}",
        m.domain.pattern,
    );
}

#[test]
fn test_tracker_lookup_miss() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");

    assert!(
        db.lookup("apple.com").is_none(),
        "apple.com should not be a tracker"
    );
}

#[test]
fn test_tracker_breakage_risk() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");

    let m = db.lookup("sentry.io").expect("should match sentry.io");
    assert_eq!(m.domain.breakage_risk, BreakageRisk::Degraded);
}

#[test]
fn test_tracker_stats() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");

    let stats = db.stats();
    assert_eq!(stats.len(), 4, "should have 4 categories");

    // Verify counts match actual data files.
    assert_eq!(
        stats[&TrackerCategory::Advertising],
        60,
        "advertising should have 60 domains"
    );
    assert_eq!(
        stats[&TrackerCategory::Analytics],
        62,
        "analytics should have 62 domains"
    );
    assert_eq!(
        stats[&TrackerCategory::Fingerprinting],
        44,
        "fingerprinting should have 44 domains"
    );
    assert_eq!(
        stats[&TrackerCategory::Social],
        49,
        "social should have 49 domains"
    );
}

// ---------------------------------------------------------------------------
// to_tracker_rules: count and validity
// ---------------------------------------------------------------------------

#[test]
fn test_to_tracker_rules_total_count() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");
    let rules = db
        .to_tracker_rules()
        .expect("to_tracker_rules should succeed");
    // Total: 60 + 62 + 44 + 49 = 215.
    assert_eq!(
        rules.len(),
        215,
        "should produce one TrackerRule per domain entry"
    );
}

#[test]
fn test_to_tracker_rules_patterns_are_valid() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");
    let rules = db
        .to_tracker_rules()
        .expect("to_tracker_rules should succeed");
    // Every rule should have a non-empty pattern string and category.
    for rule in &rules {
        assert!(
            !rule.pattern.as_str().is_empty(),
            "TrackerRule pattern should not be empty"
        );
        assert!(
            !rule.category.is_empty(),
            "TrackerRule category should not be empty"
        );
    }
}

#[test]
fn test_to_tracker_rules_categories_are_correct_strings() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");
    let rules = db
        .to_tracker_rules()
        .expect("to_tracker_rules should succeed");
    let valid_categories = ["advertising", "analytics", "fingerprinting", "social"];
    for rule in &rules {
        assert!(
            valid_categories.contains(&rule.category.as_str()),
            "unexpected category string: {}",
            rule.category
        );
    }
}

// ---------------------------------------------------------------------------
// BreakageRisk serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_breakage_risk_serde_round_trip() {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct W {
        risk: BreakageRisk,
    }
    for risk in [
        BreakageRisk::None,
        BreakageRisk::Degraded,
        BreakageRisk::Critical,
    ] {
        let w = W { risk };
        let s = toml::to_string(&w).expect("serialize");
        let back: W = toml::from_str(&s).expect("deserialize");
        assert_eq!(back.risk, risk, "round-trip failed for {risk:?}");
    }
}

#[test]
fn test_breakage_risk_display() {
    assert_eq!(BreakageRisk::None.to_string(), "none");
    assert_eq!(BreakageRisk::Degraded.to_string(), "degraded");
    assert_eq!(BreakageRisk::Critical.to_string(), "critical");
}

// ---------------------------------------------------------------------------
// TrackerCategory display and serde
// ---------------------------------------------------------------------------

#[test]
fn test_tracker_category_display() {
    assert_eq!(TrackerCategory::Advertising.to_string(), "advertising");
    assert_eq!(TrackerCategory::Analytics.to_string(), "analytics");
    assert_eq!(
        TrackerCategory::Fingerprinting.to_string(),
        "fingerprinting"
    );
    assert_eq!(TrackerCategory::Social.to_string(), "social");
}

#[test]
fn test_tracker_category_serde_round_trip() {
    #[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
    struct W {
        cat: TrackerCategory,
    }
    for cat in [
        TrackerCategory::Advertising,
        TrackerCategory::Analytics,
        TrackerCategory::Fingerprinting,
        TrackerCategory::Social,
    ] {
        let w = W { cat };
        let s = toml::to_string(&w).expect("serialize");
        let back: W = toml::from_str(&s).expect("deserialize");
        assert_eq!(back.cat, cat);
    }
}

// ---------------------------------------------------------------------------
// TrackerDatabase::lookup: no partial match
// ---------------------------------------------------------------------------

#[test]
fn test_tracker_lookup_no_partial_match() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");
    // "evildoubleclick.net" should NOT match "doubleclick.net".
    assert!(
        db.lookup("evildoubleclick.net").is_none(),
        "evildoubleclick.net must not match doubleclick.net"
    );
}

#[test]
fn test_tracker_lookup_case_insensitive() {
    let db = TrackerDatabase::load_builtin().expect("builtin database should load");
    // "Google-Analytics.COM" should match the same as "google-analytics.com".
    let m = db.lookup("Google-Analytics.COM");
    assert!(m.is_some(), "tracker lookup should be case-insensitive");
}
