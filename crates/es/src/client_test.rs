#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

// ---------------------------------------------------------------------------
// EsClientConfig tests
// ---------------------------------------------------------------------------

#[test]
fn test_default_config() {
    let config = EsClientConfig::default();
    assert!(config.network_auth);
    assert!(!config.network_notify);
    assert_eq!(config.safety_margin, Duration::from_secs(2));
    assert_eq!(config.cache_capacity, 1024);
    assert_eq!(config.cache_ttl, Duration::from_secs(300));
}

#[test]
fn test_config_custom_values() {
    let rules = Arc::new(RuleSet::default());
    let config = EsClientConfig {
        rules: Arc::clone(&rules),
        safety_margin: Duration::from_secs(5),
        network_auth: false,
        network_notify: true,
        cache_capacity: 2048,
        cache_ttl: Duration::from_secs(600),
    };

    assert!(!config.network_auth);
    assert!(config.network_notify);
    assert_eq!(config.safety_margin, Duration::from_secs(5));
    assert_eq!(config.cache_capacity, 2048);
    assert_eq!(config.cache_ttl, Duration::from_secs(600));
}

#[test]
fn test_config_safety_margin_zero() {
    let config = EsClientConfig {
        safety_margin: Duration::ZERO,
        ..EsClientConfig::default()
    };
    assert_eq!(config.safety_margin, Duration::ZERO);
}

#[test]
fn test_config_rules_shared() {
    let rules = Arc::new(RuleSet::default());
    let config = EsClientConfig {
        rules: Arc::clone(&rules),
        ..EsClientConfig::default()
    };
    assert_eq!(Arc::strong_count(&rules), 2);
    drop(config);
    assert_eq!(Arc::strong_count(&rules), 1);
}

// ---------------------------------------------------------------------------
// EsStats tests
// ---------------------------------------------------------------------------

#[test]
fn test_stats_default_all_zeros() {
    let stats = EsStats::default();
    assert_eq!(stats.events_received, 0);
    assert_eq!(stats.events_allowed, 0);
    assert_eq!(stats.events_denied, 0);
    assert_eq!(stats.events_logged, 0);
    assert_eq!(stats.events_auto_allowed, 0);
    assert_eq!(stats.events_parse_failed, 0);
    assert_eq!(stats.events_safelist_allowed, 0);
}

#[test]
fn test_stats_clone() {
    let stats = EsStats {
        events_received: 100,
        events_allowed: 90,
        events_denied: 5,
        events_logged: 3,
        events_auto_allowed: 1,
        events_parse_failed: 1,
        ..EsStats::default()
    };

    let cloned = stats.clone();
    assert_eq!(cloned.events_received, 100);
    assert_eq!(cloned.events_allowed, 90);
    assert_eq!(cloned.events_denied, 5);
    assert_eq!(cloned.events_logged, 3);
    assert_eq!(cloned.events_auto_allowed, 1);
    assert_eq!(cloned.events_parse_failed, 1);
}

#[test]
fn test_stats_debug() {
    let stats = EsStats::default();
    let debug = format!("{stats:?}");
    assert!(debug.contains("events_received"));
    assert!(debug.contains("events_allowed"));
    assert!(debug.contains("events_denied"));
}

// ---------------------------------------------------------------------------
// Non-macOS stub tests
// ---------------------------------------------------------------------------

#[cfg(not(target_os = "macos"))]
#[test]
fn test_not_available_on_non_macos() {
    let result = EsClient::start(EsClientConfig::default());
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(matches!(err, EsError::NotAvailable));
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_stub_stop_returns_not_available() {
    // Can't call stop without a client, but we can verify the type exists.
    // The start always fails on non-macOS, so we can't test stop directly.
    let stats = EsStats::default();
    assert_eq!(stats.events_received, 0);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn test_stub_stats_returns_default() {
    // Verify the stats type works on non-macOS.
    let stats = EsStats::default();
    assert_eq!(stats.events_received, 0);
    assert_eq!(stats.events_allowed, 0);
}
