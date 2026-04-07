#![allow(clippy::indexing_slicing, clippy::float_cmp)]

use super::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn connection_event(
    app_id: &str,
    host: &str,
    action: &str,
    tier: &str,
    tracker_cat: Option<&str>,
) -> MetricEvent {
    MetricEvent::ConnectionDecided {
        app_id: Some(app_id.to_owned()),
        dest_host: Some(host.to_owned()),
        dest_ip: "1.2.3.4".to_owned(),
        action: action.to_owned(),
        tier: tier.to_owned(),
        rule_name: None,
        tracker_category: tracker_cat.map(str::to_owned),
    }
}

fn enforcement_event(label: &str) -> MetricEvent {
    MetricEvent::ServiceEnforced {
        label: label.to_owned(),
        action: "disable".to_owned(),
        source: "sweep".to_owned(),
        profile: "strict".to_owned(),
    }
}

fn drift_event(label: &str) -> MetricEvent {
    MetricEvent::ServiceDrift {
        label: label.to_owned(),
        expected: "disabled".to_owned(),
        actual: "running".to_owned(),
    }
}

fn sensor_event(device: &str, state: &str, code_id: Option<&str>) -> MetricEvent {
    MetricEvent::SensorTriggered {
        device: device.to_owned(),
        state: state.to_owned(),
        process_path: "/usr/bin/test".to_owned(),
        code_id: code_id.map(str::to_owned),
    }
}

// ---------------------------------------------------------------------------
// MetricEvent accessors
// ---------------------------------------------------------------------------

#[test]
fn test_event_kind_discriminants() {
    assert_eq!(enforcement_event("x").kind(), "service_enforced");
    assert_eq!(drift_event("x").kind(), "service_drift");
    assert_eq!(
        MetricEvent::SweepCompleted {
            duration_ms: 0,
            checked: 0,
            drift_count: 0
        }
        .kind(),
        "sweep_completed"
    );
    assert_eq!(
        sensor_event("camera", "active", None).kind(),
        "sensor_triggered"
    );
    assert_eq!(
        connection_event("a", "b", "allow", "default", None).kind(),
        "connection_decided"
    );
    assert_eq!(
        MetricEvent::EsStats {
            received: 0,
            allowed: 0,
            denied: 0,
            logged: 0,
            auto_allowed: 0
        }
        .kind(),
        "es_stats"
    );
}

#[test]
fn test_event_app_id() {
    assert_eq!(
        connection_event("com.apple.Safari", "x", "allow", "default", None).app_id(),
        Some("com.apple.Safari")
    );
    assert_eq!(
        sensor_event("camera", "active", Some("com.zoom.us")).app_id(),
        Some("com.zoom.us")
    );
    assert_eq!(enforcement_event("x").app_id(), None);
    assert_eq!(drift_event("x").app_id(), None);
}

#[test]
fn test_event_domain() {
    assert_eq!(
        connection_event("a", "example.com", "allow", "default", None).domain(),
        Some("example.com")
    );
    assert_eq!(enforcement_event("x").domain(), None);
}

#[test]
fn test_event_action() {
    assert_eq!(
        connection_event("a", "b", "deny", "default", None).action(),
        Some("deny")
    );
    assert_eq!(enforcement_event("x").action(), Some("disable"));
    assert_eq!(drift_event("x").action(), None);
}

#[test]
fn test_payload_json_roundtrip() {
    let event = connection_event("app", "host.com", "deny", "tracker", Some("analytics"));
    let json = event.payload_json().expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");
    assert_eq!(parsed["tracker_category"], "analytics");
    assert_eq!(parsed["dest_ip"], "1.2.3.4");
}

// ---------------------------------------------------------------------------
// TimeRange
// ---------------------------------------------------------------------------

#[test]
fn test_time_range_new_valid() {
    let range = TimeRange::new(100, 200).expect("valid");
    assert_eq!(range.start, 100);
    assert_eq!(range.end, 200);
}

#[test]
fn test_time_range_new_equal() {
    let range = TimeRange::new(100, 100).expect("equal is valid");
    assert_eq!(range.start, range.end);
}

#[test]
fn test_time_range_new_invalid() {
    let err = TimeRange::new(200, 100);
    assert!(err.is_err());
}

#[test]
fn test_time_range_last_hours() {
    let range = TimeRange::last_hours(24);
    let span = range.end - range.start;
    // Allow 1 second tolerance for test execution time.
    assert!((span - 24 * 3_600_000).unsigned_abs() < 1000);
}

#[test]
fn test_time_range_last_days() {
    let range = TimeRange::last_days(7);
    let span = range.end - range.start;
    assert!((span - 7 * 86_400_000).unsigned_abs() < 1000);
}

#[test]
fn test_time_range_all() {
    let range = TimeRange::all();
    assert_eq!(range.start, 0);
    assert_eq!(range.end, i64::MAX);
}

// ---------------------------------------------------------------------------
// Store: open and schema
// ---------------------------------------------------------------------------

#[test]
fn test_open_creates_db() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("sub/dir/metrics.db");
    let _store = MetricsStore::open(&path).expect("open");
    assert!(path.exists());
}

#[test]
fn test_open_idempotent() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let path = tmp.path().join("metrics.db");

    let store1 = MetricsStore::open(&path).expect("first open");
    store1
        .record(&enforcement_event("com.apple.Siri"))
        .expect("record");
    drop(store1);

    let store2 = MetricsStore::open(&path).expect("second open");
    let summary = store2.summary(&TimeRange::all()).expect("summary");
    assert_eq!(summary.enforcements, 1, "data survives reopen");
}

// ---------------------------------------------------------------------------
// Store: record and count
// ---------------------------------------------------------------------------

#[test]
fn test_record_increases_count() {
    let store = MetricsStore::open_in_memory().expect("open");
    let before = store.summary(&TimeRange::all()).expect("summary");
    assert_eq!(before.total_events, 0);

    store
        .record(&enforcement_event("com.apple.Siri"))
        .expect("record");

    let after = store.summary(&TimeRange::all()).expect("summary");
    assert_eq!(after.total_events, 1);
}

#[test]
fn test_record_populates_columns_correctly() {
    let store = MetricsStore::open_in_memory().expect("open");
    let event = connection_event(
        "com.apple.Safari",
        "tracker.com",
        "deny",
        "tracker",
        Some("advertising"),
    );
    store.record(&event).expect("record");

    let summary = store.summary(&TimeRange::all()).expect("summary");
    assert_eq!(summary.connections_denied, 1);
    assert_eq!(
        *summary
            .tracker_hits_by_category
            .get("advertising")
            .unwrap_or(&0),
        1
    );
}

// ---------------------------------------------------------------------------
// Store: summary
// ---------------------------------------------------------------------------

#[test]
fn test_summary_empty_db() {
    let store = MetricsStore::open_in_memory().expect("open");
    let summary = store.summary(&TimeRange::all()).expect("summary");
    assert_eq!(summary.total_events, 0);
    assert_eq!(summary.connections_allowed, 0);
    assert_eq!(summary.connections_denied, 0);
    assert_eq!(summary.connections_logged, 0);
    assert_eq!(summary.enforcements, 0);
    assert_eq!(summary.drift_corrections, 0);
    assert!(summary.tracker_hits_by_category.is_empty());
}

#[test]
fn test_summary_mixed_events() {
    let store = MetricsStore::open_in_memory().expect("open");

    store
        .record(&connection_event(
            "app1", "good.com", "allow", "default", None,
        ))
        .expect("r1");
    store
        .record(&connection_event(
            "app1",
            "bad.com",
            "deny",
            "tracker",
            Some("analytics"),
        ))
        .expect("r2");
    store
        .record(&connection_event(
            "app2",
            "other.com",
            "allow",
            "group",
            None,
        ))
        .expect("r3");
    store
        .record(&connection_event(
            "app2",
            "ads.com",
            "deny",
            "tracker",
            Some("advertising"),
        ))
        .expect("r4");
    store
        .record(&enforcement_event("com.apple.Siri"))
        .expect("r5");
    store.record(&drift_event("com.apple.Siri")).expect("r6");

    let s = store.summary(&TimeRange::all()).expect("summary");
    assert_eq!(s.total_events, 6);
    assert_eq!(s.connections_allowed, 2);
    assert_eq!(s.connections_denied, 2);
    assert_eq!(s.enforcements, 1);
    assert_eq!(s.drift_corrections, 1);
    assert_eq!(
        *s.tracker_hits_by_category.get("analytics").unwrap_or(&0),
        1
    );
    assert_eq!(
        *s.tracker_hits_by_category.get("advertising").unwrap_or(&0),
        1
    );
}

// ---------------------------------------------------------------------------
// Store: time-range filtering
// ---------------------------------------------------------------------------

#[test]
fn test_summary_respects_time_range() {
    let store = MetricsStore::open_in_memory().expect("open");

    // Event at ts=1000.
    store
        .record_at(1000, &enforcement_event("early"))
        .expect("r1");
    // Event at ts=5000.
    store
        .record_at(5000, &enforcement_event("later"))
        .expect("r2");

    let range = TimeRange::new(2000, 6000).expect("range");
    let s = store.summary(&range).expect("summary");
    assert_eq!(s.enforcements, 1, "should exclude event at ts=1000");
}

// ---------------------------------------------------------------------------
// Store: app_stats
// ---------------------------------------------------------------------------

#[test]
fn test_app_stats_unknown_app() {
    let store = MetricsStore::open_in_memory().expect("open");
    let stats = store
        .app_stats("com.nobody.Nothing", &TimeRange::all())
        .expect("stats");
    assert_eq!(stats.connection_count, 0);
    assert_eq!(stats.denied_count, 0);
    assert_eq!(stats.tracker_hit_rate, 0.0);
    assert_eq!(stats.unique_domains, 0);
}

#[test]
fn test_app_stats_mixed_decisions() {
    let store = MetricsStore::open_in_memory().expect("open");
    let app = "com.apple.Safari";

    store
        .record(&connection_event(app, "good.com", "allow", "default", None))
        .expect("r1");
    store
        .record(&connection_event(
            app,
            "tracker.com",
            "deny",
            "tracker",
            Some("analytics"),
        ))
        .expect("r2");
    store
        .record(&connection_event(
            app,
            "another.com",
            "allow",
            "group",
            None,
        ))
        .expect("r3");
    // Different app — should not be counted.
    store
        .record(&connection_event(
            "com.other.App",
            "x.com",
            "deny",
            "default",
            None,
        ))
        .expect("r4");

    let stats = store.app_stats(app, &TimeRange::all()).expect("stats");
    assert_eq!(stats.connection_count, 3);
    assert_eq!(stats.denied_count, 1);
    assert_eq!(stats.unique_domains, 3);
    // 1 tracker hit out of 3 connections.
    assert!((stats.tracker_hit_rate - 1.0 / 3.0).abs() < f64::EPSILON);
}

// ---------------------------------------------------------------------------
// Store: top_blocked
// ---------------------------------------------------------------------------

#[test]
fn test_top_blocked_empty() {
    let store = MetricsStore::open_in_memory().expect("open");
    let result = store
        .top_blocked(&TimeRange::all(), 10)
        .expect("top_blocked");
    assert!(result.is_empty());
}

#[test]
fn test_top_blocked_ordering_and_limit() {
    let store = MetricsStore::open_in_memory().expect("open");

    // "ads.com" denied 3 times, "tracker.io" denied 2 times, "spam.net" denied 1 time.
    for _ in 0..3 {
        store
            .record(&connection_event(
                "app",
                "ads.com",
                "deny",
                "blocklist",
                None,
            ))
            .expect("record");
    }
    for _ in 0..2 {
        store
            .record(&connection_event(
                "app",
                "tracker.io",
                "deny",
                "tracker",
                None,
            ))
            .expect("record");
    }
    store
        .record(&connection_event(
            "app",
            "spam.net",
            "deny",
            "blocklist",
            None,
        ))
        .expect("record");
    // Allowed — should NOT appear.
    store
        .record(&connection_event(
            "app", "good.com", "allow", "default", None,
        ))
        .expect("record");

    let top2 = store
        .top_blocked(&TimeRange::all(), 2)
        .expect("top_blocked");
    assert_eq!(top2.len(), 2);
    assert_eq!(top2[0].domain, "ads.com");
    assert_eq!(top2[0].count, 3);
    assert_eq!(top2[1].domain, "tracker.io");
    assert_eq!(top2[1].count, 2);
}

// ---------------------------------------------------------------------------
// Store: top_talkers
// ---------------------------------------------------------------------------

#[test]
fn test_top_talkers_ordering() {
    let store = MetricsStore::open_in_memory().expect("open");

    // Safari: 4 connections (1 denied).
    for _ in 0..3 {
        store
            .record(&connection_event(
                "com.apple.Safari",
                "x.com",
                "allow",
                "default",
                None,
            ))
            .expect("record");
    }
    store
        .record(&connection_event(
            "com.apple.Safari",
            "y.com",
            "deny",
            "tracker",
            None,
        ))
        .expect("record");

    // Chrome: 2 connections (2 denied).
    for _ in 0..2 {
        store
            .record(&connection_event(
                "com.google.Chrome",
                "z.com",
                "deny",
                "blocklist",
                None,
            ))
            .expect("record");
    }

    let top = store
        .top_talkers(&TimeRange::all(), 10)
        .expect("top_talkers");
    assert_eq!(top.len(), 2);
    assert_eq!(top[0].app_id, "com.apple.Safari");
    assert_eq!(top[0].connection_count, 4);
    assert_eq!(top[0].denied_count, 1);
    assert_eq!(top[1].app_id, "com.google.Chrome");
    assert_eq!(top[1].connection_count, 2);
    assert_eq!(top[1].denied_count, 2);
}

// ---------------------------------------------------------------------------
// Store: tracker_breakdown
// ---------------------------------------------------------------------------

#[test]
fn test_tracker_breakdown_empty() {
    let store = MetricsStore::open_in_memory().expect("open");
    let breakdown = store
        .tracker_breakdown(&TimeRange::all())
        .expect("breakdown");
    assert!(breakdown.is_empty());
}

#[test]
fn test_tracker_breakdown_counts() {
    let store = MetricsStore::open_in_memory().expect("open");

    store
        .record(&connection_event(
            "a",
            "t1.com",
            "deny",
            "tracker",
            Some("analytics"),
        ))
        .expect("r1");
    store
        .record(&connection_event(
            "a",
            "t2.com",
            "deny",
            "tracker",
            Some("analytics"),
        ))
        .expect("r2");
    store
        .record(&connection_event(
            "a",
            "t3.com",
            "deny",
            "tracker",
            Some("advertising"),
        ))
        .expect("r3");
    // No tracker category — should NOT appear.
    store
        .record(&connection_event("a", "ok.com", "allow", "default", None))
        .expect("r4");

    let breakdown = store
        .tracker_breakdown(&TimeRange::all())
        .expect("breakdown");
    assert_eq!(*breakdown.get("analytics").unwrap_or(&0), 2);
    assert_eq!(*breakdown.get("advertising").unwrap_or(&0), 1);
    assert!(!breakdown.contains_key("default"));
}

// ---------------------------------------------------------------------------
// Store: sensor_timeline
// ---------------------------------------------------------------------------

#[test]
fn test_sensor_timeline_empty() {
    let store = MetricsStore::open_in_memory().expect("open");
    let timeline = store.sensor_timeline(&TimeRange::all()).expect("timeline");
    assert!(timeline.is_empty());
}

#[test]
fn test_sensor_timeline_ordered() {
    let store = MetricsStore::open_in_memory().expect("open");

    store
        .record_at(3000, &sensor_event("camera", "active", Some("com.zoom.us")))
        .expect("r1");
    store
        .record_at(1000, &sensor_event("microphone", "active", None))
        .expect("r2");
    store
        .record_at(
            2000,
            &sensor_event("camera", "inactive", Some("com.zoom.us")),
        )
        .expect("r3");

    let timeline = store.sensor_timeline(&TimeRange::all()).expect("timeline");
    assert_eq!(timeline.len(), 3);
    assert_eq!(timeline[0].ts, 1000);
    assert_eq!(timeline[0].device, "microphone");
    assert_eq!(timeline[1].ts, 2000);
    assert_eq!(timeline[1].state, "inactive");
    assert_eq!(timeline[2].ts, 3000);
    assert_eq!(timeline[2].code_id.as_deref(), Some("com.zoom.us"));
}

// ---------------------------------------------------------------------------
// Store: pruning
// ---------------------------------------------------------------------------

#[test]
fn test_prune_removes_old_events() {
    let store = MetricsStore::open_in_memory().expect("open");

    // Insert an event at a known old timestamp (1 day ago - 1 ms).
    let one_day_ms = 86_400_000_i64;
    let now = now_epoch_ms();
    let old_ts = now - one_day_ms - 1;

    store
        .record_at(old_ts, &enforcement_event("old"))
        .expect("record old");
    store
        .record(&enforcement_event("recent"))
        .expect("record recent");

    let deleted = store
        .prune(Duration::from_millis(one_day_ms as u64))
        .expect("prune");
    assert_eq!(deleted, 1);

    let summary = store.summary(&TimeRange::all()).expect("summary");
    assert_eq!(summary.enforcements, 1, "only recent event remains");
}

#[test]
fn test_prune_empty_table() {
    let store = MetricsStore::open_in_memory().expect("open");
    let deleted = store.prune(Duration::from_secs(1)).expect("prune");
    assert_eq!(deleted, 0);
}

#[test]
fn test_prune_zero_duration_deletes_all() {
    let store = MetricsStore::open_in_memory().expect("open");
    store.record(&enforcement_event("a")).expect("record");
    store.record(&enforcement_event("b")).expect("record");

    let deleted = store.prune(Duration::ZERO).expect("prune");
    assert_eq!(deleted, 2);

    let summary = store.summary(&TimeRange::all()).expect("summary");
    assert_eq!(summary.total_events, 0);
}
