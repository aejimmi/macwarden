#![allow(clippy::indexing_slicing)]

use crate::{MetricEvent, MetricsStore, TimeRange};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bandwidth_event(app_id: &str, down: u64, up: u64) -> MetricEvent {
    MetricEvent::BandwidthSampled {
        app_id: app_id.to_owned(),
        down_bytes: down,
        up_bytes: up,
    }
}

// ---------------------------------------------------------------------------
// MetricEvent: kind stability and payload round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_bandwidth_sampled_kind_stable() {
    assert_eq!(
        bandwidth_event("com.apple.Safari", 1, 2).kind(),
        "bandwidth_sampled"
    );
}

#[test]
fn test_bandwidth_sampled_app_id_accessor() {
    let event = bandwidth_event("com.apple.Safari", 10, 20);
    assert_eq!(event.app_id(), Some("com.apple.Safari"));
    assert_eq!(event.domain(), None);
    assert_eq!(event.action(), None);
}

#[test]
fn test_bandwidth_sampled_payload_roundtrip() {
    let event = bandwidth_event("com.example.App", 4096, 1024);
    let json = event.payload_json().expect("serialize");

    // Payload carries the tag plus the byte fields.
    let value: serde_json::Value = serde_json::from_str(&json).expect("parse value");
    assert_eq!(value["kind"], "bandwidth_sampled");
    assert_eq!(value["app_id"], "com.example.App");
    assert_eq!(value["down_bytes"], 4096);
    assert_eq!(value["up_bytes"], 1024);

    // Full typed round-trip: deserialize, then re-serialize to canonical JSON
    // and confirm every field survived unchanged.
    let parsed: MetricEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed.kind(), "bandwidth_sampled");
    assert_eq!(parsed.app_id(), Some("com.example.App"));
    assert!(matches!(parsed, MetricEvent::BandwidthSampled { .. }));
    assert_eq!(parsed.payload_json().expect("reserialize"), json);
}

// ---------------------------------------------------------------------------
// bandwidth_by_app
// ---------------------------------------------------------------------------

#[test]
fn test_bandwidth_by_app_empty() {
    let store = MetricsStore::open_in_memory().expect("open");
    let rows = store
        .bandwidth_by_app(&TimeRange::all())
        .expect("bandwidth_by_app");
    assert!(rows.is_empty());
}

#[test]
fn test_bandwidth_by_app_sums_across_samples_and_apps() {
    let store = MetricsStore::open_in_memory().expect("open");

    // Safari: two samples -> 300 down, 30 up.
    store
        .record(&bandwidth_event("com.apple.Safari", 100, 10))
        .expect("r1");
    store
        .record(&bandwidth_event("com.apple.Safari", 200, 20))
        .expect("r2");
    // Chrome: one sample -> 50 down, 5 up (less than Safari, so ordered second).
    store
        .record(&bandwidth_event("com.google.Chrome", 50, 5))
        .expect("r3");

    let rows = store
        .bandwidth_by_app(&TimeRange::all())
        .expect("bandwidth_by_app");
    assert_eq!(rows.len(), 2);
    // Ordered by download volume descending.
    assert_eq!(rows[0].app_id, "com.apple.Safari");
    assert_eq!(rows[0].down_bytes, 300);
    assert_eq!(rows[0].up_bytes, 30);
    assert_eq!(rows[1].app_id, "com.google.Chrome");
    assert_eq!(rows[1].down_bytes, 50);
    assert_eq!(rows[1].up_bytes, 5);
}

#[test]
fn test_bandwidth_by_app_excludes_out_of_range() {
    let store = MetricsStore::open_in_memory().expect("open");

    store
        .record_at(1000, &bandwidth_event("app", 100, 10))
        .expect("early");
    store
        .record_at(5000, &bandwidth_event("app", 200, 20))
        .expect("in range");

    let range = TimeRange::new(2000, 6000).expect("range");
    let rows = store.bandwidth_by_app(&range).expect("bandwidth_by_app");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].down_bytes, 200, "event at ts=1000 excluded");
    assert_eq!(rows[0].up_bytes, 20);
}

#[test]
fn test_bandwidth_by_app_ignores_other_event_kinds() {
    let store = MetricsStore::open_in_memory().expect("open");

    store
        .record(&MetricEvent::ConnectionDecided {
            app_id: Some("com.apple.Safari".to_owned()),
            dest_host: Some("example.com".to_owned()),
            dest_ip: "1.2.3.4".to_owned(),
            action: "allow".to_owned(),
            tier: "default".to_owned(),
            rule_name: None,
            tracker_category: None,
        })
        .expect("connection");
    store
        .record(&bandwidth_event("com.apple.Safari", 42, 7))
        .expect("bandwidth");

    let rows = store
        .bandwidth_by_app(&TimeRange::all())
        .expect("bandwidth_by_app");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].down_bytes, 42);
    assert_eq!(rows[0].up_bytes, 7);
}

// ---------------------------------------------------------------------------
// bandwidth_for_app
// ---------------------------------------------------------------------------

#[test]
fn test_bandwidth_for_app_unknown_returns_zero() {
    let store = MetricsStore::open_in_memory().expect("open");
    let bw = store
        .bandwidth_for_app("com.nobody.Nothing", &TimeRange::all())
        .expect("bandwidth_for_app");
    assert_eq!(bw.app_id, "com.nobody.Nothing");
    assert_eq!(bw.down_bytes, 0);
    assert_eq!(bw.up_bytes, 0);
}

#[test]
fn test_bandwidth_for_app_sums_only_target_app() {
    let store = MetricsStore::open_in_memory().expect("open");

    store
        .record(&bandwidth_event("com.apple.Safari", 100, 10))
        .expect("r1");
    store
        .record(&bandwidth_event("com.apple.Safari", 250, 25))
        .expect("r2");
    // Different app must not be counted.
    store
        .record(&bandwidth_event("com.google.Chrome", 999, 999))
        .expect("r3");

    let bw = store
        .bandwidth_for_app("com.apple.Safari", &TimeRange::all())
        .expect("bandwidth_for_app");
    assert_eq!(bw.down_bytes, 350);
    assert_eq!(bw.up_bytes, 35);
}

#[test]
fn test_bandwidth_for_app_respects_range() {
    let store = MetricsStore::open_in_memory().expect("open");

    store
        .record_at(1000, &bandwidth_event("app", 100, 10))
        .expect("early");
    store
        .record_at(5000, &bandwidth_event("app", 200, 20))
        .expect("in range");

    let range = TimeRange::new(2000, 6000).expect("range");
    let bw = store
        .bandwidth_for_app("app", &range)
        .expect("bandwidth_for_app");
    assert_eq!(bw.down_bytes, 200);
    assert_eq!(bw.up_bytes, 20);
}
