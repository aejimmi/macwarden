#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use ipc::protocol::HistoryScope;
use metrics::{MetricEvent, MetricsStore};

use super::*;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

fn open_store() -> (tempfile::TempDir, MetricsStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = MetricsStore::open(&dir.path().join("metrics.db")).unwrap();
    (dir, store)
}

fn decided(app: &str, host: &str, action: &str, tracker: Option<&str>) -> MetricEvent {
    MetricEvent::ConnectionDecided {
        app_id: Some(app.to_owned()),
        dest_host: Some(host.to_owned()),
        dest_ip: "1.2.3.4".to_owned(),
        action: action.to_owned(),
        tier: "user_rule".to_owned(),
        rule_name: None,
        tracker_category: tracker.map(ToOwned::to_owned),
    }
}

#[test]
fn test_rollup_today_counts_and_bytes() {
    let (_dir, store) = open_store();
    let ts = now_ms() - 60_000;
    store
        .record_at(ts, &decided("com.x", "a.test", "deny", Some("advertising")))
        .unwrap();
    store
        .record_at(ts, &decided("com.x", "b.test", "allow", None))
        .unwrap();
    store
        .record_at(
            ts,
            &MetricEvent::BandwidthSampled {
                app_id: "com.x".to_owned(),
                down_bytes: 1000,
                up_bytes: 200,
            },
        )
        .unwrap();

    let buckets = build_history(&store, HistoryScope::Today, None, 0).unwrap();
    assert_eq!(buckets.len(), 1);
    let b = &buckets[0];
    assert_eq!(b.connections, 2);
    assert_eq!(b.denied, 1);
    assert_eq!(b.tracker_hits, 1);
    assert_eq!(b.down_bytes, 1000);
    assert_eq!(b.up_bytes, 200);
    assert!(b.app_id.is_none());
}

#[test]
fn test_hour_scope_excludes_old_events() {
    let (_dir, store) = open_store();
    let two_hours_ago = now_ms() - 2 * 3_600_000;
    store
        .record_at(two_hours_ago, &decided("com.x", "a.test", "deny", None))
        .unwrap();

    let buckets = build_history(&store, HistoryScope::Hour, None, 0).unwrap();
    assert_eq!(
        buckets[0].connections, 0,
        "events outside the hour are excluded"
    );
}

#[test]
fn test_per_app_today_scopes_to_one_app() {
    let (_dir, store) = open_store();
    let ts = now_ms() - 60_000;
    store
        .record_at(ts, &decided("com.y", "y.test", "deny", None))
        .unwrap();
    store
        .record_at(ts, &decided("com.z", "z.test", "allow", None))
        .unwrap();
    store
        .record_at(
            ts,
            &MetricEvent::BandwidthSampled {
                app_id: "com.y".to_owned(),
                down_bytes: 500,
                up_bytes: 100,
            },
        )
        .unwrap();

    let buckets = build_history(&store, HistoryScope::Today, Some("com.y"), 0).unwrap();
    let b = &buckets[0];
    assert_eq!(b.app_id.as_deref(), Some("com.y"));
    assert_eq!(b.connections, 1);
    assert_eq!(b.denied, 1);
    assert_eq!(b.down_bytes, 500);
    assert_eq!(b.up_bytes, 100);
}
