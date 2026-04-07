#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

use crate::types::SnapshotEntry;
use policy::{Action, ServiceState};
use tempfile::TempDir;

fn make_snapshot(timestamp: &str, profile: &str) -> Snapshot {
    Snapshot {
        timestamp: timestamp.to_owned(),
        profile_name: profile.to_owned(),
        entries: vec![SnapshotEntry {
            label: "com.apple.Siri.agent".to_owned(),
            prior_state: ServiceState::Running,
            action_taken: Action::Disable {
                label: "com.apple.Siri.agent".to_owned(),
            },
        }],
    }
}

#[test]
fn test_write_read_roundtrip() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let store = SnapshotStore::new(tmp.path().join("snapshots"));

    let original = make_snapshot("2025-01-15T10:30:00Z", "minimal");
    let path = store.write(&original).expect("write should succeed");

    assert!(path.exists());
    assert!(path.to_string_lossy().contains("2025-01-15T10:30:00Z.json"));

    let loaded = store.read(&path).expect("read should succeed");
    assert_eq!(loaded.timestamp, original.timestamp);
    assert_eq!(loaded.profile_name, original.profile_name);
    assert_eq!(loaded.entries.len(), 1);
    assert_eq!(loaded.entries[0].label, "com.apple.Siri.agent");
}

#[test]
fn test_latest_returns_most_recent() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let store = SnapshotStore::new(tmp.path().join("snapshots"));

    let older = make_snapshot("2025-01-10T08:00:00Z", "relaxed");
    let newer = make_snapshot("2025-01-15T12:00:00Z", "strict");

    store.write(&older).expect("write older");
    store.write(&newer).expect("write newer");

    let latest = store
        .latest()
        .expect("latest should succeed")
        .expect("should have a snapshot");

    assert_eq!(latest.timestamp, "2025-01-15T12:00:00Z");
    assert_eq!(latest.profile_name, "strict");
}

#[test]
fn test_latest_empty_dir() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let store = SnapshotStore::new(tmp.path().join("snapshots"));
    store.ensure_dir().expect("ensure_dir should succeed");

    let result = store.latest().expect("latest should succeed");
    assert!(result.is_none());
}

#[test]
fn test_latest_nonexistent_dir() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let store = SnapshotStore::new(tmp.path().join("does-not-exist"));

    let result = store.latest().expect("latest should succeed");
    assert!(result.is_none());
}

#[test]
fn test_list_sorted() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let store = SnapshotStore::new(tmp.path().join("snapshots"));

    let snap_b = make_snapshot("2025-01-15T12:00:00Z", "b");
    let snap_a = make_snapshot("2025-01-10T08:00:00Z", "a");
    let snap_c = make_snapshot("2025-01-20T16:00:00Z", "c");

    // Write out of order
    store.write(&snap_b).expect("write b");
    store.write(&snap_a).expect("write a");
    store.write(&snap_c).expect("write c");

    let list = store.list().expect("list should succeed");
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].0, "2025-01-10T08:00:00Z");
    assert_eq!(list[1].0, "2025-01-15T12:00:00Z");
    assert_eq!(list[2].0, "2025-01-20T16:00:00Z");
}

#[test]
fn test_read_nonexistent_errors() {
    let tmp = TempDir::new().expect("failed to create temp dir");
    let store = SnapshotStore::new(tmp.path().join("snapshots"));

    let result = store.read(&tmp.path().join("no-such-file.json"));
    assert!(result.is_err());

    let err = result.expect_err("should be not found");
    assert!(
        matches!(err, SnapshotError::NotFound(_)),
        "expected NotFound, got: {err:?}"
    );
}
