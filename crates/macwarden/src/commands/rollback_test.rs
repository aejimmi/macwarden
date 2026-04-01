use super::*;

// ---------------------------------------------------------------------------
// build_rollback_service_info
// ---------------------------------------------------------------------------

#[test]
fn test_build_rollback_service_info_sets_label() {
    let svc = build_rollback_service_info("com.apple.analyticsd");
    assert_eq!(svc.label, "com.apple.analyticsd");
}

#[test]
fn test_build_rollback_service_info_state_is_disabled() {
    let svc = build_rollback_service_info("com.apple.analyticsd");
    assert_eq!(svc.state, ServiceState::Disabled);
}

#[test]
fn test_build_rollback_service_info_no_pid() {
    let svc = build_rollback_service_info("com.apple.analyticsd");
    assert!(svc.pid.is_none());
}

#[test]
fn test_build_rollback_service_info_no_plist_path() {
    let svc = build_rollback_service_info("com.apple.analyticsd");
    assert!(svc.plist_path.is_none());
}

#[test]
fn test_build_rollback_service_info_safety_optional() {
    let svc = build_rollback_service_info("com.apple.analyticsd");
    assert_eq!(svc.safety, SafetyLevel::Optional);
}

// ---------------------------------------------------------------------------
// infer_rollback_domain
// ---------------------------------------------------------------------------

#[test]
fn test_infer_rollback_domain_defaults_to_user() {
    let domain = infer_rollback_domain("com.apple.analyticsd");
    assert_eq!(domain, Domain::User);
}

#[test]
fn test_infer_rollback_domain_system_label_still_user() {
    // Current heuristic defaults everything to User.
    let domain = infer_rollback_domain("com.apple.launchd");
    assert_eq!(domain, Domain::User);
}

// ---------------------------------------------------------------------------
// load_named / load_latest with snapshots
// ---------------------------------------------------------------------------

#[test]
fn test_load_latest_empty_dir() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SnapshotStore::new(tmp.path().to_path_buf());
    store.ensure_dir().unwrap();

    let result = load_latest(&store);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("no snapshots"),
        "expected 'no snapshots' error, got: {err_msg}"
    );
}

#[test]
fn test_load_named_not_found() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SnapshotStore::new(tmp.path().to_path_buf());
    store.ensure_dir().unwrap();

    let result = load_named(&store, "nonexistent");
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("not found"),
        "expected 'not found' error, got: {err_msg}"
    );
}

#[test]
fn test_load_latest_with_snapshot() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SnapshotStore::new(tmp.path().to_path_buf());
    store.ensure_dir().unwrap();

    let snapshot = snapshot::Snapshot {
        timestamp: "1234567890".to_owned(),
        profile_name: "test".to_owned(),
        entries: vec![snapshot::SnapshotEntry {
            label: "com.apple.analyticsd".to_owned(),
            prior_state: ServiceState::Running,
            action_taken: Action::Disable {
                label: "com.apple.analyticsd".to_owned(),
            },
        }],
    };
    store.write(&snapshot).unwrap();

    let loaded = load_latest(&store).unwrap();
    assert_eq!(loaded.profile_name, "test");
    assert_eq!(loaded.entries.len(), 1);
}

#[test]
fn test_load_named_with_snapshot() {
    let tmp = tempfile::TempDir::new().unwrap();
    let store = SnapshotStore::new(tmp.path().to_path_buf());
    store.ensure_dir().unwrap();

    let snapshot = snapshot::Snapshot {
        timestamp: "1234567890".to_owned(),
        profile_name: "my-profile".to_owned(),
        entries: vec![],
    };
    store.write(&snapshot).unwrap();

    let loaded = load_named(&store, "1234567890").unwrap();
    assert_eq!(loaded.profile_name, "my-profile");
}
