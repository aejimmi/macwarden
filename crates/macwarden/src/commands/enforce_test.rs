#![allow(clippy::indexing_slicing)]

use super::*;

use launchd::MockPlatform;
use launchd::platform::SipState;
use policy::{Domain, SafetyLevel, ServiceCategory, ServiceInfo, ServiceState};

fn make_service(label: &str, domain: Domain, state: ServiceState, pid: Option<u32>) -> ServiceInfo {
    ServiceInfo {
        label: label.to_owned(),
        domain,
        plist_path: None,
        state,
        category: ServiceCategory::Telemetry,
        safety: SafetyLevel::Optional,
        description: None,
        pid,
    }
}

fn mock_platform() -> MockPlatform {
    MockPlatform::new(vec![], SipState::Enabled)
}

// ---------------------------------------------------------------------------
// enforce_disable
// ---------------------------------------------------------------------------

#[test]
fn test_enforce_disable_critical_service_skipped() {
    let svc = make_service(
        "com.apple.launchd",
        Domain::System,
        ServiceState::Running,
        Some(1),
    );
    let platform = mock_platform();

    enforce_disable(&svc, &platform, false, false);

    assert!(platform.disabled_labels().is_empty());
    assert!(platform.booted_out_targets().is_empty());
    assert!(platform.killed_pids().is_empty());
}

#[test]
fn test_enforce_disable_running_service_calls_all_three_steps() {
    let svc = make_service(
        "com.apple.analyticsd",
        Domain::System,
        ServiceState::Running,
        Some(42),
    );
    let platform = mock_platform();

    enforce_disable(&svc, &platform, false, false);

    assert_eq!(
        platform.disabled_labels(),
        vec!["system/com.apple.analyticsd"]
    );
    assert_eq!(
        platform.booted_out_targets(),
        vec!["system/com.apple.analyticsd"]
    );
    assert_eq!(platform.killed_pids(), vec![42]);
}

#[test]
fn test_enforce_disable_stopped_service_no_kill() {
    let svc = make_service(
        "com.apple.analyticsd",
        Domain::System,
        ServiceState::Stopped,
        None,
    );
    let platform = mock_platform();

    enforce_disable(&svc, &platform, false, false);

    assert_eq!(
        platform.disabled_labels(),
        vec!["system/com.apple.analyticsd"]
    );
    assert_eq!(
        platform.booted_out_targets(),
        vec!["system/com.apple.analyticsd"]
    );
    assert!(platform.killed_pids().is_empty());
}

#[test]
fn test_enforce_disable_dry_run_calls_nothing() {
    let svc = make_service(
        "com.apple.analyticsd",
        Domain::System,
        ServiceState::Running,
        Some(42),
    );
    let platform = mock_platform();

    enforce_disable(&svc, &platform, true, false);

    assert!(platform.disabled_labels().is_empty());
    assert!(platform.booted_out_targets().is_empty());
    assert!(platform.killed_pids().is_empty());
}

#[test]
fn test_enforce_disable_quiet_mode_does_not_panic() {
    let svc = make_service(
        "com.apple.analyticsd",
        Domain::System,
        ServiceState::Running,
        Some(42),
    );
    let platform = mock_platform();

    enforce_disable(&svc, &platform, false, true);

    assert_eq!(platform.disabled_labels().len(), 1);
}

#[test]
fn test_enforce_disable_user_domain_uses_gui() {
    let svc = make_service(
        "com.apple.Siri.agent",
        Domain::User,
        ServiceState::Running,
        Some(99),
    );
    let platform = mock_platform();

    enforce_disable(&svc, &platform, false, false);

    let disabled = platform.disabled_labels();
    assert_eq!(disabled.len(), 1);
    assert!(disabled[0].starts_with("gui/"));
}

// ---------------------------------------------------------------------------
// enforce_enable
// ---------------------------------------------------------------------------

#[test]
fn test_enforce_enable_calls_platform() {
    let svc = make_service(
        "com.apple.Siri.agent",
        Domain::User,
        ServiceState::Disabled,
        None,
    );
    let platform = mock_platform();

    enforce_enable(&svc, &platform, false, false);

    let enabled = platform.enabled_labels();
    assert_eq!(enabled.len(), 1);
    assert!(enabled[0].starts_with("gui/"));
    assert!(enabled[0].ends_with("com.apple.Siri.agent"));
}

#[test]
fn test_enforce_enable_dry_run_calls_nothing() {
    let svc = make_service(
        "com.apple.Siri.agent",
        Domain::User,
        ServiceState::Disabled,
        None,
    );
    let platform = mock_platform();

    enforce_enable(&svc, &platform, true, false);

    assert!(platform.enabled_labels().is_empty());
}

// ---------------------------------------------------------------------------
// domain_string
// ---------------------------------------------------------------------------

#[test]
fn test_domain_string_system() {
    let svc = make_service(
        "com.apple.logd",
        Domain::System,
        ServiceState::Running,
        None,
    );
    assert_eq!(domain_string(&svc), "system");
}

#[test]
fn test_domain_string_user_returns_gui() {
    let svc = make_service(
        "com.apple.Siri.agent",
        Domain::User,
        ServiceState::Running,
        None,
    );
    let result = domain_string(&svc);
    assert!(result.starts_with("gui/"), "expected gui/UID, got {result}");
}

#[test]
fn test_domain_string_global_returns_gui() {
    let svc = make_service(
        "com.apple.some.agent",
        Domain::Global,
        ServiceState::Running,
        None,
    );
    let result = domain_string(&svc);
    assert!(result.starts_with("gui/"), "expected gui/UID, got {result}");
}

// ---------------------------------------------------------------------------
// timestamp_now
// ---------------------------------------------------------------------------

#[test]
fn test_timestamp_now_is_numeric() {
    let ts = timestamp_now();
    assert!(
        ts.parse::<u64>().is_ok(),
        "expected numeric timestamp, got {ts}"
    );
}

#[test]
fn test_timestamp_now_is_reasonable() {
    let ts: u64 = timestamp_now().parse().unwrap();
    // Should be after 2024-01-01 (1704067200) and before 2030-01-01 (1893456000).
    assert!(ts > 1_704_067_200, "timestamp too old: {ts}");
    assert!(ts < 1_893_456_000, "timestamp too far in future: {ts}");
}

// ---------------------------------------------------------------------------
// write_snapshot
// ---------------------------------------------------------------------------

#[test]
#[allow(unsafe_code)]
fn test_write_snapshot_creates_file() {
    let tmp = tempfile::TempDir::new().unwrap();
    // Override HOME so expand_home points to our temp dir.
    let home = tmp.path().to_str().unwrap().to_owned();
    // SAFETY: test runs single-threaded; no other thread reads HOME concurrently.
    unsafe { std::env::set_var("HOME", &home) };

    let svc = make_service(
        "com.apple.analyticsd",
        Domain::System,
        ServiceState::Running,
        Some(42),
    );
    let targets = vec![&svc];

    let result = write_snapshot("test-profile", &targets);
    assert!(result.is_ok(), "write_snapshot failed: {result:?}");

    let snap_dir = tmp.path().join(".local/share/macwarden/snapshots");
    assert!(snap_dir.exists(), "snapshot directory not created");

    let files: Vec<_> = std::fs::read_dir(&snap_dir)
        .expect("snapshot dir must be readable")
        .filter_map(Result::ok)
        .collect();
    assert_eq!(files.len(), 1, "expected exactly one snapshot file");
}

// ---------------------------------------------------------------------------
// run_shell_commands
// ---------------------------------------------------------------------------

#[test]
fn test_run_shell_commands_dry_run_does_not_execute() {
    // If this actually executed, `false` would fail the test.
    run_shell_commands(&["false".to_owned()], true);
}
