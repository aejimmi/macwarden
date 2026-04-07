#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

fn sample_services() -> Vec<LaunchctlEntry> {
    vec![
        LaunchctlEntry {
            label: "com.apple.running".to_owned(),
            pid: Some(100),
            last_exit_status: Some(0),
        },
        LaunchctlEntry {
            label: "com.apple.stopped".to_owned(),
            pid: None,
            last_exit_status: Some(0),
        },
    ]
}

#[test]
fn test_mock_enumerate_returns_configured() {
    let mock = MockPlatform::new(sample_services(), SipState::Enabled);
    let entries = mock.enumerate().expect("enumerate should succeed");

    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].label, "com.apple.running");
    assert_eq!(entries[1].label, "com.apple.stopped");
}

#[test]
fn test_mock_disable_tracks_calls() {
    let mock = MockPlatform::new(vec![], SipState::Enabled);

    mock.disable("system", "com.apple.test")
        .expect("disable should succeed");
    mock.disable("gui/501", "com.apple.other")
        .expect("disable should succeed");

    let labels = mock.disabled_labels();
    assert_eq!(labels.len(), 2);
    assert_eq!(labels[0], "system/com.apple.test");
    assert_eq!(labels[1], "gui/501/com.apple.other");
}

#[test]
fn test_mock_enable_tracks_calls() {
    let mock = MockPlatform::new(vec![], SipState::Enabled);

    mock.enable("system", "com.apple.test")
        .expect("enable should succeed");

    let labels = mock.enabled_labels();
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0], "system/com.apple.test");
}

#[test]
fn test_mock_kill_tracks_pids() {
    let mock = MockPlatform::new(vec![], SipState::Enabled);

    mock.kill_process(42).expect("kill should succeed");
    mock.kill_process(99).expect("kill should succeed");

    let pids = mock.killed_pids();
    assert_eq!(pids, vec![42, 99]);
}

#[test]
fn test_mock_is_running() {
    let mock = MockPlatform::new(sample_services(), SipState::Enabled);

    assert!(
        mock.is_running("com.apple.running")
            .expect("should succeed")
    );
    assert!(
        !mock
            .is_running("com.apple.stopped")
            .expect("should succeed")
    );
    assert!(
        !mock
            .is_running("com.apple.unknown")
            .expect("should succeed")
    );
}

#[test]
fn test_mock_sip_status() {
    let mock = MockPlatform::new(vec![], SipState::Disabled);
    assert_eq!(
        mock.sip_status().expect("should succeed"),
        SipState::Disabled
    );
}
