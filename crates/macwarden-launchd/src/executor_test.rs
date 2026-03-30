use super::*;

use crate::mock::MockPlatform;
use crate::platform::{LaunchctlEntry, SipState};

fn sample_actions() -> Vec<Action> {
    vec![
        Action::Disable {
            label: "com.apple.Siri.agent".to_owned(),
        },
        Action::Kill {
            label: "com.apple.analyticsd".to_owned(),
            pid: 42,
        },
        Action::Enable {
            label: "com.apple.restored".to_owned(),
        },
    ]
}

#[test]
fn test_execute_actions_dry_run_no_platform_calls() {
    let mock = MockPlatform::new(vec![], SipState::Enabled);
    let actions = sample_actions();

    let results = execute_actions(&mock, &actions, "system", true);

    assert_eq!(results.len(), 3);
    for r in &results {
        assert!(r.success, "all dry-run results should be successful");
        assert!(r.error.is_none());
    }

    // No actual platform calls should have been made
    assert!(mock.disabled_labels().is_empty());
    assert!(mock.killed_pids().is_empty());
    assert!(mock.enabled_labels().is_empty());
}

#[test]
fn test_execute_actions_real_mode_calls_platform() {
    let mock = MockPlatform::new(
        vec![LaunchctlEntry {
            label: "com.apple.analyticsd".to_owned(),
            pid: Some(42),
            last_exit_status: Some(0),
        }],
        SipState::Enabled,
    );
    let actions = sample_actions();

    let results = execute_actions(&mock, &actions, "system", false);

    assert_eq!(results.len(), 3);
    for r in &results {
        assert!(r.success, "result for {} should be successful", r.label);
    }

    // Verify platform calls
    let disabled = mock.disabled_labels();
    assert_eq!(disabled.len(), 1);
    assert_eq!(disabled[0], "system/com.apple.Siri.agent");

    let killed = mock.killed_pids();
    assert_eq!(killed.len(), 1);
    assert_eq!(killed[0], 42);

    let enabled = mock.enabled_labels();
    assert_eq!(enabled.len(), 1);
    assert_eq!(enabled[0], "system/com.apple.restored");
}

#[test]
fn test_execute_actions_empty_list() {
    let mock = MockPlatform::new(vec![], SipState::Enabled);

    let results = execute_actions(&mock, &[], "system", false);

    assert!(results.is_empty());
}

#[test]
fn test_execute_actions_result_labels() {
    let mock = MockPlatform::new(vec![], SipState::Enabled);
    let actions = vec![Action::Disable {
        label: "com.example.test".to_owned(),
    }];

    let results = execute_actions(&mock, &actions, "gui/501", false);

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].label, "com.example.test");
    assert!(results[0].action.contains("disable"));

    let disabled = mock.disabled_labels();
    assert_eq!(disabled[0], "gui/501/com.example.test");
}
