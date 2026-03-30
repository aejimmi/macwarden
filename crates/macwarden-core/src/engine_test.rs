use super::*;
use crate::profile::parse_profile_toml;
use crate::types::{Domain, SafetyLevel, ServiceCategory, ServiceInfo, ServiceState};

fn make_service(label: &str, category: ServiceCategory, state: ServiceState) -> ServiceInfo {
    ServiceInfo {
        label: label.to_owned(),
        domain: Domain::User,
        plist_path: None,
        state,
        category,
        safety: SafetyLevel::Optional,
        description: None,
        pid: if state == ServiceState::Running {
            Some(1234)
        } else {
            None
        },
    }
}

fn privacy_profile() -> Profile {
    parse_profile_toml(
        r#"
[profile]
name = "privacy"
description = "Disable telemetry and analytics"
extends = ["base"]

[rules]
deny = [
    "com.apple.analyticsd",
    "com.apple.Siri.*",
    "com.apple.assistant*",
]
allow = ["com.apple.analyticsd.special"]

[rules.categories]
telemetry = "deny"
core-os = "allow"

[enforcement]
action = "disable"
exec_policy = "allow"
"#,
    )
    .expect("should parse")
}

// ---- decide ----

#[test]
fn test_decide_explicit_deny() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.analyticsd",
        ServiceCategory::Telemetry,
        ServiceState::Running,
    );
    let decision = decide(&svc, &profile);
    match decision {
        Decision::Deny { reason } => {
            assert!(reason.contains("explicit deny"));
            assert!(reason.contains("com.apple.analyticsd"));
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn test_decide_explicit_allow() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.analyticsd.special",
        ServiceCategory::Telemetry,
        ServiceState::Running,
    );
    let decision = decide(&svc, &profile);
    match decision {
        Decision::Allow { reason } => {
            assert!(reason.contains("explicit allow"));
        }
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn test_decide_glob_deny() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.Siri.agent",
        ServiceCategory::Telemetry,
        ServiceState::Running,
    );
    let decision = decide(&svc, &profile);
    match decision {
        Decision::Deny { reason } => {
            assert!(reason.contains("glob pattern"));
            assert!(reason.contains("com.apple.Siri.*"));
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn test_decide_glob_deny_assistant() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.assistantd",
        ServiceCategory::Telemetry,
        ServiceState::Running,
    );
    let decision = decide(&svc, &profile);
    match decision {
        Decision::Deny { reason } => {
            assert!(reason.contains("glob pattern"));
            assert!(reason.contains("com.apple.assistant*"));
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn test_decide_category_deny() {
    let profile = privacy_profile();
    // A telemetry service not in the explicit deny list.
    let svc = make_service(
        "com.apple.diagnosticd.analytics",
        ServiceCategory::Telemetry,
        ServiceState::Running,
    );
    let decision = decide(&svc, &profile);
    match decision {
        Decision::Deny { reason } => {
            assert!(reason.contains("category rule"));
            assert!(reason.contains("telemetry"));
        }
        other => panic!("expected Deny, got {other:?}"),
    }
}

#[test]
fn test_decide_category_allow() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.coreservicesd",
        ServiceCategory::CoreOs,
        ServiceState::Running,
    );
    let decision = decide(&svc, &profile);
    match decision {
        Decision::Allow { reason } => {
            assert!(reason.contains("category rule"));
            assert!(reason.contains("core-os"));
        }
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn test_decide_default_allow() {
    let profile = privacy_profile();
    // A media service with no matching rule.
    let svc = make_service(
        "com.apple.coreaudiod",
        ServiceCategory::Media,
        ServiceState::Running,
    );
    let decision = decide(&svc, &profile);
    match decision {
        Decision::Allow { reason } => {
            assert!(reason.contains("default allow"));
        }
        other => panic!("expected Allow, got {other:?}"),
    }
}

#[test]
fn test_decide_explicit_deny_takes_precedence_over_allow() {
    // Explicit deny should win over category allow.
    let profile = parse_profile_toml(
        r#"
[profile]
name = "test"
description = "Test"

[rules]
deny = ["com.apple.specificservice"]
allow = []

[rules.categories]
core-os = "allow"

[enforcement]
action = "disable"
"#,
    )
    .expect("should parse");

    let svc = make_service(
        "com.apple.specificservice",
        ServiceCategory::CoreOs,
        ServiceState::Running,
    );
    let decision = decide(&svc, &profile);
    assert!(matches!(decision, Decision::Deny { .. }));
}

#[test]
fn test_decide_explicit_allow_overrides_category_deny() {
    let profile = parse_profile_toml(
        r#"
[profile]
name = "test"
description = "Test"

[rules]
deny = []
allow = ["com.apple.special.telemetry"]

[rules.categories]
telemetry = "deny"

[enforcement]
action = "disable"
"#,
    )
    .expect("should parse");

    let svc = make_service(
        "com.apple.special.telemetry",
        ServiceCategory::Telemetry,
        ServiceState::Running,
    );
    let decision = decide(&svc, &profile);
    assert!(matches!(decision, Decision::Allow { .. }));
}

// ---- diff ----

#[test]
fn test_diff_running_denied_service_produces_disable_and_kill() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.analyticsd",
        ServiceCategory::Telemetry,
        ServiceState::Running,
    );
    let actions = diff(&[svc], &profile);

    assert_eq!(actions.len(), 2);
    assert!(
        actions
            .iter()
            .any(|(_, a)| matches!(a, Action::Disable { .. }))
    );
    assert!(
        actions
            .iter()
            .any(|(_, a)| matches!(a, Action::Kill { .. }))
    );
}

#[test]
fn test_diff_stopped_denied_service_produces_disable_only() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.analyticsd",
        ServiceCategory::Telemetry,
        ServiceState::Stopped,
    );
    let actions = diff(&[svc], &profile);

    assert_eq!(actions.len(), 1);
    assert!(matches!(&actions[0].1, Action::Disable { .. }));
}

#[test]
fn test_diff_disabled_allowed_service_produces_no_action() {
    // macwarden should NOT re-enable services it didn't disable.
    // The user may have disabled them manually.
    let profile = privacy_profile();
    let mut svc = make_service(
        "com.apple.coreservicesd",
        ServiceCategory::CoreOs,
        ServiceState::Disabled,
    );
    svc.pid = None;
    let actions = diff(&[svc], &profile);

    assert!(actions.is_empty());
}

#[test]
fn test_diff_running_allowed_service_produces_no_action() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.coreservicesd",
        ServiceCategory::CoreOs,
        ServiceState::Running,
    );
    let actions = diff(&[svc], &profile);
    assert!(actions.is_empty());
}

#[test]
fn test_diff_stopped_allowed_service_produces_no_action() {
    let profile = privacy_profile();
    let mut svc = make_service(
        "com.apple.coreservicesd",
        ServiceCategory::CoreOs,
        ServiceState::Stopped,
    );
    svc.pid = None;
    let actions = diff(&[svc], &profile);
    assert!(actions.is_empty());
}

#[test]
fn test_diff_already_disabled_denied_produces_no_action() {
    let profile = privacy_profile();
    let mut svc = make_service(
        "com.apple.analyticsd",
        ServiceCategory::Telemetry,
        ServiceState::Disabled,
    );
    svc.pid = None;
    let actions = diff(&[svc], &profile);
    assert!(actions.is_empty());
}

#[test]
fn test_diff_log_only_produces_no_action() {
    let profile = parse_profile_toml(
        r#"
[profile]
name = "logging"
description = "Log only"

[rules]
deny = []
allow = []

[rules.categories]
telemetry = "log-only"

[enforcement]
action = "log-only"
"#,
    )
    .expect("should parse");

    let svc = make_service(
        "com.apple.analyticsd",
        ServiceCategory::Telemetry,
        ServiceState::Running,
    );
    let actions = diff(&[svc], &profile);
    assert!(actions.is_empty());
}

// ---- explain ----

#[test]
fn test_explain_denied_service() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.Siri.agent",
        ServiceCategory::Telemetry,
        ServiceState::Running,
    );
    let output = explain("com.apple.Siri.agent", &profile, &[svc]);

    assert!(output.starts_with("DENIED"));
    assert!(output.contains("com.apple.Siri.*"));
    assert!(output.contains("privacy"));
    assert!(output.contains("category: telemetry"));
    assert!(output.contains("safety: optional"));
}

#[test]
fn test_explain_allowed_service() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.coreservicesd",
        ServiceCategory::CoreOs,
        ServiceState::Running,
    );
    let output = explain("com.apple.coreservicesd", &profile, &[svc]);

    assert!(output.starts_with("ALLOWED"));
    assert!(output.contains("privacy"));
    assert!(output.contains("category: core-os"));
}

#[test]
fn test_explain_service_not_found() {
    let profile = privacy_profile();
    let output = explain("com.example.nonexistent", &profile, &[]);
    assert!(output.contains("not found"));
}

#[test]
fn test_explain_with_extends_note() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.analyticsd",
        ServiceCategory::Telemetry,
        ServiceState::Running,
    );
    let output = explain("com.apple.analyticsd", &profile, &[svc]);
    // The profile has extends = ["base"], so the note should appear.
    assert!(output.contains("inherited from base"));
}

#[test]
fn test_explain_default_allow() {
    let profile = privacy_profile();
    let svc = make_service(
        "com.apple.coreaudiod",
        ServiceCategory::Media,
        ServiceState::Running,
    );
    let output = explain("com.apple.coreaudiod", &profile, &[svc]);
    assert!(output.starts_with("ALLOWED"));
    assert!(output.contains("default"));
}
