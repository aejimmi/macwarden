use super::*;

#[test]
fn test_domain_display() {
    assert_eq!(Domain::System.to_string(), "system");
    assert_eq!(Domain::User.to_string(), "user");
    assert_eq!(Domain::Global.to_string(), "global");
}

#[test]
fn test_service_state_display() {
    assert_eq!(ServiceState::Running.to_string(), "running");
    assert_eq!(ServiceState::Stopped.to_string(), "stopped");
    assert_eq!(ServiceState::Disabled.to_string(), "disabled");
    assert_eq!(ServiceState::Unknown.to_string(), "unknown");
}

#[test]
fn test_service_category_display() {
    assert_eq!(ServiceCategory::CoreOs.to_string(), "core-os");
    assert_eq!(ServiceCategory::Networking.to_string(), "networking");
    assert_eq!(ServiceCategory::Security.to_string(), "security");
    assert_eq!(ServiceCategory::Media.to_string(), "media");
    assert_eq!(ServiceCategory::Cloud.to_string(), "cloud");
    assert_eq!(ServiceCategory::Telemetry.to_string(), "telemetry");
    assert_eq!(ServiceCategory::Profiling.to_string(), "profiling");
    assert_eq!(ServiceCategory::Input.to_string(), "input");
    assert_eq!(ServiceCategory::Accessibility.to_string(), "accessibility");
    assert_eq!(ServiceCategory::Developer.to_string(), "developer");
    assert_eq!(ServiceCategory::ThirdParty.to_string(), "third-party");
    assert_eq!(ServiceCategory::Unknown.to_string(), "unknown");
}

#[test]
fn test_safety_level_display() {
    assert_eq!(SafetyLevel::Critical.to_string(), "critical");
    assert_eq!(SafetyLevel::Important.to_string(), "important");
    assert_eq!(SafetyLevel::Optional.to_string(), "optional");
    assert_eq!(SafetyLevel::Telemetry.to_string(), "telemetry");
}

#[test]
fn test_action_display() {
    let disable = Action::Disable {
        label: "com.apple.Siri".to_owned(),
    };
    assert_eq!(disable.to_string(), "disable com.apple.Siri");

    let enable = Action::Enable {
        label: "com.apple.Siri".to_owned(),
    };
    assert_eq!(enable.to_string(), "enable com.apple.Siri");

    let kill = Action::Kill {
        label: "com.apple.Siri".to_owned(),
        pid: 42,
    };
    assert_eq!(kill.to_string(), "kill com.apple.Siri (pid 42)");
}

#[test]
fn test_action_label() {
    let disable = Action::Disable {
        label: "com.apple.foo".to_owned(),
    };
    assert_eq!(disable.label(), "com.apple.foo");

    let kill = Action::Kill {
        label: "com.apple.bar".to_owned(),
        pid: 1,
    };
    assert_eq!(kill.label(), "com.apple.bar");
}

#[test]
fn test_service_info_display() {
    let svc = ServiceInfo {
        label: "com.apple.Siri.agent".to_owned(),
        domain: Domain::User,
        plist_path: None,
        state: ServiceState::Running,
        category: ServiceCategory::Telemetry,
        safety: SafetyLevel::Optional,
        description: None,
        pid: Some(123),
    };
    let display = svc.to_string();
    assert!(display.contains("com.apple.Siri.agent"));
    assert!(display.contains("user"));
    assert!(display.contains("running"));
    assert!(display.contains("telemetry"));
}

#[test]
fn test_service_info_serde_roundtrip() {
    let svc = ServiceInfo {
        label: "com.apple.test".to_owned(),
        domain: Domain::System,
        plist_path: Some("/Library/LaunchDaemons/com.apple.test.plist".into()),
        state: ServiceState::Running,
        category: ServiceCategory::CoreOs,
        safety: SafetyLevel::Critical,
        description: Some("Test service".to_owned()),
        pid: Some(42),
    };
    let json = serde_json::to_string(&svc).expect("should serialize");
    let deserialized: ServiceInfo = serde_json::from_str(&json).expect("should deserialize");
    assert_eq!(svc, deserialized);
}

#[test]
fn test_action_serde_roundtrip() {
    let actions = vec![
        Action::Disable {
            label: "com.apple.foo".to_owned(),
        },
        Action::Enable {
            label: "com.apple.bar".to_owned(),
        },
        Action::Kill {
            label: "com.apple.baz".to_owned(),
            pid: 99,
        },
    ];
    for action in &actions {
        let json = serde_json::to_string(action).expect("should serialize");
        let deserialized: Action = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(*action, deserialized);
    }
}

#[test]
fn test_domain_serde_roundtrip() {
    for domain in [Domain::System, Domain::User, Domain::Global] {
        let json = serde_json::to_string(&domain).expect("should serialize");
        let deserialized: Domain = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(domain, deserialized);
    }
}
