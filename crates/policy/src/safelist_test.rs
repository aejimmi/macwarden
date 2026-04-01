use super::*;

#[test]
fn test_is_critical_exact_match() {
    assert!(is_critical("com.apple.WindowServer"));
    assert!(is_critical("com.apple.securityd"));
    assert!(is_critical("com.apple.configd"));
    assert!(is_critical("com.apple.logd"));
    assert!(is_critical("com.apple.notifyd"));
    assert!(is_critical("com.apple.distnoted"));
    assert!(is_critical("com.apple.fseventsd"));
    assert!(is_critical("com.apple.SystemStarter"));
    assert!(is_critical("com.apple.kernelmanagerd"));
    assert!(is_critical("com.apple.coreservicesd"));
    assert!(is_critical("com.apple.opendirectoryd"));
    assert!(is_critical("com.apple.diskarbitrationd"));
}

#[test]
fn test_is_critical_glob_match() {
    // launchd* pattern
    assert!(is_critical("com.apple.launchd"));
    assert!(is_critical("com.apple.launchd.peruser.501"));

    // loginwindow* pattern
    assert!(is_critical("com.apple.loginwindow"));
    assert!(is_critical("com.apple.loginwindow.plist"));

    // xpc.* pattern
    assert!(is_critical("com.apple.xpc.launchd"));
    assert!(is_critical("com.apple.xpc.smd"));

    // IOKit* pattern
    assert!(is_critical("com.apple.IOKit"));
    assert!(is_critical("com.apple.IOKitUserClient"));
}

#[test]
fn test_is_critical_non_match() {
    assert!(!is_critical("com.apple.Siri.agent"));
    assert!(!is_critical("com.apple.analyticsd"));
    assert!(!is_critical("com.apple.Spotlight"));
    assert!(!is_critical("com.apple.GameController"));
    assert!(!is_critical("com.example.myapp"));
    assert!(!is_critical(""));
    assert!(!is_critical("com.apple"));
}

#[test]
fn test_validate_actions_all_safe() {
    let actions = vec![
        Action::Disable {
            label: "com.apple.Siri.agent".to_owned(),
        },
        Action::Kill {
            label: "com.apple.analyticsd".to_owned(),
            pid: 123,
        },
    ];
    let result = validate_actions(&actions);
    assert!(result.is_ok());
    assert_eq!(result.expect("should be ok").len(), 2);
}

#[test]
fn test_validate_actions_rejects_critical() {
    let actions = vec![
        Action::Disable {
            label: "com.apple.Siri.agent".to_owned(),
        },
        Action::Disable {
            label: "com.apple.WindowServer".to_owned(),
        },
        Action::Kill {
            label: "com.apple.launchd".to_owned(),
            pid: 1,
        },
    ];
    let result = validate_actions(&actions);
    assert!(result.is_err());
    let err = result.expect_err("should be err");
    assert_eq!(err.rejected.len(), 2);
    assert!(err.rejected.contains(&"com.apple.WindowServer".to_owned()));
    assert!(err.rejected.contains(&"com.apple.launchd".to_owned()));
}

#[test]
fn test_validate_actions_empty_list() {
    let actions: Vec<Action> = vec![];
    let result = validate_actions(&actions);
    assert!(result.is_ok());
    assert!(result.expect("should be ok").is_empty());
}

#[test]
fn test_validate_actions_all_critical() {
    let actions = vec![
        Action::Disable {
            label: "com.apple.WindowServer".to_owned(),
        },
        Action::Disable {
            label: "com.apple.securityd".to_owned(),
        },
    ];
    let result = validate_actions(&actions);
    assert!(result.is_err());
    let err = result.expect_err("should be err");
    assert_eq!(err.rejected.len(), 2);
}
