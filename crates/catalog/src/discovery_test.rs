use super::*;

use std::io::Write;

/// Helper: write an XML plist to a file inside the given directory.
fn write_plist_file(dir: &std::path::Path, filename: &str, label: &str) {
    let content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>"#
    );

    let path = dir.join(filename);
    let mut file = std::fs::File::create(&path).expect("failed to create plist file");
    file.write_all(content.as_bytes())
        .expect("failed to write plist file");
}

#[test]
fn test_discover_plists_basic() {
    let dir = tempfile::TempDir::new().expect("failed to create temp dir");

    write_plist_file(dir.path(), "com.apple.test.plist", "com.apple.test");
    write_plist_file(dir.path(), "com.example.app.plist", "com.example.app");

    let results = discover_plists(&[dir.path().to_path_buf()]);
    assert_eq!(results.len(), 2, "should discover both plists");

    let labels: Vec<&str> = results.iter().map(|p| p.label.as_str()).collect();
    assert!(labels.contains(&"com.apple.test"));
    assert!(labels.contains(&"com.example.app"));
}

#[test]
fn test_discover_plists_skips_non_plist_files() {
    let dir = tempfile::TempDir::new().expect("failed to create temp dir");

    write_plist_file(dir.path(), "com.apple.test.plist", "com.apple.test");

    // Write a non-plist file.
    let txt_path = dir.path().join("readme.txt");
    std::fs::write(&txt_path, "not a plist").expect("failed to write txt");

    let results = discover_plists(&[dir.path().to_path_buf()]);
    assert_eq!(results.len(), 1, "should skip non-plist files");
    assert_eq!(results[0].label, "com.apple.test");
}

#[test]
fn test_discover_plists_skips_malformed() {
    let dir = tempfile::TempDir::new().expect("failed to create temp dir");

    write_plist_file(dir.path(), "good.plist", "com.apple.good");

    // Write a malformed plist.
    let bad_path = dir.path().join("bad.plist");
    std::fs::write(&bad_path, "this is not valid plist XML").expect("failed to write bad plist");

    let results = discover_plists(&[dir.path().to_path_buf()]);
    assert_eq!(results.len(), 1, "should skip malformed plists");
    assert_eq!(results[0].label, "com.apple.good");
}

#[test]
fn test_discover_plists_nonexistent_dir() {
    let results = discover_plists(&[PathBuf::from("/nonexistent/directory/path")]);
    assert!(
        results.is_empty(),
        "nonexistent dir should yield empty results"
    );
}

#[test]
fn test_discover_plists_multiple_dirs() {
    let dir1 = tempfile::TempDir::new().expect("failed to create temp dir 1");
    let dir2 = tempfile::TempDir::new().expect("failed to create temp dir 2");

    write_plist_file(dir1.path(), "svc1.plist", "com.example.svc1");
    write_plist_file(dir2.path(), "svc2.plist", "com.example.svc2");

    let results = discover_plists(&[dir1.path().to_path_buf(), dir2.path().to_path_buf()]);
    assert_eq!(results.len(), 2);
}

#[test]
fn test_annotate_services_with_known_service() {
    let toml = r#"
[[services]]
pattern = "com.apple.analyticsd"
description = "Apple analytics"
category = "telemetry"
safety = "telemetry"
"#;
    let db = AnnotationDb::load_from_toml(toml).expect("failed to parse TOML");

    let plists = vec![PlistInfo {
        label: "com.apple.analyticsd".to_string(),
        program: Some("/usr/libexec/analyticsd".to_string()),
        run_at_load: true,
        keep_alive: false,
        disabled: false,
        path: PathBuf::from("/Library/LaunchDaemons/com.apple.analyticsd.plist"),
    }];

    let services = annotate_services(&plists, &db);
    assert_eq!(services.len(), 1);

    let svc = &services[0];
    assert_eq!(svc.label, "com.apple.analyticsd");
    assert_eq!(svc.category, policy::ServiceCategory::Telemetry);
    assert_eq!(svc.safety, policy::SafetyLevel::Telemetry);
    assert_eq!(svc.description.as_deref(), Some("Apple analytics"));
    assert_eq!(svc.domain, policy::Domain::System);
}

#[test]
fn test_annotate_services_unknown_label() {
    let db = AnnotationDb::load_from_toml(
        r#"
[[services]]
pattern = "com.apple.analyticsd"
description = "Apple analytics"
category = "telemetry"
safety = "telemetry"
"#,
    )
    .expect("failed to parse TOML");

    let plists = vec![PlistInfo {
        label: "com.example.unknown".to_string(),
        program: None,
        run_at_load: false,
        keep_alive: false,
        disabled: false,
        path: PathBuf::from("/Library/LaunchAgents/com.example.unknown.plist"),
    }];

    let services = annotate_services(&plists, &db);
    assert_eq!(services.len(), 1);

    let svc = &services[0];
    // com.example.* is third-party, auto-categorized
    assert_eq!(svc.category, policy::ServiceCategory::ThirdParty);
    assert_eq!(svc.safety, policy::SafetyLevel::Optional);
    assert!(svc.description.is_some());
}

#[test]
fn test_annotate_services_unknown_telemetry_heuristic() {
    let db = AnnotationDb::load_from_toml(
        r#"
[[services]]
pattern = "com.apple.analyticsd"
description = "Apple analytics"
category = "telemetry"
safety = "telemetry"
"#,
    )
    .expect("failed to parse TOML");

    let plists = vec![PlistInfo {
        label: "com.vendor.diagnosticHelper".to_string(),
        program: None,
        run_at_load: false,
        keep_alive: false,
        disabled: false,
        path: PathBuf::from("/Library/LaunchAgents/com.vendor.diagnosticHelper.plist"),
    }];

    let services = annotate_services(&plists, &db);
    let svc = &services[0];

    assert_eq!(
        svc.category,
        policy::ServiceCategory::Telemetry,
        "label containing 'diagnostic' should get telemetry category"
    );
    assert_eq!(svc.safety, policy::SafetyLevel::Telemetry);
}

#[test]
fn test_annotate_services_disabled_state() {
    let db = AnnotationDb::load_from_toml(
        r#"
[[services]]
pattern = "com.apple.test"
description = "Test"
category = "unknown"
safety = "optional"
"#,
    )
    .expect("failed to parse TOML");

    let plists = vec![PlistInfo {
        label: "com.apple.test".to_string(),
        program: None,
        run_at_load: false,
        keep_alive: false,
        disabled: true,
        path: PathBuf::from("/Library/LaunchDaemons/com.apple.test.plist"),
    }];

    let services = annotate_services(&plists, &db);
    assert_eq!(
        services[0].state,
        policy::ServiceState::Disabled,
        "disabled plist should result in Disabled state"
    );
}

#[test]
fn test_infer_domain_system() {
    assert_eq!(
        infer_domain(std::path::Path::new(
            "/System/Library/LaunchDaemons/com.apple.test.plist"
        )),
        policy::Domain::System
    );
    assert_eq!(
        infer_domain(std::path::Path::new(
            "/Library/LaunchDaemons/com.apple.test.plist"
        )),
        policy::Domain::System
    );
}

#[test]
fn test_infer_domain_global() {
    assert_eq!(
        infer_domain(std::path::Path::new(
            "/System/Library/LaunchAgents/com.apple.test.plist"
        )),
        policy::Domain::Global
    );
}

#[test]
fn test_infer_domain_user() {
    assert_eq!(
        infer_domain(std::path::Path::new(
            "/Library/LaunchAgents/com.apple.test.plist"
        )),
        policy::Domain::User
    );
    assert_eq!(
        infer_domain(std::path::Path::new(
            "/Users/test/Library/LaunchAgents/com.apple.test.plist"
        )),
        policy::Domain::User
    );
}

#[test]
fn test_default_plist_dirs_count() {
    assert_eq!(DEFAULT_PLIST_DIRS.len(), 5, "should have 5 canonical dirs");
}

// ---------------------------------------------------------------------------
// Auto-categorization heuristics
// ---------------------------------------------------------------------------

#[test]
fn test_infer_unknown_audio_service() {
    let (cat, safety, desc) = infer_unknown("com.vendor.audioManager");
    assert_eq!(cat, policy::ServiceCategory::Media);
    assert_eq!(safety, policy::SafetyLevel::Important);
    assert!(desc.is_some());
}

#[test]
fn test_infer_unknown_bluetooth_service() {
    let (cat, safety, desc) = infer_unknown("com.vendor.bluetoothHelper");
    assert_eq!(cat, policy::ServiceCategory::Networking);
    assert_eq!(safety, policy::SafetyLevel::Optional);
    assert!(desc.is_some());
}

#[test]
fn test_infer_unknown_notification_service() {
    let (cat, safety, desc) = infer_unknown("com.vendor.notificationCenter");
    assert_eq!(cat, policy::ServiceCategory::Unknown);
    assert_eq!(safety, policy::SafetyLevel::Optional);
    assert!(desc.is_some());
}

#[test]
fn test_infer_unknown_location_service() {
    let (cat, safety, desc) = infer_unknown("com.vendor.locationTracker");
    assert_eq!(cat, policy::ServiceCategory::Networking);
    assert_eq!(safety, policy::SafetyLevel::Optional);
    assert!(desc.is_some());
}

#[test]
fn test_infer_unknown_security_service() {
    let (cat, safety, desc) = infer_unknown("com.vendor.keychainHelper");
    assert_eq!(cat, policy::ServiceCategory::Security);
    assert_eq!(safety, policy::SafetyLevel::Important);
    assert!(desc.is_some());
}

#[test]
fn test_infer_unknown_filesystem_service() {
    let (cat, safety, desc) = infer_unknown("com.vendor.diskimageHelper");
    assert_eq!(cat, policy::ServiceCategory::CoreOs);
    assert_eq!(safety, policy::SafetyLevel::Important);
    assert!(desc.is_some());
}

#[test]
fn test_infer_unknown_safari_service() {
    let (cat, safety, desc) = infer_unknown("com.vendor.safariExtension");
    assert_eq!(cat, policy::ServiceCategory::Unknown);
    assert_eq!(safety, policy::SafetyLevel::Optional);
    assert!(desc.is_some());
}

#[test]
fn test_infer_unknown_accessibility_service() {
    let (cat, safety, desc) = infer_unknown("com.vendor.accessibilityHelper");
    assert_eq!(cat, policy::ServiceCategory::Accessibility);
    assert_eq!(safety, policy::SafetyLevel::Important);
    assert!(desc.is_some());
}

#[test]
fn test_infer_unknown_printing_service() {
    let (cat, safety, desc) = infer_unknown("com.vendor.printServer");
    assert_eq!(cat, policy::ServiceCategory::Unknown);
    assert_eq!(safety, policy::SafetyLevel::Optional);
    assert!(desc.is_some());
}

#[test]
fn test_infer_unknown_third_party() {
    // Non-Apple reverse-DNS labels get categorized as third-party
    let (cat, safety, desc) = infer_unknown("com.vendor.genericThing");
    assert_eq!(cat, policy::ServiceCategory::ThirdParty);
    assert_eq!(safety, policy::SafetyLevel::Optional);
    assert!(desc.is_some());
}

#[test]
fn test_infer_unknown_apple_system() {
    // com.apple.* without a specific keyword match — we don't know, say so
    let (cat, safety, desc) = infer_unknown("com.apple.someInternalDaemon");
    assert_eq!(cat, policy::ServiceCategory::Unknown);
    assert_eq!(safety, policy::SafetyLevel::Optional);
    assert!(desc.is_some()); // but we DO note it's Apple
}

#[test]
fn test_contains_any_basic() {
    assert!(contains_any("hello world", &["hello"]));
    assert!(contains_any("hello world", &["world"]));
    assert!(!contains_any("hello world", &["foo", "bar"]));
    assert!(contains_any("foobar", &["baz", "bar"]));
}
