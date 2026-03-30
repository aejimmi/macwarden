use super::*;

use macwarden_core::{SafetyLevel, ServiceCategory};

const SIMPLE_TOML: &str = r#"
[[services]]
pattern = "com.apple.analyticsd"
description = "Apple analytics"
category = "telemetry"
safety = "telemetry"

[[services]]
pattern = "com.apple.Siri*"
description = "Siri voice assistant"
category = "input"
safety = "optional"

[[services]]
pattern = "com.apple.WindowServer"
description = "Display compositor"
category = "core-os"
safety = "critical"
"#;

#[test]
fn test_lookup_exact_match() {
    let db = AnnotationDb::load_from_toml(SIMPLE_TOML).expect("failed to parse test TOML");

    let ann = db.lookup("com.apple.analyticsd");
    assert!(ann.is_some(), "exact match should find analyticsd");

    let ann = ann.expect("checked above");
    assert_eq!(ann.category, ServiceCategory::Telemetry);
    assert_eq!(ann.safety, SafetyLevel::Telemetry);
    assert_eq!(ann.description, "Apple analytics");
}

#[test]
fn test_lookup_glob_match() {
    let db = AnnotationDb::load_from_toml(SIMPLE_TOML).expect("failed to parse test TOML");

    let ann = db.lookup("com.apple.SiriAgent");
    assert!(ann.is_some(), "glob should match com.apple.Siri*");

    let ann = ann.expect("checked above");
    assert_eq!(ann.category, ServiceCategory::Input);
    assert_eq!(ann.safety, SafetyLevel::Optional);
}

#[test]
fn test_lookup_no_match() {
    let db = AnnotationDb::load_from_toml(SIMPLE_TOML).expect("failed to parse test TOML");

    let ann = db.lookup("com.example.unknown");
    assert!(ann.is_none(), "unknown label should return None");
}

#[test]
fn test_lookup_exact_takes_priority_over_glob() {
    // com.apple.WindowServer is an exact match, not a glob.
    let db = AnnotationDb::load_from_toml(SIMPLE_TOML).expect("failed to parse test TOML");

    let ann = db
        .lookup("com.apple.WindowServer")
        .expect("should find WindowServer");
    assert_eq!(ann.category, ServiceCategory::CoreOs);
    assert_eq!(ann.safety, SafetyLevel::Critical);
}

#[test]
fn test_load_builtin_succeeds() {
    let db = AnnotationDb::load_builtin();
    assert!(
        db.len() >= 40,
        "built-in DB should have at least 40 annotations, got {}",
        db.len()
    );
}

#[test]
fn test_builtin_has_expected_entries() {
    let db = AnnotationDb::load_builtin();

    // Critical service should be present.
    let ws = db
        .lookup("com.apple.WindowServer")
        .expect("WindowServer should be in built-in DB");
    assert_eq!(ws.safety, SafetyLevel::Critical);

    // Telemetry service should be present.
    let analytics = db
        .lookup("com.apple.analyticsd")
        .expect("analyticsd should be in built-in DB");
    assert_eq!(analytics.safety, SafetyLevel::Telemetry);

    // Glob match on developer tools.
    let dt = db
        .lookup("com.apple.dt.Xcode")
        .expect("com.apple.dt.* glob should match");
    assert_eq!(dt.category, ServiceCategory::Developer);
}

#[test]
fn test_load_from_toml_malformed() {
    let bad_toml = "this is not valid toml {{{{";
    let result = AnnotationDb::load_from_toml(bad_toml);
    assert!(result.is_err(), "malformed TOML should return error");

    let err = result.expect_err("checked above");
    match err {
        CatalogError::AnnotationParse { message } => {
            assert!(!message.is_empty(), "error message should not be empty");
        }
        other => {
            // Use debug formatting to avoid the test silently passing.
            let _ = format!("expected AnnotationParse, got {:?}", other);
            assert!(false, "expected AnnotationParse variant");
        }
    }
}

#[test]
fn test_load_from_toml_missing_field() {
    let incomplete = r#"
[[services]]
pattern = "com.example.test"
description = "Test service"
"#;
    let result = AnnotationDb::load_from_toml(incomplete);
    assert!(result.is_err(), "missing required fields should fail");
}

#[test]
fn test_load_from_toml_invalid_glob() {
    let bad_glob = r#"
[[services]]
pattern = "com.apple.[invalid"
description = "Bad glob"
category = "unknown"
safety = "optional"
"#;
    let result = AnnotationDb::load_from_toml(bad_glob);
    assert!(result.is_err(), "invalid glob pattern should fail");
}

#[test]
fn test_db_len_and_is_empty() {
    let db = AnnotationDb::load_from_toml(SIMPLE_TOML).expect("failed to parse test TOML");
    assert_eq!(db.len(), 3);
    assert!(!db.is_empty());
}

#[test]
fn test_db_iter() {
    let db = AnnotationDb::load_from_toml(SIMPLE_TOML).expect("failed to parse test TOML");
    let labels: Vec<&str> = db.iter().map(|a| a.label_pattern.as_str()).collect();
    assert_eq!(
        labels,
        vec![
            "com.apple.analyticsd",
            "com.apple.Siri*",
            "com.apple.WindowServer"
        ]
    );
}

#[test]
fn test_load_from_toml_with_version_ranges() {
    let toml = r#"
[[services]]
pattern = "com.apple.test"
description = "Test service"
category = "unknown"
safety = "optional"
macos_min = "14.0.0"
macos_max = "26.0.0"
"#;
    let db = AnnotationDb::load_from_toml(toml).expect("failed to parse TOML with versions");
    let ann = db
        .lookup("com.apple.test")
        .expect("should find test service");
    assert_eq!(
        ann.macos_min.as_ref().map(|v| v.to_string()),
        Some("14.0.0".to_string())
    );
    assert_eq!(
        ann.macos_max.as_ref().map(|v| v.to_string()),
        Some("26.0.0".to_string())
    );
}
