use super::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_base_profile() -> Profile {
    parse_profile_toml(
        r#"
[profile]
name = "base"
description = "Base profile for testing"

[rules]
deny = ["com.apple.analyticsd", "com.apple.SubmitDiagInfo"]
allow = []

[rules.categories]
telemetry = "deny"

[enforcement]
action = "disable"
exec_policy = "allow"
"#,
    )
    .expect("base profile must parse")
}

fn make_minimal_profile() -> Profile {
    parse_profile_toml(
        r#"
[profile]
name = "minimal"
description = "Extends base for testing"
extends = ["base"]

[rules]
deny = ["com.apple.Siri.*"]
allow = []

[enforcement]
action = "disable"
"#,
    )
    .expect("minimal profile must parse")
}

fn make_developer_profile() -> Profile {
    parse_profile_toml(
        r#"
[profile]
name = "developer"
description = "Extends minimal for testing"
extends = ["minimal"]

[rules]
deny = []
allow = ["com.apple.dt.*"]

[rules.categories]
developer = "allow"

[enforcement]
action = "disable"
"#,
    )
    .expect("developer profile must parse")
}

// ---------------------------------------------------------------------------
// TOML parsing
// ---------------------------------------------------------------------------

#[test]
fn test_parse_profile_valid_toml() {
    let toml = r#"
[profile]
name = "test"
description = "A test profile"

[rules]
deny = ["com.apple.Siri.*"]
allow = []

[rules.categories]
telemetry = "deny"

[enforcement]
action = "disable"
exec_policy = "allow"
"#;
    let profile = parse_profile_toml(toml);
    assert!(profile.is_ok());
    let p = profile.expect("should parse");
    assert_eq!(p.profile.name, "test");
    assert_eq!(p.rules.deny, vec!["com.apple.Siri.*"]);
    assert_eq!(
        p.rules.categories.get("telemetry"),
        Some(&CategoryAction::Deny)
    );
    assert_eq!(p.enforcement.action, EnforcementAction::Disable);
}

#[test]
fn test_parse_profile_invalid_toml() {
    let toml = "this is not valid toml {{{";
    let result = parse_profile_toml(toml);
    assert!(result.is_err());
    match result {
        Err(CoreError::ProfileParse { message }) => {
            assert!(!message.is_empty());
        }
        _ => panic!("expected ProfileParse error"),
    }
}

#[test]
fn test_parse_profile_missing_required_fields() {
    let toml = r#"
[profile]
name = "test"
"#;
    let result = parse_profile_toml(toml);
    assert!(result.is_err());
}

#[test]
fn test_parse_profile_with_extends() {
    let toml = r#"
[profile]
name = "child"
description = "Extends base"
extends = ["base"]

[rules]
deny = ["com.example.foo"]
allow = []

[enforcement]
action = "disable"
"#;
    let p = parse_profile_toml(toml).expect("should parse");
    assert_eq!(p.profile.extends, vec!["base"]);
}

#[test]
fn test_parse_profile_with_macos_min() {
    let toml = r#"
[profile]
name = "versioned"
description = "Requires macOS 14"
macos_min = "14.0.0"

[rules]
deny = []
allow = []

[enforcement]
action = "disable"
"#;
    let p = parse_profile_toml(toml).expect("should parse");
    assert_eq!(p.profile.macos_min, Some(semver::Version::new(14, 0, 0)));
}

// ---------------------------------------------------------------------------
// Load from file
// ---------------------------------------------------------------------------

#[test]
fn test_load_profile_from_file() {
    let dir = tempfile::tempdir().expect("should create temp dir");
    let path = dir.path().join("test.toml");
    std::fs::write(
        &path,
        r#"
[profile]
name = "file-test"
description = "From file"

[rules]
deny = []
allow = []

[enforcement]
action = "log-only"
"#,
    )
    .expect("should write");
    let p = load_profile(&path).expect("should load");
    assert_eq!(p.profile.name, "file-test");
    assert_eq!(p.enforcement.action, EnforcementAction::LogOnly);
}

#[test]
fn test_load_profile_nonexistent_file() {
    let result = load_profile(Path::new("/nonexistent/profile.toml"));
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Extends resolution
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_extends_single_level() {
    let base = make_base_profile();
    let minimal = make_minimal_profile();
    let available = vec![base, minimal.clone()];
    let resolved = resolve_extends(&minimal, &available).expect("should resolve");

    // Should include base's deny rules plus minimal's own.
    assert!(
        resolved
            .rules
            .deny
            .contains(&"com.apple.analyticsd".to_owned())
    );
    assert!(resolved.rules.deny.contains(&"com.apple.Siri.*".to_owned()));
    // Extends should be cleared after resolution.
    assert!(resolved.profile.extends.is_empty());
}

#[test]
fn test_resolve_extends_two_levels() {
    let base = make_base_profile();
    let minimal = make_minimal_profile();
    let dev = make_developer_profile();
    let available = vec![base, minimal, dev.clone()];
    let resolved = resolve_extends(&dev, &available).expect("should resolve");

    // developer extends minimal extends base.
    // Should have base's deny rules.
    assert!(
        resolved
            .rules
            .deny
            .contains(&"com.apple.analyticsd".to_owned())
    );
    // Should have minimal's deny rules.
    assert!(resolved.rules.deny.contains(&"com.apple.Siri.*".to_owned()));
    // Should have developer's allow rules.
    assert!(resolved.rules.allow.contains(&"com.apple.dt.*".to_owned()));
    // Developer's category overrides ancestor.
    assert_eq!(
        resolved.rules.categories.get("developer"),
        Some(&CategoryAction::Allow)
    );
}

#[test]
fn test_resolve_extends_circular_reference() {
    let a = parse_profile_toml(
        r#"
[profile]
name = "a"
description = "A extends B"
extends = ["b"]

[rules]
deny = []
allow = []

[enforcement]
action = "disable"
"#,
    )
    .expect("should parse");

    let b = parse_profile_toml(
        r#"
[profile]
name = "b"
description = "B extends A"
extends = ["a"]

[rules]
deny = []
allow = []

[enforcement]
action = "disable"
"#,
    )
    .expect("should parse");

    let available = vec![a.clone(), b];
    let result = resolve_extends(&a, &available);
    assert!(result.is_err());
    match result {
        Err(CoreError::CircularExtends { .. }) => {}
        other => panic!("expected CircularExtends, got {other:?}"),
    }
}

#[test]
fn test_resolve_extends_max_depth_exceeded() {
    // Create a chain 4 levels deep: d -> c -> b -> a -> base
    let mk = |name: &str, parent: &str| -> Profile {
        parse_profile_toml(&format!(
            r#"
[profile]
name = "{name}"
description = "Level"
extends = ["{parent}"]

[rules]
deny = []
allow = []

[enforcement]
action = "disable"
"#
        ))
        .expect("should parse")
    };

    let base = make_base_profile();
    let a = mk("a", "base");
    let b = mk("b", "a");
    let c = mk("c", "b");
    let d = mk("d", "c");

    let available = vec![base, a, b, c, d.clone()];
    let result = resolve_extends(&d, &available);
    assert!(result.is_err());
    match result {
        Err(CoreError::MaxExtendsDepth { max_depth }) => {
            assert_eq!(max_depth, 3);
        }
        other => panic!("expected MaxExtendsDepth, got {other:?}"),
    }
}

#[test]
fn test_resolve_extends_profile_not_found() {
    let child = parse_profile_toml(
        r#"
[profile]
name = "orphan"
description = "Extends nonexistent"
extends = ["does_not_exist"]

[rules]
deny = []
allow = []

[enforcement]
action = "disable"
"#,
    )
    .expect("should parse");

    let result = resolve_extends(&child, &[]);
    assert!(result.is_err());
    match result {
        Err(CoreError::ProfileNotFound { name }) => {
            assert_eq!(name, "does_not_exist");
        }
        other => panic!("expected ProfileNotFound, got {other:?}"),
    }
}

#[test]
fn test_resolve_extends_no_parents() {
    let base = make_base_profile();
    let resolved = resolve_extends(&base, &[]).expect("should resolve");
    assert_eq!(resolved.profile.name, "base");
    assert_eq!(resolved.rules.deny, base.rules.deny);
}

// ---------------------------------------------------------------------------
// Profile validation
// ---------------------------------------------------------------------------

#[test]
fn test_validate_profile_passes_for_safe_rules() {
    let base = make_base_profile();
    assert!(validate_profile(&base).is_ok());
}

#[test]
fn test_validate_profile_rejects_critical_in_deny_list() {
    let bad = parse_profile_toml(
        r#"
[profile]
name = "bad"
description = "Tries to deny critical services"

[rules]
deny = ["com.apple.WindowServer", "com.apple.Siri.agent"]
allow = []

[enforcement]
action = "disable"
"#,
    )
    .expect("should parse");

    let result = validate_profile(&bad);
    assert!(result.is_err());
    let err = result.expect_err("should fail");
    assert!(err.message.contains("com.apple.WindowServer"));
}
