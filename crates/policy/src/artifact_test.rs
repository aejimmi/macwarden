#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn valid_toml() -> &'static str {
    r#"
[domain]
name = "saved-state"
description = "Window snapshots every app leaves behind at quit"
safety = "recommended"

[[artifact]]
name = "saved-state-all"
path = "~/Library/Saved Application State/"
description = "Window snapshots for all applications"

[[artifact]]
name = "saved-state-chrome"
path = "~/Library/Saved Application State/com.google.Chrome.savedState/"
description = "Chrome window snapshots"
"#
}

fn command_toml() -> &'static str {
    r#"
[domain]
name = "telemetry"
description = "Telemetry and diagnostic data"
safety = "recommended"

[[artifact]]
name = "diagnostic-reports"
path = "~/Library/Logs/DiagnosticReports/"
description = "Crash and diagnostic reports"

[[artifact]]
name = "unified-log"
command = "log erase --all"
description = "Unified system log"
"#
}

fn make_domains() -> Vec<ArtifactDomain> {
    vec![
        parse_artifact_file(valid_toml()).expect("must parse"),
        parse_artifact_file(command_toml()).expect("must parse"),
    ]
}

// ---------------------------------------------------------------------------
// Parsing: success
// ---------------------------------------------------------------------------

#[test]
fn test_parse_valid_path_artifacts() {
    let domain = parse_artifact_file(valid_toml()).expect("must parse");
    assert_eq!(domain.name, "saved-state");
    assert_eq!(domain.safety, Safety::Recommended);
    assert_eq!(domain.artifacts.len(), 2);
    assert_eq!(domain.artifacts[0].name, "saved-state-all");
    assert!(matches!(
        domain.artifacts[0].action,
        ArtifactAction::Path(_)
    ));
}

#[test]
fn test_parse_command_artifact() {
    let domain = parse_artifact_file(command_toml()).expect("must parse");
    assert_eq!(domain.artifacts.len(), 2);

    let log_artifact = &domain.artifacts[1];
    assert_eq!(log_artifact.name, "unified-log");
    match &log_artifact.action {
        ArtifactAction::Command(cmd) => assert_eq!(cmd, "log erase --all"),
        ArtifactAction::Path(_) => panic!("expected Command variant"),
    }
}

// ---------------------------------------------------------------------------
// Parsing: errors
// ---------------------------------------------------------------------------

#[test]
fn test_parse_both_path_and_command_fails() {
    let toml = r#"
[domain]
name = "bad"
description = "Bad domain"
safety = "optional"

[[artifact]]
name = "both"
path = "/tmp/foo"
command = "echo hi"
description = "Has both"
"#;
    let err = parse_artifact_file(toml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("both path and command"), "got: {msg}");
}

#[test]
fn test_parse_neither_path_nor_command_fails() {
    let toml = r#"
[domain]
name = "bad"
description = "Bad domain"
safety = "optional"

[[artifact]]
name = "neither"
description = "Has neither"
"#;
    let err = parse_artifact_file(toml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("neither path nor command"), "got: {msg}");
}

#[test]
fn test_parse_empty_domain_name_fails() {
    let toml = r#"
[domain]
name = ""
description = "Empty name"
safety = "optional"

[[artifact]]
name = "foo"
path = "/tmp/foo"
description = "Something"
"#;
    let err = parse_artifact_file(toml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid"), "got: {msg}");
}

#[test]
fn test_parse_invalid_domain_name_chars_fails() {
    let toml = r#"
[domain]
name = "Bad_Name"
description = "Uppercase and underscore"
safety = "optional"

[[artifact]]
name = "foo"
path = "/tmp/foo"
description = "Something"
"#;
    let err = parse_artifact_file(toml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid"), "got: {msg}");
}

#[test]
fn test_parse_empty_artifact_name_fails() {
    let toml = r#"
[domain]
name = "good"
description = "Good domain"
safety = "optional"

[[artifact]]
name = ""
path = "/tmp/foo"
description = "Empty artifact name"
"#;
    let err = parse_artifact_file(toml).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("invalid"), "got: {msg}");
}

#[test]
fn test_parse_no_artifacts_fails() {
    let toml = r#"
[domain]
name = "empty"
description = "No artifacts"
safety = "optional"
"#;
    let err = parse_artifact_file(toml).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no artifacts") || msg.contains("missing field"),
        "got: {msg}"
    );
}

#[test]
fn test_parse_invalid_toml_fails() {
    let err = parse_artifact_file("not valid toml {{{").unwrap_err();
    assert!(err.to_string().contains("failed to parse"));
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

#[test]
fn test_validate_valid_catalog() {
    let domains = make_domains();
    assert!(validate_artifact_catalog(&domains).is_ok());
}

#[test]
fn test_validate_duplicate_domain_names() {
    let domain = parse_artifact_file(valid_toml()).expect("must parse");
    let domains = vec![domain.clone(), domain];
    let err = validate_artifact_catalog(&domains).unwrap_err();
    assert!(err.to_string().contains("duplicate domain name"));
}

#[test]
fn test_validate_duplicate_artifact_names_across_domains() {
    let toml_a = r#"
[domain]
name = "domain-a"
description = "Domain A"
safety = "optional"

[[artifact]]
name = "shared-name"
path = "/tmp/a"
description = "In domain A"
"#;
    let toml_b = r#"
[domain]
name = "domain-b"
description = "Domain B"
safety = "optional"

[[artifact]]
name = "shared-name"
path = "/tmp/b"
description = "In domain B"
"#;
    let domains = vec![
        parse_artifact_file(toml_a).expect("must parse"),
        parse_artifact_file(toml_b).expect("must parse"),
    ];
    let err = validate_artifact_catalog(&domains).unwrap_err();
    assert!(err.to_string().contains("duplicate artifact name"));
}

#[test]
fn test_validate_artifact_name_collides_with_domain_name() {
    let toml = r#"
[domain]
name = "collider"
description = "Will collide"
safety = "optional"

[[artifact]]
name = "saved-state"
path = "/tmp/x"
description = "Name matches domain saved-state"
"#;
    let domains = vec![
        parse_artifact_file(valid_toml()).expect("must parse"),
        parse_artifact_file(toml).expect("must parse"),
    ];
    let err = validate_artifact_catalog(&domains).unwrap_err();
    assert!(err.to_string().contains("collides with a domain name"));
}

// ---------------------------------------------------------------------------
// Lookup
// ---------------------------------------------------------------------------

#[test]
fn test_find_artifact_domain_exact() {
    let domains = make_domains();
    let found = find_artifact_domain("saved-state", &domains);
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "saved-state");
}

#[test]
fn test_find_artifact_domain_case_insensitive() {
    let domains = make_domains();
    assert!(find_artifact_domain("Saved-State", &domains).is_some());
    assert!(find_artifact_domain("TELEMETRY", &domains).is_some());
}

#[test]
fn test_find_artifact_domain_unknown() {
    let domains = make_domains();
    assert!(find_artifact_domain("nonexistent", &domains).is_none());
}

#[test]
fn test_find_artifact_by_name() {
    let domains = make_domains();
    let result = find_artifact("saved-state-chrome", &domains);
    assert!(result.is_some());
    let (domain, artifact) = result.unwrap();
    assert_eq!(domain.name, "saved-state");
    assert_eq!(artifact.name, "saved-state-chrome");
}

#[test]
fn test_find_artifact_case_insensitive() {
    let domains = make_domains();
    assert!(find_artifact("Unified-Log", &domains).is_some());
}

#[test]
fn test_find_artifact_unknown() {
    let domains = make_domains();
    assert!(find_artifact("nonexistent", &domains).is_none());
}
