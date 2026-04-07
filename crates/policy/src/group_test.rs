#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

use crate::types::{Domain, SafetyLevel, ServiceCategory, ServiceState};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_groups() -> Vec<ServiceGroup> {
    let toml = r#"
[[group]]
name = "spotlight"
description = "Spotlight search and metadata indexing"
safety = "optional"
patterns = [
    "com.apple.Spotlight",
    "com.apple.metadata.mds*",
    "com.apple.metadata.md*",
    "com.apple.corespotlight*",
]
disable_commands = ["mdutil -a -i off"]
enable_commands = ["mdutil -a -i on"]

[[group]]
name = "siri"
description = "Siri and voice assistant"
safety = "recommended"
patterns = [
    "com.apple.Siri*",
    "com.apple.siriactionsd",
    "com.apple.assistant*",
    "com.apple.parsec*",
    "com.apple.DictationIM",
]

[[group]]
name = "telemetry"
description = "Apple telemetry and analytics"
safety = "recommended"
patterns = [
    "com.apple.analyticsd",
    "com.apple.SubmitDiagInfo",
    "com.apple.inputanalyticsd",
    "com.apple.triald",
]
"#;
    parse_groups_toml(toml).expect("test TOML must parse")
}

fn make_service(label: &str) -> ServiceInfo {
    ServiceInfo {
        label: label.to_owned(),
        domain: Domain::User,
        plist_path: None,
        state: ServiceState::Running,
        category: ServiceCategory::Unknown,
        safety: SafetyLevel::Optional,
        description: None,
        pid: None,
    }
}

// ---------------------------------------------------------------------------
// Pattern matching
// ---------------------------------------------------------------------------

#[test]
fn test_spotlight_group_matches_mds() {
    let groups = test_groups();
    let group = find_group("spotlight", &groups).expect("spotlight group must exist");
    assert!(group.matches("com.apple.metadata.mds"));
    assert!(group.matches("com.apple.metadata.mds_stores"));
    assert!(group.matches("com.apple.metadata.mdworker_shared"));
}

#[test]
fn test_spotlight_group_matches_corespotlightd() {
    let groups = test_groups();
    let group = find_group("spotlight", &groups).expect("spotlight group must exist");
    assert!(group.matches("com.apple.corespotlightd"));
    assert!(group.matches("com.apple.corespotlight.migration"));
}

#[test]
fn test_spotlight_group_does_not_match_unrelated() {
    let groups = test_groups();
    let group = find_group("spotlight", &groups).expect("spotlight group must exist");
    assert!(!group.matches("com.apple.Siri.agent"));
    assert!(!group.matches("com.apple.analyticsd"));
    assert!(!group.matches("com.apple.WindowServer"));
}

// ---------------------------------------------------------------------------
// Lookup functions
// ---------------------------------------------------------------------------

#[test]
fn test_find_group_by_name() {
    let groups = test_groups();
    assert!(find_group("spotlight", &groups).is_some());
    assert!(find_group("siri", &groups).is_some());
    assert!(find_group("telemetry", &groups).is_some());
    assert!(find_group("nonexistent", &groups).is_none());
}

#[test]
fn test_find_group_case_insensitive() {
    let groups = test_groups();
    assert!(find_group("Spotlight", &groups).is_some());
    assert!(find_group("TELEMETRY", &groups).is_some());
}

// ---------------------------------------------------------------------------
// Reverse lookup
// ---------------------------------------------------------------------------

#[test]
fn test_find_groups_for_service() {
    let groups = test_groups();
    let matched = find_groups_for_service("com.apple.analyticsd", &groups);
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0].name, "telemetry");
}

#[test]
fn test_find_groups_for_service_no_match() {
    let groups = test_groups();
    let matched = find_groups_for_service("com.apple.WindowServer", &groups);
    assert!(matched.is_empty());
}

// ---------------------------------------------------------------------------
// Resolve against service list
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_group_services() {
    let groups = test_groups();
    let services = vec![
        make_service("com.apple.metadata.mds"),
        make_service("com.apple.corespotlightd"),
        make_service("com.apple.Siri.agent"),
        make_service("com.apple.analyticsd"),
    ];

    let group = find_group("spotlight", &groups).expect("spotlight group must exist");
    let matched = resolve_group_services(group, &services);

    assert_eq!(matched.len(), 2);
    let labels: Vec<&str> = matched.iter().map(|s| s.label.as_str()).collect();
    assert!(labels.contains(&"com.apple.metadata.mds"));
    assert!(labels.contains(&"com.apple.corespotlightd"));
}

#[test]
fn test_resolve_group_services_empty() {
    let groups = test_groups();
    let services = vec![make_service("com.apple.WindowServer")];
    let group = find_group("siri", &groups).expect("siri group must exist");
    let matched = resolve_group_services(group, &services);
    assert!(matched.is_empty());
}

// ---------------------------------------------------------------------------
// Group commands
// ---------------------------------------------------------------------------

#[test]
fn test_spotlight_has_disable_commands() {
    let groups = test_groups();
    let group = find_group("spotlight", &groups).expect("spotlight group must exist");
    assert_eq!(group.disable_commands.len(), 1);
    assert_eq!(group.disable_commands[0], "mdutil -a -i off");
    assert_eq!(group.enable_commands.len(), 1);
    assert_eq!(group.enable_commands[0], "mdutil -a -i on");
}

#[test]
fn test_siri_has_no_extra_commands() {
    let groups = test_groups();
    let group = find_group("siri", &groups).expect("siri group must exist");
    assert!(group.disable_commands.is_empty());
    assert!(group.enable_commands.is_empty());
}

// ---------------------------------------------------------------------------
// TOML parsing
// ---------------------------------------------------------------------------

#[test]
fn test_parse_groups_toml_valid() {
    let toml = r#"
[[group]]
name = "test"
description = "A test group"
safety = "keep"
patterns = ["com.test.*"]
disable_commands = ["echo off"]
enable_commands = ["echo on"]
"#;
    let groups = parse_groups_toml(toml).expect("should parse");
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].name, "test");
    assert_eq!(groups[0].patterns, vec!["com.test.*"]);
}

#[test]
fn test_parse_groups_toml_invalid() {
    let toml = "not valid toml {{{";
    let result = parse_groups_toml(toml);
    assert!(result.is_err());
}
