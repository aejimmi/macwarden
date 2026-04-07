#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

use crate::connection::{AddressFamily, Destination, ProcessIdentity};
use crate::rule::Protocol;
use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;

fn make_process_id(code_id: &str) -> ProcessIdentity {
    ProcessIdentity {
        pid: 42,
        uid: 501,
        path: PathBuf::from("/Applications/Test.app"),
        code_id: Some(code_id.to_owned()),
        team_id: None,
        is_valid_signature: None,
    }
}

fn make_dest_host(host: &str) -> Destination {
    Destination {
        host: Some(host.to_owned()),
        ip: "17.253.144.10".parse::<IpAddr>().expect("valid IP"),
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        address_family: AddressFamily::Inet,
    }
}

#[test]
fn test_load_builtin_groups() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");

    let names: Vec<&str> = groups.list().iter().map(|(n, _)| *n).collect();
    assert!(
        names.contains(&"icloud-services"),
        "should have icloud-services"
    );
    assert!(
        names.contains(&"macos-services"),
        "should have macos-services"
    );
    assert!(
        names.contains(&"browser-essentials"),
        "should have browser-essentials"
    );
    assert!(names.contains(&"development"), "should have development");
    assert!(names.contains(&"gaming"), "should have gaming");
    assert!(
        names.contains(&"media-streaming"),
        "should have media-streaming"
    );
    assert!(names.contains(&"productivity"), "should have productivity");
    assert!(
        names.contains(&"communication"),
        "should have communication"
    );
    assert_eq!(names.len(), 8, "should have exactly 8 builtin groups");
}

#[test]
fn test_group_enabled_by_default() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");

    let list = groups.list();
    for &name in &["icloud-services", "macos-services", "browser-essentials"] {
        let entry = list
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("group `{name}` should exist"));
        assert!(entry.1, "group `{name}` should be enabled by default");
    }
}

#[test]
fn test_group_disabled_by_default() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");

    let dev = groups
        .get("development")
        .expect("development group should exist");
    assert!(
        !dev.default_enabled,
        "development group should be disabled by default"
    );
}

#[test]
fn test_to_grouped_rules_respects_overrides() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");

    // Enable development, disable icloud-services.
    let enable: HashSet<String> = ["development".to_owned()].into_iter().collect();
    let disable: HashSet<String> = ["icloud-services".to_owned()].into_iter().collect();

    let rules = groups
        .to_grouped_rules(&enable, &disable)
        .expect("expansion should succeed");

    // Development rules should be present.
    assert!(
        rules.iter().any(|r| r.group_name == "development"),
        "development rules should be included when enabled"
    );

    // iCloud rules should be absent.
    assert!(
        !rules.iter().any(|r| r.group_name == "icloud-services"),
        "icloud-services rules should be excluded when disabled"
    );

    // macos-services should still be present (default enabled, not overridden).
    assert!(
        rules.iter().any(|r| r.group_name == "macos-services"),
        "macos-services should be included (default enabled)"
    );
}

#[test]
fn test_group_rule_expansion() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");

    let no_overrides = HashSet::new();

    let rules = groups
        .to_grouped_rules(&no_overrides, &no_overrides)
        .expect("expansion should succeed");

    // The icloud-services group's first rule has 6 dest_hosts entries.
    // Each should become a separate GroupedRule.
    let icloud_core_count = rules
        .iter()
        .filter(|r| r.group_name == "icloud-services" && r.rule.name == "iCloud core domains")
        .count();
    assert_eq!(
        icloud_core_count, 6,
        "iCloud core domains rule with 6 dest_hosts should produce 6 GroupedRules"
    );

    // Verify that the Private Relay rule also expanded (2 hosts).
    let relay_count = rules
        .iter()
        .filter(|r| r.group_name == "icloud-services" && r.rule.name == "iCloud Private Relay")
        .count();
    assert_eq!(
        relay_count, 2,
        "iCloud Private Relay rule with 2 dest_hosts should produce 2 GroupedRules"
    );
}

// ---------------------------------------------------------------------------
// get() by name
// ---------------------------------------------------------------------------

#[test]
fn test_get_existing_group() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");
    let g = groups.get("icloud-services");
    assert!(g.is_some(), "get('icloud-services') should return Some");
    assert_eq!(g.unwrap().name, "icloud-services");
}

#[test]
fn test_get_nonexistent_group_returns_none() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");
    assert!(
        groups.get("nonexistent-xyz").is_none(),
        "get with unknown name should return None"
    );
}

// ---------------------------------------------------------------------------
// Grouped rules actually match expected destinations
// ---------------------------------------------------------------------------

#[test]
fn test_icloud_grouped_rules_match_icloud_domain() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");
    let no_overrides = HashSet::new();
    let rules = groups
        .to_grouped_rules(&no_overrides, &no_overrides)
        .expect("expansion should succeed");

    // "icloud.com" should be matched by one of the icloud-services grouped rules.
    let process = make_process_id("com.apple.iCloud");
    let dest = make_dest_host("icloud.com");

    let matched = rules
        .iter()
        .any(|gr| gr.group_name == "icloud-services" && gr.rule.matches(&process, &dest));

    assert!(
        matched,
        "icloud.com should be matched by an icloud-services rule"
    );
}

#[test]
fn test_development_rules_not_included_when_disabled() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");
    // development is disabled by default; confirm its rules are absent.
    let no_overrides: HashSet<String> = HashSet::new();
    let rules = groups
        .to_grouped_rules(&no_overrides, &no_overrides)
        .expect("expansion should succeed");

    assert!(
        !rules.iter().any(|r| r.group_name == "development"),
        "development rules should not be included when the group is disabled by default"
    );
}

// ---------------------------------------------------------------------------
// Both enable and disable set for the same group — disable wins
// ---------------------------------------------------------------------------

#[test]
fn test_disable_overrides_enable_for_same_group() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");

    // Both enable and disable contain "icloud-services" — disable should win.
    let enable: HashSet<String> = ["icloud-services".to_owned()].into_iter().collect();
    let disable: HashSet<String> = ["icloud-services".to_owned()].into_iter().collect();

    let rules = groups
        .to_grouped_rules(&enable, &disable)
        .expect("expansion should succeed");

    assert!(
        !rules.iter().any(|r| r.group_name == "icloud-services"),
        "disable should override enable when both are set for the same group"
    );
}

// ---------------------------------------------------------------------------
// Groups are sorted by priority
// ---------------------------------------------------------------------------

#[test]
fn test_groups_sorted_by_priority() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");
    let all = groups.all();
    for window in all.windows(2) {
        assert!(
            window[0].priority <= window[1].priority,
            "groups should be sorted by priority (ascending), got {} > {}",
            window[0].priority,
            window[1].priority
        );
    }
}

// ---------------------------------------------------------------------------
// default_true / default_priority via TOML deserialization
// ---------------------------------------------------------------------------

#[test]
fn test_network_group_default_enabled_defaults_true() {
    // A group TOML without `default_enabled` field should default to true.
    let toml_str = r#"
[group]
name = "test-group"
description = "A test group"
rules = []
"#;
    let file: GroupFile = toml::from_str(toml_str).expect("should parse");
    assert!(
        file.group.default_enabled,
        "default_enabled should default to true when absent"
    );
}

#[test]
fn test_network_group_priority_defaults_to_50() {
    // A group TOML without `priority` field should default to 50.
    let toml_str = r#"
[group]
name = "test-group"
description = "A test group"
rules = []
"#;
    let file: GroupFile = toml::from_str(toml_str).expect("should parse");
    assert_eq!(
        file.group.priority, 50,
        "priority should default to 50 when absent"
    );
}

// ---------------------------------------------------------------------------
// parse_process: path variant (starts with '/')
// ---------------------------------------------------------------------------

#[test]
fn test_parse_process_path_variant_in_group_rule() {
    // A group rule whose process starts with '/' should use the Path matcher.
    let toml_str = r#"
[group]
name = "path-process-group"
description = "Group with path-based process"
rules = [
    { name = "Block curl", process = "/usr/bin/curl", dest_hosts = ["example.com"], action = "deny" }
]
"#;
    let file: GroupFile = toml::from_str(toml_str).expect("should parse");
    let groups = NetworkGroups {
        groups: vec![file.group],
    };
    let no_overrides = HashSet::new();
    let rules = groups
        .to_grouped_rules(&no_overrides, &no_overrides)
        .expect("should expand successfully");

    assert_eq!(rules.len(), 1);
    // The rule should match a process with the exact path.
    let curl_proc = make_process_id("com.whatever"); // code_id won't match
    let curl_proc_path = ProcessIdentity {
        pid: 42,
        uid: 501,
        path: PathBuf::from("/usr/bin/curl"),
        code_id: None,
        team_id: None,
        is_valid_signature: None,
    };
    let dest = make_dest_host("example.com");
    assert!(
        rules[0].rule.matches(&curl_proc_path, &dest),
        "path-based process rule should match by path"
    );
    assert!(
        !rules[0].rule.matches(&curl_proc, &dest),
        "path-based process rule should not match a different process"
    );
}

// ---------------------------------------------------------------------------
// to_grouped_rules with empty enable/disable overrides produces
// default-enabled groups only
// ---------------------------------------------------------------------------

#[test]
fn test_to_grouped_rules_no_overrides_uses_defaults() {
    let groups = NetworkGroups::load_builtin().expect("builtin groups should load");
    let no_overrides = HashSet::new();
    let rules = groups
        .to_grouped_rules(&no_overrides, &no_overrides)
        .expect("should succeed");

    // With no overrides, only default-enabled groups produce rules.
    // development is disabled by default, so no development rules.
    assert!(
        !rules.iter().any(|r| r.group_name == "development"),
        "development (default disabled) should not appear with no overrides"
    );
    // icloud-services is enabled by default, so it should appear.
    assert!(
        rules.iter().any(|r| r.group_name == "icloud-services"),
        "icloud-services (default enabled) should appear with no overrides"
    );
}
