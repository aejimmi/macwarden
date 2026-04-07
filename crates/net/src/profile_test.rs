#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::connection::{AddressFamily, Destination, ProcessIdentity};
use crate::group::NetworkGroups;
use crate::rule::Protocol;
use crate::tracker::TrackerDatabase;
use appdb::AppDb;
use std::net::IpAddr;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_process(code_id: &str) -> ProcessIdentity {
    ProcessIdentity {
        pid: 100,
        uid: 501,
        path: PathBuf::from("/Applications/Test.app"),
        code_id: Some(code_id.to_owned()),
        team_id: None,
        is_valid_signature: None,
    }
}

fn make_dest(host: &str) -> Destination {
    Destination {
        host: Some(host.to_owned()),
        ip: "93.184.216.34".parse::<IpAddr>().expect("valid IP"),
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        address_family: AddressFamily::Inet,
    }
}

fn load_all() -> (NetworkGroups, TrackerDatabase, AppDb) {
    let groups = NetworkGroups::load_builtin().expect("groups should load");
    let tracker_db = TrackerDatabase::load_builtin().expect("tracker db should load");
    let category_db = AppDb::load_builtin().expect("category db should load");
    (groups, tracker_db, category_db)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_parse_network_profile_toml() {
    let toml_str = r#"
        default = "deny"

        [trackers]
        advertising = "deny"
        analytics = "log"
        fingerprinting = "deny"
        social = "allow"

        [groups]
        enable = ["development"]
        disable = ["icloud-services"]

        [blocklists]
        enable = ["peter-lowe"]

        [[rules]]
        name = "Safari full access"
        process = "com.apple.Safari"
        dest = "*"
        action = "allow"
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("profile TOML should parse");

    assert_eq!(profile.default, NetworkAction::Deny);
    assert_eq!(profile.trackers.advertising, NetworkAction::Deny);
    assert_eq!(profile.trackers.analytics, NetworkAction::Log);
    assert_eq!(profile.trackers.fingerprinting, NetworkAction::Deny);
    assert_eq!(profile.trackers.social, NetworkAction::Allow);
    assert_eq!(profile.groups.enable, vec!["development"]);
    assert_eq!(profile.groups.disable, vec!["icloud-services"]);
    assert_eq!(profile.blocklists.enable, vec!["peter-lowe"]);
    assert_eq!(profile.rules.len(), 1);
    assert_eq!(profile.rules[0].name, "Safari full access");
}

#[test]
fn test_resolve_with_category_expansion() {
    let (groups, tracker_db, category_db) = load_all();

    let toml_str = r#"
        default = "deny"

        [[rules]]
        name = "Browsers unrestricted"
        process = { category = "browser" }
        dest = "*"
        action = "allow"
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("profile should parse");

    let rule_set = profile
        .resolve(&groups, &tracker_db, &category_db, &[])
        .expect("resolve should succeed");

    // Browser category has 4 apps, so 4 user rules should be generated.
    let browser_rules: Vec<_> = rule_set
        .user_rules
        .iter()
        .filter(|r| r.name == "Browsers unrestricted")
        .collect();
    assert_eq!(
        browser_rules.len(),
        4,
        "category expansion should produce 4 rules (one per browser app)"
    );

    // Verify Safari is matched by one of the expanded rules.
    let safari = make_process("com.apple.Safari");
    let dest = make_dest("example.com");
    assert!(
        browser_rules.iter().any(|r| r.matches(&safari, &dest)),
        "one of the expanded rules should match Safari"
    );
}

#[test]
fn test_resolve_tracker_settings() {
    let (groups, tracker_db, category_db) = load_all();

    // Only deny advertising, leave others as log.
    let toml_str = r#"
        default = "allow"

        [trackers]
        advertising = "deny"
        analytics = "log"
        fingerprinting = "log"
        social = "log"

        [groups]
        disable = ["icloud-services", "macos-services", "browser-essentials"]
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("profile should parse");

    let rule_set = profile
        .resolve(&groups, &tracker_db, &category_db, &[])
        .expect("resolve should succeed");

    // Only advertising tracker rules should be present.
    assert!(
        !rule_set.tracker_rules.is_empty(),
        "should have some tracker rules"
    );
    for tr in &rule_set.tracker_rules {
        assert_eq!(
            tr.category, "advertising",
            "only advertising trackers should be included, got: {}",
            tr.category,
        );
    }
}

#[test]
fn test_resolve_group_overrides() {
    let (groups, tracker_db, category_db) = load_all();

    let toml_str = r#"
        default = "log"

        [groups]
        enable = ["development"]
        disable = ["icloud-services"]
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("profile should parse");

    let rule_set = profile
        .resolve(&groups, &tracker_db, &category_db, &[])
        .expect("resolve should succeed");

    // Development rules should be present.
    assert!(
        rule_set
            .group_rules
            .iter()
            .any(|r| r.group_name == "development"),
        "development should be in group rules after enable override"
    );

    // iCloud rules should be absent.
    assert!(
        !rule_set
            .group_rules
            .iter()
            .any(|r| r.group_name == "icloud-services"),
        "icloud-services should not be in group rules after disable override"
    );
}

#[test]
fn test_resolve_default_action() {
    let (groups, tracker_db, category_db) = load_all();

    let toml_str = r#"
        default = "deny"

        [groups]
        disable = ["icloud-services", "macos-services", "browser-essentials"]
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("profile should parse");

    let rule_set = profile
        .resolve(&groups, &tracker_db, &category_db, &[])
        .expect("resolve should succeed");

    assert_eq!(
        rule_set.default_action,
        NetworkAction::Deny,
        "default action should be Deny"
    );

    // An unknown destination with no matching rule should get denied.
    let process = make_process("com.unknown.app");
    let dest = make_dest("unknown.example.com");
    let decision = rule_set.decide_for(&process, &dest);
    assert_eq!(decision.action, NetworkAction::Deny);
}

#[test]
fn test_default_profile_is_monitor_mode() {
    // Default TrackerSettings should have all actions as Log.
    let settings = TrackerSettings::default();
    assert_eq!(settings.advertising, NetworkAction::Log);
    assert_eq!(settings.analytics, NetworkAction::Log);
    assert_eq!(settings.fingerprinting, NetworkAction::Log);
    assert_eq!(settings.social, NetworkAction::Log);
    assert!(settings.breakage_detection);

    // A profile with no settings should default to monitor mode.
    let toml_str = "";
    let profile: NetworkProfile = toml::from_str(toml_str).expect("empty profile should parse");
    assert_eq!(
        profile.default,
        NetworkAction::Log,
        "default action should be Log (monitor mode)"
    );
}

// ---------------------------------------------------------------------------
// TrackerSettings::denied_categories — only Deny actions are included
// ---------------------------------------------------------------------------

#[test]
fn test_tracker_settings_denied_categories_only_deny() {
    let settings = TrackerSettings {
        advertising: NetworkAction::Deny,
        analytics: NetworkAction::Log,
        fingerprinting: NetworkAction::Allow,
        social: NetworkAction::Deny,
        breakage_detection: true,
    };
    let denied = settings.denied_categories();
    assert!(denied.contains("advertising"));
    assert!(denied.contains("social"));
    assert!(!denied.contains("analytics"), "Log should not be in denied");
    assert!(
        !denied.contains("fingerprinting"),
        "Allow should not be in denied"
    );
    assert_eq!(denied.len(), 2);
}

#[test]
fn test_tracker_settings_denied_categories_all_log_is_empty() {
    let settings = TrackerSettings::default(); // all Log
    let denied = settings.denied_categories();
    assert!(
        denied.is_empty(),
        "all-Log settings should produce no denied categories"
    );
}

#[test]
fn test_tracker_settings_denied_categories_all_deny() {
    let settings = TrackerSettings {
        advertising: NetworkAction::Deny,
        analytics: NetworkAction::Deny,
        fingerprinting: NetworkAction::Deny,
        social: NetworkAction::Deny,
        breakage_detection: true,
    };
    let denied = settings.denied_categories();
    assert_eq!(
        denied.len(),
        4,
        "all-Deny settings should produce 4 denied categories"
    );
}

// ---------------------------------------------------------------------------
// Blocklist enabled filtering: only named lists are included
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_blocklist_only_includes_enabled_lists() {
    let (groups, tracker_db, category_db) = load_all();

    use crate::blocklist::{Blocklist, BlocklistFormat};

    let list_a =
        Blocklist::parse("listA", "ad.example.com\n", BlocklistFormat::DomainList).expect("parse");
    let list_b = Blocklist::parse(
        "listB",
        "tracker.example.com\n",
        BlocklistFormat::DomainList,
    )
    .expect("parse");

    // Profile only enables listA.
    let toml_str = r#"
        default = "deny"

        [groups]
        disable = ["icloud-services", "macos-services", "browser-essentials"]

        [blocklists]
        enable = ["listA"]
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("profile should parse");
    let rule_set = profile
        .resolve(&groups, &tracker_db, &category_db, &[list_a, list_b])
        .expect("resolve should succeed");

    let list_names: Vec<&str> = rule_set
        .blocklist_domains
        .iter()
        .map(|e| e.list_name.as_str())
        .collect();

    assert!(
        list_names.iter().all(|&n| n == "listA"),
        "only listA domains should be included, got: {list_names:?}"
    );
    assert!(
        list_names.contains(&"listA"),
        "listA domains should be present"
    );
}

// ---------------------------------------------------------------------------
// Tracker settings: log-action categories are NOT added to tracker_rules
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_log_action_tracker_categories_not_in_rules() {
    let (groups, tracker_db, category_db) = load_all();

    // All categories set to Log (monitor mode).
    let toml_str = r#"
        default = "allow"

        [trackers]
        advertising = "log"
        analytics = "log"
        fingerprinting = "log"
        social = "log"

        [groups]
        disable = ["icloud-services", "macos-services", "browser-essentials"]
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("profile should parse");
    let rule_set = profile
        .resolve(&groups, &tracker_db, &category_db, &[])
        .expect("resolve should succeed");

    assert!(
        rule_set.tracker_rules.is_empty(),
        "log-action tracker categories should not produce any tracker rules"
    );
}

// ---------------------------------------------------------------------------
// Group enable/disable for a non-existent group name — should be silently
// ignored (no panic, no error). The unknown name simply doesn't match
// any group's name so it has no effect on the result.
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_with_unknown_group_name_is_no_op() {
    let (groups, tracker_db, category_db) = load_all();

    let toml_str = r#"
        default = "allow"

        [groups]
        enable = ["nonexistent-group-xyz"]
        disable = ["another-fake-group"]
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("profile should parse");
    let result = profile.resolve(&groups, &tracker_db, &category_db, &[]);
    assert!(
        result.is_ok(),
        "unknown group names in enable/disable should not cause an error"
    );
}

#[test]
fn test_bare_category_name_as_process_is_rejected() {
    let (groups, tracker_db, category_db) = load_all();

    // Common mistake: `process = "browser"` instead of
    // `process = { category = "browser" }`.
    let toml_str = r#"
        default = "log"

        [[rules]]
        name = "bad rule"
        process = "browser"
        dest = "*"
        action = "allow"
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("toml should parse");
    let result = profile.resolve(&groups, &tracker_db, &category_db, &[]);
    assert!(result.is_err(), "bare category name should be rejected");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("category"),
        "error should mention category syntax: {err}"
    );
}

#[test]
fn test_category_syntax_works_correctly() {
    let (groups, tracker_db, category_db) = load_all();

    // Correct syntax: `process = { category = "browser" }`
    let toml_str = r#"
        default = "log"

        [[rules]]
        name = "browsers unrestricted"
        process = { category = "browser" }
        dest = "*"
        action = "allow"
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("toml should parse");
    let result = profile.resolve(&groups, &tracker_db, &category_db, &[]);
    assert!(result.is_ok(), "category syntax should work: {result:?}");
}

// ---------------------------------------------------------------------------
// ProfileProcess::TeamId — team_id syntax in profile TOML
// ---------------------------------------------------------------------------

#[test]
fn test_profile_process_team_id_syntax() {
    let (groups, tracker_db, category_db) = load_all();

    let toml_str = r#"
        default = "deny"

        [[rules]]
        name = "Allow Google apps"
        process = { team_id = "EQHXZ8M8AV" }
        dest = "*"
        action = "allow"
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("toml should parse");
    let rule_set = profile
        .resolve(&groups, &tracker_db, &category_db, &[])
        .expect("resolve should succeed");

    assert_eq!(
        rule_set.user_rules.len(),
        1,
        "team_id process should produce exactly 1 rule"
    );

    // Verify the rule matches a process with the right team_id.
    let google_proc = ProcessIdentity {
        pid: 100,
        uid: 501,
        path: PathBuf::from("/Applications/Chrome.app"),
        code_id: Some("com.google.Chrome".to_owned()),
        team_id: Some("EQHXZ8M8AV".to_owned()),
        is_valid_signature: Some(true),
    };
    let other_proc = ProcessIdentity {
        pid: 100,
        uid: 501,
        path: PathBuf::from("/Applications/Other.app"),
        code_id: Some("com.other.App".to_owned()),
        team_id: Some("DIFFERENT01".to_owned()),
        is_valid_signature: Some(true),
    };
    let dest = make_dest("example.com");

    assert!(
        rule_set.user_rules[0].matches(&google_proc, &dest),
        "rule should match process with matching team_id"
    );
    assert!(
        !rule_set.user_rules[0].matches(&other_proc, &dest),
        "rule should not match process with different team_id"
    );
}

#[test]
fn test_profile_process_team_id_empty_rejected() {
    let (groups, tracker_db, category_db) = load_all();

    let toml_str = r#"
        default = "deny"

        [[rules]]
        name = "Bad rule"
        process = { team_id = "" }
        dest = "*"
        action = "allow"
    "#;

    let profile: NetworkProfile = toml::from_str(toml_str).expect("toml should parse");
    let result = profile.resolve(&groups, &tracker_db, &category_db, &[]);
    assert!(
        result.is_err(),
        "empty team_id should be rejected during resolve"
    );
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("team_id must not be empty"),
        "error should mention empty team_id: {err}"
    );
}
