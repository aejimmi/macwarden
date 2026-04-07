#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::connection::{AddressFamily, Destination, ProcessIdentity};
use crate::rule::{NetworkAction, RuleId};
use std::net::IpAddr;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_process(path: &str, code_id: Option<&str>) -> ProcessIdentity {
    ProcessIdentity {
        pid: 1234,
        uid: 501,
        path: PathBuf::from(path),
        code_id: code_id.map(ToOwned::to_owned),
        team_id: None,
        is_valid_signature: None,
    }
}

fn make_dest(host: Option<&str>, port: Option<u16>) -> Destination {
    Destination {
        host: host.map(ToOwned::to_owned),
        ip: "127.0.0.1".parse::<IpAddr>().expect("valid IP"),
        port,
        protocol: None,
        address_family: AddressFamily::Inet,
    }
}

// ---------------------------------------------------------------------------
// UserRuleFile tests
// ---------------------------------------------------------------------------

#[test]
fn test_user_rule_file_from_toml() {
    let toml = r#"
name = "Block curl tracking"
process = "/usr/bin/curl"
dest = "tracker.example.com"
action = "deny"
note = "prevent curl exfiltration"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    assert_eq!(rule_file.name, "Block curl tracking");
    assert_eq!(rule_file.process, "/usr/bin/curl");
    assert_eq!(rule_file.dest, "tracker.example.com");
    assert_eq!(rule_file.action, NetworkAction::Deny);
    assert!(rule_file.enabled, "default enabled should be true");
    assert_eq!(rule_file.note.as_deref(), Some("prevent curl exfiltration"));
}

#[test]
fn test_user_rule_file_enabled_defaults_true() {
    let toml = r#"
name = "Test"
process = "*"
dest = "*"
action = "allow"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    assert!(rule_file.enabled, "enabled should default to true");
}

#[test]
fn test_user_rule_file_to_network_rule_path() {
    let toml = r#"
name = "Allow Safari"
process = "/Applications/Safari.app/Contents/MacOS/Safari"
dest = "apple.com"
action = "allow"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    let rule = rule_file.to_network_rule(42).expect("should convert");
    assert_eq!(rule.id, RuleId(42));
    assert_eq!(rule.name, "Allow Safari");
    assert_eq!(rule.action, NetworkAction::Allow);
    assert!(rule.enabled);

    let safari = make_process("/Applications/Safari.app/Contents/MacOS/Safari", None);
    let dest = make_dest(Some("apple.com"), None);
    assert!(rule.matches(&safari, &dest));
}

#[test]
fn test_user_rule_file_to_network_rule_code_id() {
    let toml = r#"
name = "Deny Chrome analytics"
process = "com.google.Chrome"
dest = "analytics.google.com"
action = "deny"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    let rule = rule_file.to_network_rule(1).expect("should convert");

    let chrome = make_process("/Applications/Chrome.app", Some("com.google.Chrome"));
    let dest = make_dest(Some("analytics.google.com"), None);
    assert!(rule.matches(&chrome, &dest));
}

#[test]
fn test_user_rule_file_to_network_rule_any() {
    let toml = r#"
name = "Global log"
process = "*"
dest = "*"
action = "log"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    let rule = rule_file.to_network_rule(1).expect("should convert");

    let any_proc = make_process("/some/app", None);
    let any_dest = make_dest(Some("anything.com"), None);
    assert!(rule.matches(&any_proc, &any_dest));
}

#[test]
fn test_user_rule_file_with_port() {
    let toml = r#"
name = "Allow HTTPS only"
process = "*"
dest = "example.com"
dest_port = 443
action = "allow"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    let rule = rule_file.to_network_rule(1).expect("should convert");

    let proc = make_process("/usr/bin/curl", None);
    let dest_443 = make_dest(Some("example.com"), Some(443));
    let dest_80 = make_dest(Some("example.com"), Some(80));
    assert!(rule.matches(&proc, &dest_443));
    assert!(!rule.matches(&proc, &dest_80));
}

#[test]
fn test_load_user_rules_from_dir() {
    let dir = tempfile::tempdir().expect("should create temp dir");

    let rule1 = r#"
name = "Rule one"
process = "*"
dest = "one.com"
action = "allow"
"#;
    let rule2 = r#"
name = "Rule two"
process = "/usr/bin/curl"
dest = "two.com"
action = "deny"
"#;
    std::fs::write(dir.path().join("rule1.toml"), rule1).expect("write");
    std::fs::write(dir.path().join("rule2.toml"), rule2).expect("write");
    // Non-toml file should be skipped.
    std::fs::write(dir.path().join("readme.txt"), "ignore me").expect("write");

    let rules = load_user_rules(dir.path()).expect("should load rules");
    assert_eq!(rules.len(), 2, "should load exactly 2 .toml files");
}

// ---------------------------------------------------------------------------
// Error: missing required fields
// ---------------------------------------------------------------------------

#[test]
fn test_from_toml_missing_name_returns_error() {
    let toml = r#"
process = "*"
dest = "*"
action = "allow"
"#;
    let result = UserRuleFile::from_toml(toml);
    assert!(result.is_err(), "missing 'name' field should return error");
}

#[test]
fn test_from_toml_missing_action_returns_error() {
    let toml = r#"
name = "Test rule"
process = "*"
dest = "*"
"#;
    let result = UserRuleFile::from_toml(toml);
    assert!(
        result.is_err(),
        "missing 'action' field should return error"
    );
}

#[test]
fn test_from_toml_missing_process_returns_error() {
    let toml = r#"
name = "Test rule"
dest = "*"
action = "deny"
"#;
    let result = UserRuleFile::from_toml(toml);
    assert!(
        result.is_err(),
        "missing 'process' field should return error"
    );
}

#[test]
fn test_from_toml_missing_dest_returns_error() {
    let toml = r#"
name = "Test rule"
process = "*"
action = "allow"
"#;
    let result = UserRuleFile::from_toml(toml);
    assert!(result.is_err(), "missing 'dest' field should return error");
}

// ---------------------------------------------------------------------------
// Error: invalid action string
// ---------------------------------------------------------------------------

#[test]
fn test_from_toml_invalid_action_returns_error() {
    let toml = r#"
name = "Bad rule"
process = "*"
dest = "*"
action = "block"
"#;
    let result = UserRuleFile::from_toml(toml);
    assert!(
        result.is_err(),
        "invalid action value 'block' should return error"
    );
}

// ---------------------------------------------------------------------------
// Extra unknown fields are ignored (serde default behavior)
// ---------------------------------------------------------------------------

#[test]
fn test_from_toml_extra_unknown_fields_ignored() {
    let toml = r#"
name = "Test rule"
process = "*"
dest = "*"
action = "log"
unknown_field = "ignored"
another_unknown = 42
"#;
    // serde with deny_unknown_fields would error; without it, extra fields
    // are silently ignored (the TOML crate's default).
    let result = UserRuleFile::from_toml(toml);
    assert!(
        result.is_ok(),
        "extra unknown fields should be ignored, got: {:?}",
        result.err()
    );
    let rule = result.unwrap();
    assert_eq!(rule.action, NetworkAction::Log);
}

// ---------------------------------------------------------------------------
// load_user_rules: malformed file is skipped, not fatal
// ---------------------------------------------------------------------------

#[test]
fn test_load_user_rules_skips_malformed_file() {
    let dir = tempfile::tempdir().expect("should create temp dir");

    let good_rule = r#"
name = "Good rule"
process = "*"
dest = "good.com"
action = "allow"
"#;
    let bad_rule = "this is not valid toml = = = garbage";

    std::fs::write(dir.path().join("good.toml"), good_rule).expect("write");
    std::fs::write(dir.path().join("bad.toml"), bad_rule).expect("write");

    let rules = load_user_rules(dir.path()).expect("should not error on malformed file");
    assert_eq!(
        rules.len(),
        1,
        "malformed rule file should be skipped, good rule should load"
    );
    assert_eq!(rules[0].name, "Good rule");
}

// ---------------------------------------------------------------------------
// load_user_rules: nonexistent directory returns error
// ---------------------------------------------------------------------------

#[test]
fn test_load_user_rules_nonexistent_dir_returns_error() {
    let result = load_user_rules(std::path::Path::new("/nonexistent/path/net-rules"));
    assert!(result.is_err(), "nonexistent directory should return error");
}

// ---------------------------------------------------------------------------
// Disabled rule loaded from file
// ---------------------------------------------------------------------------

#[test]
fn test_user_rule_file_disabled_rule() {
    let toml = r#"
name = "Disabled deny all"
process = "*"
dest = "*"
action = "deny"
enabled = false
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    assert!(!rule_file.enabled, "enabled = false should be preserved");
    let rule = rule_file.to_network_rule(1).expect("should convert");
    assert!(!rule.enabled);

    // A disabled rule should not match anything.
    let proc = make_process("/usr/bin/curl", None);
    let dest = make_dest(Some("anything.com"), None);
    assert!(!rule.matches(&proc, &dest), "disabled rule must not match");
}
