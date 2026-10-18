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
        is_apple_signed: None,
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

// ---------------------------------------------------------------------------
// R9: extended on-disk format (ip / CIDR + protocol + team_id)
// ---------------------------------------------------------------------------

#[test]
fn test_dest_ip_cidr_parses_and_matches() {
    let toml = r#"
name = "block subnet"
process = "*"
dest = "*"
dest_ip = "192.168.0.0/16"
action = "deny"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    let rule = rule_file.to_network_rule(1).expect("should convert");
    let proc = make_process("/bin/app", None);
    let inside = Destination {
        host: None,
        ip: "192.168.5.5".parse::<IpAddr>().expect("ip"),
        port: None,
        protocol: None,
        address_family: AddressFamily::Inet,
    };
    let outside = Destination {
        host: None,
        ip: "10.0.0.1".parse::<IpAddr>().expect("ip"),
        port: None,
        protocol: None,
        address_family: AddressFamily::Inet,
    };
    assert!(rule.matches(&proc, &inside));
    assert!(!rule.matches(&proc, &outside));
}

#[test]
fn test_team_id_selects_team_matcher() {
    let toml = r#"
name = "allow team"
process = "*"
dest = "*"
team_id = "EQHXZ8M8AV"
action = "allow"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    let rule = rule_file.to_network_rule(1).expect("should convert");
    assert!(
        matches!(rule.process, crate::rule::ProcessMatcher::TeamId(ref t) if t == "EQHXZ8M8AV")
    );
}

#[test]
fn test_team_id_with_non_star_process_errors() {
    let toml = r#"
name = "conflict"
process = "com.foo.Bar"
dest = "*"
team_id = "EQHXZ8M8AV"
action = "allow"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    assert!(rule_file.to_network_rule(1).is_err());
}

#[test]
fn test_team_id_bad_length_errors() {
    let toml = r#"
name = "bad team"
process = "*"
dest = "*"
team_id = "short"
action = "allow"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    assert!(rule_file.to_network_rule(1).is_err());
}

#[test]
fn test_old_file_without_new_fields_still_parses() {
    let toml = r#"
name = "legacy"
process = "com.apple.Safari"
dest = "apple.com"
action = "allow"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    assert!(rule_file.dest_ip.is_none());
    assert!(rule_file.dest_protocol.is_none());
    assert!(rule_file.team_id.is_none());
    rule_file.to_network_rule(1).expect("should convert");
}

// ---------------------------------------------------------------------------
// R2/R3 hardening: symlink skip, size/count/total caps, no-content logging
// ---------------------------------------------------------------------------

/// A minimal valid rule file body with the given (unique) name.
fn valid_rule(name: &str) -> String {
    format!("name = \"{name}\"\nprocess = \"*\"\ndest = \"*\"\naction = \"log\"\n")
}

/// Non-default limits for exercising a specific cap without huge fixtures.
fn limits(per_file_bytes: u64, file_count: usize, total_bytes: u64) -> RuleLoadLimits {
    RuleLoadLimits {
        per_file_bytes,
        file_count,
        total_bytes,
    }
}

#[test]
fn test_load_user_rules_skips_symlinked_file() {
    let root = tempfile::tempdir().expect("tempdir");
    // A valid rule stored OUTSIDE the rules dir — the confused-deputy target.
    let outside = root.path().join("outside.toml");
    std::fs::write(&outside, valid_rule("secret")).expect("write outside");

    let rules_dir = root.path().join("net-rules");
    std::fs::create_dir(&rules_dir).expect("mkdir");
    // A symlink into the rules dir pointing at the outside file...
    std::os::unix::fs::symlink(&outside, rules_dir.join("link.toml")).expect("symlink");
    // ...and a genuine regular file, to prove non-symlinks still load.
    std::fs::write(rules_dir.join("real.toml"), valid_rule("real")).expect("write real");

    let rules = load_user_rules(&rules_dir).expect("load");
    assert_eq!(rules.len(), 1, "symlinked rule file must be skipped");
    assert_eq!(rules[0].name, "real");
}

#[test]
fn test_read_rule_file_refuses_symlink_with_o_nofollow() {
    // Belt-and-suspenders: even bypassing the lstat pre-check, the O_NOFOLLOW
    // open itself refuses a symlinked final component.
    let root = tempfile::tempdir().expect("tempdir");
    let target = root.path().join("target.toml");
    std::fs::write(&target, valid_rule("t")).expect("write");
    let link = root.path().join("link.toml");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");

    let err = read_rule_file(&link, 256 * 1024).expect_err("O_NOFOLLOW must reject a symlink");
    // ELOOP ("Too many levels of symbolic links"); exact kind varies by libc, so
    // just assert it failed rather than followed and read the target.
    let _ = err;
}

#[test]
fn test_load_user_rules_skips_oversize_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let big = format!("{}# {}\n", valid_rule("big"), "x".repeat(400));
    std::fs::write(dir.path().join("big.toml"), &big).expect("write big");
    std::fs::write(dir.path().join("small.toml"), valid_rule("small")).expect("write small");

    let rules =
        load_user_rules_with_limits(dir.path(), limits(200, 1024, 8 * 1024 * 1024)).expect("load");
    assert_eq!(rules.len(), 1, "oversize file must be skipped");
    assert_eq!(rules[0].name, "small");
}

#[test]
fn test_load_user_rules_respects_file_count_cap() {
    let dir = tempfile::tempdir().expect("tempdir");
    for i in 0..5 {
        std::fs::write(
            dir.path().join(format!("r{i}.toml")),
            valid_rule(&format!("r{i}")),
        )
        .expect("write");
    }
    let rules = load_user_rules_with_limits(dir.path(), limits(256 * 1024, 2, 8 * 1024 * 1024))
        .expect("load");
    assert_eq!(rules.len(), 2, "file-count cap must bound files read");
}

#[test]
fn test_load_user_rules_respects_total_byte_cap() {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(dir.path().join("a.toml"), valid_rule("a")).expect("write a");
    std::fs::write(dir.path().join("b.toml"), valid_rule("b")).expect("write b");
    // Each file is ~40 bytes; a 60-byte total budget admits exactly one.
    let rules =
        load_user_rules_with_limits(dir.path(), limits(256 * 1024, 1024, 60)).expect("load");
    assert_eq!(rules.len(), 1, "total-byte cap must bound bytes read");
}

/// A `tracing` writer that captures all emitted output into a shared buffer.
#[derive(Clone, Default)]
struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for LogCapture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("log buffer lock")
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn test_load_user_rules_malformed_file_does_not_log_content() {
    let dir = tempfile::tempdir().expect("tempdir");
    // A sentinel that appears ONLY in the file body, never in its path, and that
    // a TOML error's `Display` would embed if the message were logged verbatim.
    let sentinel = "leaked_secret_value";
    std::fs::write(
        dir.path().join("bad.toml"),
        format!("{sentinel} = = = not toml"),
    )
    .expect("write bad");

    let capture = LogCapture::default();
    let sink = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || sink.clone())
        .with_max_level(tracing::Level::WARN)
        .without_time()
        .finish();

    let rules = tracing::subscriber::with_default(subscriber, || {
        load_user_rules(dir.path()).expect("load")
    });
    assert!(rules.is_empty(), "malformed file yields no rules");

    let logged = String::from_utf8(capture.0.lock().expect("lock").clone()).expect("utf8");
    assert!(
        logged.contains("malformed TOML"),
        "the skip must be logged (path + coarse kind): {logged}"
    );
    assert!(
        !logged.contains(sentinel),
        "the file's content must NOT appear in the log: {logged}"
    );
}

#[test]
fn test_ip_and_protocol_round_trip() {
    let toml = r#"
name = "rt"
process = "*"
dest = "*"
dest_ip = "1.2.3.4"
dest_protocol = "tcp"
action = "deny"
"#;
    let rule_file = UserRuleFile::from_toml(toml).expect("should parse");
    // Re-serialize and re-parse.
    let serialized = toml::to_string(&rule_file).expect("serialize");
    let reparsed = UserRuleFile::from_toml(&serialized).expect("reparse");
    assert_eq!(reparsed.dest_ip.as_deref(), Some("1.2.3.4"));
    assert_eq!(reparsed.dest_protocol, Some(crate::rule::Protocol::Tcp));
    let rule = reparsed.to_network_rule(1).expect("convert");
    assert!(rule.destination.ip.is_some());
    assert_eq!(rule.destination.protocol, Some(crate::rule::Protocol::Tcp));
}
