use super::*;
use crate::rule::NetworkAction;

// ---------------------------------------------------------------------------
// LuLu JSON parsing
// ---------------------------------------------------------------------------

const SAMPLE_LULU_JSON: &str = r#"{
    "abc-123": {
        "path": "/Applications/Firefox.app/Contents/MacOS/firefox",
        "name": "firefox",
        "endpointAddr": "detectportal.firefox.com",
        "endpointPort": "443",
        "isEndpointAddrRegex": "0",
        "type": "1",
        "scope": "process",
        "action": 3,
        "csInfo": {
            "signingID": "org.mozilla.firefox",
            "teamID": "43AQ936H96"
        }
    },
    "def-456": {
        "path": "/usr/bin/curl",
        "name": "curl",
        "endpointAddr": "",
        "endpointPort": "",
        "isEndpointAddrRegex": "0",
        "type": "1",
        "scope": "process",
        "action": 4,
        "csInfo": {
            "signingID": "com.apple.curl",
            "teamID": ""
        }
    },
    "ghi-789": {
        "path": "/some/sketchy/binary",
        "name": "sketchy",
        "endpointAddr": "evil\\.com",
        "endpointPort": "",
        "isEndpointAddrRegex": "1",
        "type": "1",
        "scope": "",
        "action": 4
    }
}"#;

#[test]
fn test_import_lulu_from_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rules.json");
    std::fs::write(&path, SAMPLE_LULU_JSON).expect("write");

    let summary = import_lulu(&path).expect("import");

    // 2 imported (firefox allow, curl block), 1 skipped (regex endpoint).
    assert_eq!(
        summary.imported.len(),
        2,
        "expected 2 imported, got: {:?}",
        summary
            .imported
            .iter()
            .map(|r| &r.rule.name)
            .collect::<Vec<_>>()
    );
    assert_eq!(
        summary.skipped.len(),
        1,
        "expected 1 skipped, got: {:?}",
        summary.skipped
    );
    assert!(
        summary.skipped[0].1.contains("regex"),
        "skip reason should mention regex"
    );
}

#[test]
fn test_firefox_rule_uses_team_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rules.json");
    std::fs::write(&path, SAMPLE_LULU_JSON).expect("write");

    let summary = import_lulu(&path).expect("import");

    let firefox = summary
        .imported
        .iter()
        .find(|r| r.rule.name.contains("firefox"))
        .expect("should have firefox rule");

    // Should prefer team_id over signing_id.
    assert_eq!(firefox.rule.process, "team:43AQ936H96");
    assert_eq!(firefox.rule.dest, "detectportal.firefox.com");
    assert_eq!(firefox.rule.dest_port, Some(443));
    assert_eq!(firefox.rule.action, NetworkAction::Allow);
}

#[test]
fn test_curl_rule_uses_signing_id() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rules.json");
    std::fs::write(&path, SAMPLE_LULU_JSON).expect("write");

    let summary = import_lulu(&path).expect("import");

    let curl = summary
        .imported
        .iter()
        .find(|r| r.rule.name.contains("curl"))
        .expect("should have curl rule");

    // Team ID is empty, should fall back to signing ID.
    assert_eq!(curl.rule.process, "com.apple.curl");
    assert_eq!(curl.rule.dest, "*");
    assert_eq!(curl.rule.action, NetworkAction::Deny);
}

#[test]
fn test_rule_with_no_cs_info_uses_path() {
    let json = r#"{
        "test-1": {
            "path": "/opt/homebrew/bin/myapp",
            "name": "myapp",
            "endpointAddr": "api.example.com",
            "endpointPort": "",
            "isEndpointAddrRegex": "0",
            "type": "1",
            "scope": "",
            "action": 4
        }
    }"#;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rules.json");
    std::fs::write(&path, json).expect("write");

    let summary = import_lulu(&path).expect("import");
    assert_eq!(summary.imported.len(), 1);
    assert_eq!(summary.imported[0].rule.process, "/opt/homebrew/bin/myapp");
    assert_eq!(summary.imported[0].rule.dest, "api.example.com");
}

#[test]
fn test_rule_with_ip_destination() {
    let json = r#"{
        "test-1": {
            "path": "/usr/bin/ssh",
            "name": "ssh",
            "endpointAddr": "192.168.1.100",
            "endpointPort": "22",
            "isEndpointAddrRegex": "0",
            "type": "1",
            "scope": "",
            "action": 3,
            "csInfo": {
                "signingID": "com.apple.ssh",
                "teamID": ""
            }
        }
    }"#;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rules.json");
    std::fs::write(&path, json).expect("write");

    let summary = import_lulu(&path).expect("import");
    assert_eq!(summary.imported.len(), 1);
    assert_eq!(summary.imported[0].rule.dest, "192.168.1.100");
    assert_eq!(summary.imported[0].rule.dest_port, Some(22));
}

#[test]
fn test_unknown_action_skipped() {
    let json = r#"{
        "test-1": {
            "path": "/bin/test",
            "name": "test",
            "endpointAddr": "",
            "endpointPort": "",
            "isEndpointAddrRegex": "0",
            "type": "1",
            "scope": "",
            "action": 99
        }
    }"#;

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rules.json");
    std::fs::write(&path, json).expect("write");

    let summary = import_lulu(&path).expect("import");
    assert_eq!(summary.imported.len(), 0);
    assert_eq!(summary.skipped.len(), 1);
    assert!(summary.skipped[0].1.contains("unknown action"));
}

#[test]
fn test_rule_to_toml_serializes() {
    let rule = crate::user_rule::UserRuleFile {
        name: "test-rule".to_owned(),
        process: "com.apple.Safari".to_owned(),
        dest: "example.com".to_owned(),
        dest_port: Some(443),
        action: NetworkAction::Allow,
        enabled: true,
        note: Some("test".to_owned()),
    };

    let toml = rule_to_toml(&rule).expect("serialize");
    assert!(toml.contains("name = \"test-rule\""));
    assert!(toml.contains("process = \"com.apple.Safari\""));
    assert!(toml.contains("dest = \"example.com\""));
    assert!(toml.contains("dest_port = 443"));
}

#[test]
fn test_empty_rules_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("rules.json");
    std::fs::write(&path, "{}").expect("write");

    let summary = import_lulu(&path).expect("import");
    assert_eq!(summary.imported.len(), 0);
    assert_eq!(summary.skipped.len(), 0);
}
