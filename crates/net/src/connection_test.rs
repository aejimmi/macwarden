use super::*;
use crate::rule::{NetworkAction, Protocol, RuleId};
use std::net::IpAddr;
use std::path::PathBuf;

// ---------------------------------------------------------------------------
// Destination::Display
// ---------------------------------------------------------------------------

#[test]
fn test_destination_display_with_host_and_port() {
    let dest = Destination {
        host: Some("apple.com".to_owned()),
        ip: "17.253.144.10".parse::<IpAddr>().expect("valid IP"),
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        address_family: AddressFamily::Inet,
    };
    assert_eq!(dest.to_string(), "apple.com:443");
}

#[test]
fn test_destination_display_host_no_port() {
    let dest = Destination {
        host: Some("apple.com".to_owned()),
        ip: "17.253.144.10".parse::<IpAddr>().expect("valid IP"),
        port: None,
        protocol: None,
        address_family: AddressFamily::Inet,
    };
    assert_eq!(dest.to_string(), "apple.com");
}

#[test]
fn test_destination_display_no_host_uses_ip() {
    let dest = Destination {
        host: None,
        ip: "17.253.144.10".parse::<IpAddr>().expect("valid IP"),
        port: Some(80),
        protocol: None,
        address_family: AddressFamily::Inet,
    };
    assert_eq!(dest.to_string(), "17.253.144.10:80");
}

#[test]
fn test_destination_display_no_host_no_port() {
    let dest = Destination {
        host: None,
        ip: "2001:db8::1".parse::<IpAddr>().expect("valid IPv6"),
        port: None,
        protocol: None,
        address_family: AddressFamily::Inet6,
    };
    assert_eq!(dest.to_string(), "2001:db8::1");
}

// ---------------------------------------------------------------------------
// ProcessIdentity::Display
// ---------------------------------------------------------------------------

#[test]
fn test_process_identity_display_with_code_id() {
    let p = ProcessIdentity {
        pid: 42,
        uid: 501,
        path: PathBuf::from("/Applications/Safari.app/Contents/MacOS/Safari"),
        code_id: Some("com.apple.Safari".to_owned()),
        team_id: None,
        is_valid_signature: None,
    };
    let s = p.to_string();
    assert!(s.contains("com.apple.Safari"), "should show code_id");
    assert!(s.contains("42"), "should show pid");
}

#[test]
fn test_process_identity_display_without_code_id() {
    let p = ProcessIdentity {
        pid: 99,
        uid: 0,
        path: PathBuf::from("/tmp/sketchy"),
        code_id: None,
        team_id: None,
        is_valid_signature: None,
    };
    let s = p.to_string();
    assert!(
        s.contains("/tmp/sketchy"),
        "should show path when no code_id"
    );
    assert!(s.contains("99"), "should show pid");
    assert!(!s.contains("com."), "should not show code_id prefix");
}

// ---------------------------------------------------------------------------
// AddressFamily::Display
// ---------------------------------------------------------------------------

#[test]
fn test_address_family_display() {
    assert_eq!(AddressFamily::Inet.to_string(), "IPv4");
    assert_eq!(AddressFamily::Inet6.to_string(), "IPv6");
}

// ---------------------------------------------------------------------------
// MatchTier::Display — all variants
// ---------------------------------------------------------------------------

#[test]
fn test_match_tier_display_all_variants() {
    assert_eq!(MatchTier::SafeList.to_string(), "safe-list");
    assert_eq!(MatchTier::UserRule.to_string(), "user-rule");
    assert_eq!(
        MatchTier::RuleGroup {
            group_name: "icloud-services".to_owned()
        }
        .to_string(),
        "group/icloud-services"
    );
    assert_eq!(
        MatchTier::Tracker {
            category: "advertising".to_owned()
        }
        .to_string(),
        "tracker-shield/advertising"
    );
    assert_eq!(
        MatchTier::Blocklist {
            list_name: "peter-lowe".to_owned()
        }
        .to_string(),
        "blocklist/peter-lowe"
    );
    assert_eq!(MatchTier::ProfileDefault.to_string(), "profile-default");
}

// ---------------------------------------------------------------------------
// NetworkDecision::Display
// ---------------------------------------------------------------------------

#[test]
fn test_network_decision_display_allow() {
    let d = NetworkDecision {
        action: NetworkAction::Allow,
        matched_rule: None,
        explanation: "no rule matched".to_owned(),
    };
    let s = d.to_string();
    assert!(
        s.starts_with("ALLOWED"),
        "display should start with ALLOWED"
    );
    assert!(s.contains("no rule matched"));
}

#[test]
fn test_network_decision_display_deny() {
    let d = NetworkDecision {
        action: NetworkAction::Deny,
        matched_rule: Some(MatchedRule {
            rule_id: RuleId(7),
            rule_name: "block-ads".to_owned(),
            tier: MatchTier::UserRule,
        }),
        explanation: "DENIED by user-rule".to_owned(),
    };
    let s = d.to_string();
    assert!(s.starts_with("DENIED"), "display should start with DENIED");
}

#[test]
fn test_network_decision_display_log() {
    let d = NetworkDecision {
        action: NetworkAction::Log,
        matched_rule: None,
        explanation: "logging for review".to_owned(),
    };
    assert!(d.to_string().starts_with("LOGGED"));
}

// ---------------------------------------------------------------------------
// ProcessIdentity with team_id
// ---------------------------------------------------------------------------

#[test]
fn test_process_identity_with_team_id() {
    let p = ProcessIdentity {
        pid: 42,
        uid: 501,
        path: PathBuf::from("/Applications/Chrome.app"),
        code_id: Some("com.google.Chrome".to_owned()),
        team_id: Some("EQHXZ8M8AV".to_owned()),
        is_valid_signature: Some(true),
    };
    assert_eq!(p.team_id.as_deref(), Some("EQHXZ8M8AV"));
    assert_eq!(p.is_valid_signature, Some(true));
}

#[test]
fn test_process_identity_display_with_team_id() {
    let p = ProcessIdentity {
        pid: 42,
        uid: 501,
        path: PathBuf::from("/Applications/Chrome.app"),
        code_id: Some("com.google.Chrome".to_owned()),
        team_id: Some("EQHXZ8M8AV".to_owned()),
        is_valid_signature: Some(true),
    };
    let s = p.to_string();
    assert!(
        s.contains("[team EQHXZ8M8AV]"),
        "should show team ID in brackets, got: {s}"
    );
    assert!(
        s.contains("com.google.Chrome"),
        "should show code_id, got: {s}"
    );
    assert!(s.contains("42"), "should show pid, got: {s}");
}

#[test]
fn test_process_identity_display_no_team_id_unchanged() {
    let p = ProcessIdentity {
        pid: 42,
        uid: 501,
        path: PathBuf::from("/Applications/Safari.app"),
        code_id: Some("com.apple.Safari".to_owned()),
        team_id: None,
        is_valid_signature: None,
    };
    let s = p.to_string();
    assert!(
        !s.contains("[team"),
        "should not show team bracket when team_id is None, got: {s}"
    );
    assert_eq!(s, "com.apple.Safari (pid 42)");
}

#[test]
fn test_process_identity_serde_round_trip_with_new_fields() {
    let p = ProcessIdentity {
        pid: 42,
        uid: 501,
        path: PathBuf::from("/Applications/Chrome.app"),
        code_id: Some("com.google.Chrome".to_owned()),
        team_id: Some("EQHXZ8M8AV".to_owned()),
        is_valid_signature: Some(true),
    };
    let json = serde_json::to_string(&p).expect("serialize");
    let back: ProcessIdentity = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back.team_id.as_deref(), Some("EQHXZ8M8AV"));
    assert_eq!(back.is_valid_signature, Some(true));
}

#[test]
fn test_process_identity_deser_without_new_fields() {
    // Simulate legacy JSON without team_id / is_valid_signature.
    let json = r#"{
        "pid": 42,
        "uid": 501,
        "path": "/Applications/Safari.app",
        "code_id": "com.apple.Safari"
    }"#;
    let p: ProcessIdentity = serde_json::from_str(json).expect("deserialize");
    assert!(
        p.team_id.is_none(),
        "team_id should default to None for legacy data"
    );
    assert!(
        p.is_valid_signature.is_none(),
        "is_valid_signature should default to None for legacy data"
    );
}
