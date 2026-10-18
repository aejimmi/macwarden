#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use ipc::protocol::WireVerdict;
use net::{DestMatcher, NetworkAction, NetworkRule, ProcessMatcher, RuleDuration, RuleId, RuleSet};

use super::*;

#[test]
fn test_make_slug_sanitizes_and_lowercases() {
    assert_eq!(
        make_slug(Some("com.Example.App"), Some("Ads.Tracker.com")),
        "com-example-app-ads-tracker-com"
    );
    assert_eq!(make_slug(Some("com.a"), None), "com-a");
    assert_eq!(make_slug(None, Some("host.com")), "host-com");
    assert_eq!(make_slug(None, None), "unknown");
}

#[test]
fn test_generate_rule_toml_matches_net_block_format() {
    let toml = generate_rule_toml(Some("com.example.app"), Some("ads.example"));
    assert!(toml.contains("process = \"com.example.app\""));
    assert!(toml.contains("dest = \"ads.example\""));
    assert!(toml.contains("action = \"deny\""));
    assert!(toml.contains("enabled = true"));
}

#[test]
fn test_generate_rule_toml_app_only_uses_wildcard_dest() {
    let toml = generate_rule_toml(Some("com.example.app"), None);
    assert!(toml.contains("process = \"com.example.app\""));
    assert!(toml.contains("dest = \"*\""));
}

fn ruleset_with_deny(code_id: &str) -> RuleSet {
    let mut rs = RuleSet::default();
    rs.user_rules = vec![NetworkRule {
        id: RuleId(1),
        name: "block".to_owned(),
        process: ProcessMatcher::code_id(code_id).unwrap(),
        destination: DestMatcher::default(),
        action: NetworkAction::Deny,
        duration: RuleDuration::Permanent,
        enabled: true,
        note: None,
    }];
    rs.sort_user_rules();
    rs
}

#[test]
fn test_verdict_for_target_blocked_when_denied() {
    let rs = ruleset_with_deny("com.example.app");
    let verdict = verdict_for_target(&rs, Some("com.example.app"), None);
    assert_eq!(verdict, WireVerdict::Blocked);
}

#[test]
fn test_verdict_for_target_allow_when_no_rule() {
    let rs = RuleSet::default();
    let verdict = verdict_for_target(&rs, Some("com.other.app"), None);
    assert_eq!(verdict, WireVerdict::Allow);
}
