//! Tests for the persisted policy configuration.
#![allow(clippy::indexing_slicing, clippy::panic, clippy::default_trait_access)]

use super::*;
use crate::connection::{AddressFamily, Destination, ProcessIdentity};
use crate::host::HostPattern;
use crate::matcher::RuleSet;
use crate::profile::{GroupSettings, NetworkProfile};
use crate::rule::{DestMatcher, NetworkAction, NetworkRule, ProcessMatcher, RuleDuration, RuleId};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use tempfile::TempDir;

fn process(path: &str, code_id: Option<&str>, team_id: Option<&str>) -> ProcessIdentity {
    ProcessIdentity {
        pid: 1,
        uid: 501,
        path: PathBuf::from(path),
        code_id: code_id.map(ToOwned::to_owned),
        team_id: team_id.map(ToOwned::to_owned),
        is_valid_signature: None,
        is_apple_signed: None,
    }
}

fn dest(host: Option<&str>, ip: &str) -> Destination {
    Destination {
        host: host.map(ToOwned::to_owned),
        ip: ip.parse().expect("ip"),
        port: None,
        protocol: None,
        address_family: AddressFamily::Inet,
    }
}

/// Build a minimal rule set from a policy config: default from mode + the
/// synthetic allow rules, sorted.
fn ruleset_from(config: &PolicyConfig) -> RuleSet {
    let mut rs = RuleSet {
        default_action: config.mode.default_action(),
        ..RuleSet::default()
    };
    rs.user_rules
        .extend(config.to_allow_rules().expect("allow rules"));
    rs.sort_user_rules();
    rs
}

// ---------------------------------------------------------------------------
// PolicyMode
// ---------------------------------------------------------------------------

#[test]
fn test_default_action_allow_all_is_log() {
    assert_eq!(PolicyMode::AllowAll.default_action(), NetworkAction::Log);
}

#[test]
fn test_default_action_block_all_is_deny() {
    assert_eq!(PolicyMode::BlockAll.default_action(), NetworkAction::Deny);
}

#[test]
fn test_mode_serde_strings() {
    let toml = toml::to_string(&PolicyConfig {
        mode: PolicyMode::BlockAll,
        ..PolicyConfig::default()
    })
    .expect("serialize");
    assert!(toml.contains("mode = \"block\""), "got: {toml}");
}

// ---------------------------------------------------------------------------
// Defaults / fail-open
// ---------------------------------------------------------------------------

#[test]
fn test_load_missing_returns_default() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("net-profile.toml");
    let config = PolicyConfig::load(&path);
    assert_eq!(config, PolicyConfig::default());
    assert_eq!(config.mode, PolicyMode::AllowAll);
    assert!(!config.allow_apple_programs);
    assert!(config.allow_dns_traffic);
    assert!(config.groups.enable.is_empty());
    assert!(config.allowlist.is_empty());
}

#[test]
fn test_load_malformed_returns_default() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("net-profile.toml");
    std::fs::write(&path, "this is = = not valid toml [[[").expect("write");
    let config = PolicyConfig::load(&path);
    assert_eq!(config, PolicyConfig::default());
}

#[test]
fn test_load_drops_invalid_entry_keeps_rest() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("net-profile.toml");
    // First entry is all-None (invalid); second is valid.
    let toml = r#"
mode = "block"
[[allowlist]]
note = "empty, should drop"
[[allowlist]]
host = "example.com"
"#;
    std::fs::write(&path, toml).expect("write");
    let config = PolicyConfig::load(&path);
    assert_eq!(config.mode, PolicyMode::BlockAll);
    assert_eq!(config.allowlist.len(), 1);
    assert_eq!(config.allowlist[0].host.as_deref(), Some("example.com"));
}

// ---------------------------------------------------------------------------
// Round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_save_load_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("sub").join("net-profile.toml");
    let config = PolicyConfig {
        mode: PolicyMode::BlockAll,
        allow_apple_programs: true,
        allow_dns_traffic: false,
        groups: GroupSettings {
            enable: vec!["location-services".to_owned()],
            disable: vec!["gaming".to_owned()],
        },
        allowlist: vec![
            AllowListEntry {
                app: Some("com.google.Chrome".to_owned()),
                team_id: None,
                host: Some("*.googleapis.com".to_owned()),
                ip: None,
                note: Some("work SSO".to_owned()),
            },
            AllowListEntry {
                app: None,
                team_id: None,
                host: None,
                ip: Some(parse_ip_or_cidr("140.82.112.0/20").expect("cidr")),
                note: None,
            },
        ],
    };
    config.save(&path).expect("save");
    let loaded = PolicyConfig::load(&path);
    assert_eq!(loaded, config);
}

#[test]
fn test_save_is_atomic_no_tmp_left() {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("net-profile.toml");
    PolicyConfig::default().save(&path).expect("save");
    assert!(path.exists());
    let tmp = dir.path().join("net-profile.toml.tmp");
    assert!(!tmp.exists(), "temp file should be renamed away");
}

// ---------------------------------------------------------------------------
// AllowListEntry validation
// ---------------------------------------------------------------------------

#[test]
fn test_entry_all_none_rejected() {
    let entry = AllowListEntry {
        app: None,
        team_id: None,
        host: None,
        ip: None,
        note: Some("x".to_owned()),
    };
    assert!(entry.validate().is_err());
}

#[test]
fn test_entry_app_and_team_id_rejected() {
    let entry = AllowListEntry {
        app: Some("com.google.Chrome".to_owned()),
        team_id: Some("EQHXZ8M8AV".to_owned()),
        host: Some("x.com".to_owned()),
        ip: None,
        note: None,
    };
    assert!(entry.validate().is_err());
}

#[test]
fn test_entry_host_only_matches_any_process() {
    let entry = AllowListEntry {
        app: None,
        team_id: None,
        host: Some("example.com".to_owned()),
        ip: None,
        note: None,
    };
    let rule = entry.to_network_rule(800_000).expect("rule");
    let p = process("/usr/bin/anything", Some("com.example.foo"), None);
    assert!(rule.matches(&p, &dest(Some("example.com"), "1.2.3.4")));
}

#[test]
fn test_entry_app_and_cidr_scopes_match() {
    let entry = AllowListEntry {
        app: Some("com.google.Chrome".to_owned()),
        team_id: None,
        host: None,
        ip: Some(parse_ip_or_cidr("10.0.0.0/8").expect("cidr")),
        note: None,
    };
    let rule = entry.to_network_rule(800_000).expect("rule");
    let chrome = process("/Applications/Chrome.app", Some("com.google.Chrome"), None);
    let other = process("/Applications/Other.app", Some("com.other.App"), None);
    assert!(rule.matches(&chrome, &dest(None, "10.1.2.3")));
    assert!(!rule.matches(&chrome, &dest(None, "8.8.8.8")));
    assert!(!rule.matches(&other, &dest(None, "10.1.2.3")));
}

// ---------------------------------------------------------------------------
// Mode / allow-list decisions
// ---------------------------------------------------------------------------

#[test]
fn test_allow_all_no_rules_logs() {
    let rs = ruleset_from(&PolicyConfig::default());
    let p = process("/bin/app", Some("com.x.y"), None);
    let d = rs.decide_for(&p, &dest(Some("random.example"), "9.9.9.9"));
    assert_eq!(d.action, NetworkAction::Log);
    assert!(d.matched_rule.is_none());
}

#[test]
fn test_block_all_no_carveouts_denies() {
    let config = PolicyConfig {
        mode: PolicyMode::BlockAll,
        allow_dns_traffic: false,
        ..PolicyConfig::default()
    };
    let rs = ruleset_from(&config);
    let p = process("/bin/app", Some("com.x.y"), None);
    let d = rs.decide_for(&p, &dest(Some("random.example"), "9.9.9.9"));
    assert_eq!(d.action, NetworkAction::Deny);
}

#[test]
fn test_block_all_essential_domain_allowed() {
    let config = PolicyConfig {
        mode: PolicyMode::BlockAll,
        allow_dns_traffic: false,
        ..PolicyConfig::default()
    };
    let rs = ruleset_from(&config);
    let p = process("/bin/app", Some("com.x.y"), None);
    // ocsp.apple.com is an essential (safelist) domain.
    let d = rs.decide_for(&p, &dest(Some("ocsp.apple.com"), "17.1.1.1"));
    assert_eq!(d.action, NetworkAction::Allow);
}

#[test]
fn test_block_all_allowlist_host_allows_match_denies_other() {
    let config = PolicyConfig {
        mode: PolicyMode::BlockAll,
        allow_dns_traffic: false,
        allowlist: vec![AllowListEntry {
            app: None,
            team_id: None,
            host: Some("*.example.com".to_owned()),
            ip: None,
            note: None,
        }],
        ..PolicyConfig::default()
    };
    let rs = ruleset_from(&config);
    let p = process("/bin/app", Some("com.x.y"), None);
    assert_eq!(
        rs.decide_for(&p, &dest(Some("api.example.com"), "1.2.3.4"))
            .action,
        NetworkAction::Allow
    );
    assert_eq!(
        rs.decide_for(&p, &dest(Some("evil.com"), "1.2.3.4")).action,
        NetworkAction::Deny
    );
}

#[test]
fn test_block_all_more_specific_deny_beats_allowlist() {
    let config = PolicyConfig {
        mode: PolicyMode::BlockAll,
        allow_dns_traffic: false,
        allowlist: vec![AllowListEntry {
            app: None,
            team_id: None,
            host: Some("*.googleapis.com".to_owned()),
            ip: None,
            note: None,
        }],
        ..PolicyConfig::default()
    };
    let mut rs = ruleset_from(&config);
    // A more-specific Tier-1 Deny (specific process) inside the allowed glob.
    // The allow-list rule is process-Any; this deny names the process, so it
    // ranks higher by process specificity and wins for that process.
    rs.user_rules.push(NetworkRule {
        id: RuleId(10),
        name: "block analytics".to_owned(),
        process: ProcessMatcher::code_id("com.x.y").expect("code id"),
        destination: DestMatcher {
            host: Some(HostPattern::new("analytics.googleapis.com").expect("host")),
            ..Default::default()
        },
        action: NetworkAction::Deny,
        duration: RuleDuration::Permanent,
        enabled: true,
        note: None,
    });
    rs.sort_user_rules();
    let p = process("/bin/app", Some("com.x.y"), None);
    // The named process is denied to the more-specific host...
    assert_eq!(
        rs.decide_for(&p, &dest(Some("analytics.googleapis.com"), "1.2.3.4"))
            .action,
        NetworkAction::Deny
    );
    // ...but still allowed to other hosts in the pattern.
    assert_eq!(
        rs.decide_for(&p, &dest(Some("sheets.googleapis.com"), "1.2.3.4"))
            .action,
        NetworkAction::Allow
    );
    // A different process is not affected by the specific deny.
    let other = process("/bin/other", Some("com.other.app"), None);
    assert_eq!(
        rs.decide_for(&other, &dest(Some("analytics.googleapis.com"), "1.2.3.4"))
            .action,
        NetworkAction::Allow
    );
}

#[test]
fn test_block_all_team_id_allowlist() {
    let config = PolicyConfig {
        mode: PolicyMode::BlockAll,
        allow_dns_traffic: false,
        allowlist: vec![AllowListEntry {
            app: None,
            team_id: Some("EQHXZ8M8AV".to_owned()),
            host: None,
            ip: None,
            note: None,
        }],
        ..PolicyConfig::default()
    };
    let rs = ruleset_from(&config);
    let signed = process(
        "/Applications/Foo.app",
        Some("com.foo.Bar"),
        Some("EQHXZ8M8AV"),
    );
    let unsigned = process("/Applications/Foo.app", Some("com.foo.Bar"), None);
    assert_eq!(
        rs.decide_for(&signed, &dest(Some("x.com"), "1.2.3.4"))
            .action,
        NetworkAction::Allow
    );
    assert_eq!(
        rs.decide_for(&unsigned, &dest(Some("x.com"), "1.2.3.4"))
            .action,
        NetworkAction::Deny
    );
}

// ---------------------------------------------------------------------------
// DNS carve-out
// ---------------------------------------------------------------------------

#[test]
fn test_dns_allowed_when_flag_on() {
    let config = PolicyConfig {
        mode: PolicyMode::BlockAll,
        allow_dns_traffic: true,
        ..PolicyConfig::default()
    };
    let rs = ruleset_from(&config);
    let resolver = process(DNS_RESOLVER_PATH, Some(DNS_RESOLVER_CODE_ID), None);
    let d = rs.decide_for(&resolver, &dest(Some("whatever.example"), "9.9.9.9"));
    assert_eq!(d.action, NetworkAction::Allow);
}

#[test]
fn test_dns_denied_when_flag_off() {
    let config = PolicyConfig {
        mode: PolicyMode::BlockAll,
        allow_dns_traffic: false,
        ..PolicyConfig::default()
    };
    let rs = ruleset_from(&config);
    let resolver = process(DNS_RESOLVER_PATH, Some(DNS_RESOLVER_CODE_ID), None);
    let d = rs.decide_for(&resolver, &dest(Some("whatever.example"), "9.9.9.9"));
    assert_eq!(d.action, NetworkAction::Deny);
}

#[test]
fn test_dns_flag_does_not_allow_other_apps() {
    let config = PolicyConfig {
        mode: PolicyMode::BlockAll,
        allow_dns_traffic: true,
        ..PolicyConfig::default()
    };
    let rs = ruleset_from(&config);
    let other = process("/Applications/App.app", Some("com.app"), None);
    let d = rs.decide_for(&other, &dest(Some("whatever.example"), "9.9.9.9"));
    assert_eq!(d.action, NetworkAction::Deny);
}

// ---------------------------------------------------------------------------
// Reserved id band + helpers
// ---------------------------------------------------------------------------

#[test]
fn test_synthetic_rules_use_reserved_id_band() {
    let config = PolicyConfig {
        allow_dns_traffic: true,
        allowlist: vec![AllowListEntry {
            app: None,
            team_id: None,
            host: Some("x.com".to_owned()),
            ip: None,
            note: None,
        }],
        ..PolicyConfig::default()
    };
    let rules = config.to_allow_rules().expect("rules");
    assert!(rules.iter().all(|r| r.id.0 >= ALLOWLIST_RULE_ID_BASE));
}

#[test]
fn test_is_apple_code_id() {
    assert!(is_apple_code_id("com.apple.Safari"));
    assert!(!is_apple_code_id("com.google.Chrome"));
}

#[test]
fn test_parse_ip_or_cidr_bare_and_cidr() {
    let bare = parse_ip_or_cidr("1.2.3.4").expect("bare");
    assert!(bare.contains(&IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    let cidr = parse_ip_or_cidr("10.0.0.0/8").expect("cidr");
    assert!(cidr.contains(&IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1))));
    assert!(parse_ip_or_cidr("not-an-ip").is_err());
}

#[test]
fn test_apply_to_sets_default_and_merges_groups() {
    let config = PolicyConfig {
        mode: PolicyMode::BlockAll,
        groups: GroupSettings {
            enable: vec!["location-services".to_owned()],
            disable: vec!["gaming".to_owned()],
        },
        ..PolicyConfig::default()
    };
    let mut profile = NetworkProfile {
        default: NetworkAction::Log,
        trackers: Default::default(),
        groups: GroupSettings {
            enable: vec!["development".to_owned()],
            disable: Vec::new(),
        },
        blocklists: Default::default(),
        rules: Vec::new(),
    };
    config.apply_to(&mut profile);
    assert_eq!(profile.default, NetworkAction::Deny);
    assert!(profile.groups.enable.contains(&"development".to_owned()));
    assert!(
        profile
            .groups
            .enable
            .contains(&"location-services".to_owned())
    );
    assert!(profile.groups.disable.contains(&"gaming".to_owned()));
}
