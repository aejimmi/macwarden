use super::*;
use net_explain::{build_destination, build_process_identity};

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

#[test]
fn test_build_process_identity_code_id() {
    let pi = build_process_identity("com.apple.Safari");
    assert_eq!(pi.code_id.as_deref(), Some("com.apple.Safari"));
    assert_eq!(pi.path, PathBuf::from("/unknown"));
}

#[test]
fn test_build_process_identity_path() {
    let pi = build_process_identity("/usr/bin/curl");
    assert!(pi.code_id.is_none());
    assert_eq!(pi.path, PathBuf::from("/usr/bin/curl"));
}

#[test]
fn test_build_destination_with_host() {
    let dest = build_destination(Some("example.com"));
    assert_eq!(dest.host.as_deref(), Some("example.com"));
    assert_eq!(dest.ip, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    assert!(dest.port.is_none());
}

#[test]
fn test_build_destination_without_host() {
    let dest = build_destination(None);
    assert!(dest.host.is_none());
}

#[test]
fn test_format_dest_any() {
    let dest = net::DestMatcher::default();
    assert_eq!(format_dest(&dest), "*");
}

#[test]
fn test_format_dest_with_port() {
    let dest = net::DestMatcher {
        port: Some(net::PortMatcher::Single(443)),
        ..Default::default()
    };
    assert_eq!(format_dest(&dest), ":443");
}

#[test]
fn test_group_domain_count_empty() {
    let group = net::NetworkGroup {
        name: "test".to_owned(),
        description: "test group".to_owned(),
        default_enabled: true,
        priority: 10,
        rules: vec![],
    };
    assert_eq!(group_domain_count(&group), 0);
}

#[test]
fn test_group_domain_count_multiple_rules() {
    let group = net::NetworkGroup {
        name: "test".to_owned(),
        description: "test group".to_owned(),
        default_enabled: true,
        priority: 10,
        rules: vec![
            net::NetworkGroupRule {
                name: "r1".to_owned(),
                process: "*".to_owned(),
                dest_hosts: vec!["a.com".to_owned(), "b.com".to_owned()],
                action: NetworkAction::Allow,
                note: None,
            },
            net::NetworkGroupRule {
                name: "r2".to_owned(),
                process: "*".to_owned(),
                dest_hosts: vec!["c.com".to_owned()],
                action: NetworkAction::Allow,
                note: None,
            },
        ],
    };
    assert_eq!(group_domain_count(&group), 3);
}

#[test]
fn test_base_profile_defaults_to_log() {
    let profile = base_profile();
    assert_eq!(profile.default, NetworkAction::Log);
    assert!(profile.rules.is_empty());
}

#[test]
fn test_build_base_ruleset_succeeds() {
    let result = build_base_ruleset();
    assert!(result.is_ok());
    let rs = result.expect("ruleset should build");
    assert_eq!(rs.default_action, NetworkAction::Log);
}
