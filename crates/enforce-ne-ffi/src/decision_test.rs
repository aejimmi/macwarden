use super::*;

use std::path::Path;

use net::RuleSet;

fn ruleset(profile: &str, rule: Option<&str>) -> RuleSet {
    let dir = tempfile::TempDir::new().expect("tempdir");
    if !profile.is_empty() {
        std::fs::write(dir.path().join("net-profile.toml"), profile).expect("write profile");
    }
    if let Some(rule) = rule {
        let rules = dir.path().join("net-rules");
        std::fs::create_dir_all(&rules).expect("mkdir net-rules");
        std::fs::write(rules.join("rule.toml"), rule).expect("write rule");
    }
    net::load_live_ruleset(dir.path(), &[], &[]).expect("load ruleset")
}

#[test]
fn test_build_identity_empty_is_unknown() {
    let id = build_identity(Some(""), Some(""));
    assert!(id.code_id.is_none());
    assert_eq!(id.path, Path::new(""));
    assert!(id.is_apple_signed.is_none());
}

#[test]
fn test_build_identity_apple_code_id_flags_apple_signed() {
    let id = build_identity(Some("com.apple.Safari"), Some("/Applications/Safari.app"));
    assert_eq!(id.code_id.as_deref(), Some("com.apple.Safari"));
    assert_eq!(id.is_apple_signed, Some(true));
}

#[test]
fn test_build_identity_third_party_is_not_apple_signed() {
    let id = build_identity(Some("com.evil.tracker"), None);
    assert_eq!(id.is_apple_signed, Some(false));
}

#[test]
fn test_build_destination_maps_protocol_and_family() {
    let d = build_destination(Some("example.com"), Some("2001:db8::1"), 443, 6);
    assert_eq!(d.host.as_deref(), Some("example.com"));
    assert_eq!(d.port, Some(443));
    assert_eq!(d.protocol, Some(net::Protocol::Tcp));
    assert_eq!(d.address_family, net::AddressFamily::Inet6);
}

#[test]
fn test_build_destination_bad_ip_falls_back_to_unspecified() {
    let d = build_destination(Some("example.com"), Some("not-an-ip"), 0, 99);
    assert!(d.ip.is_unspecified());
    assert_eq!(d.port, None);
    assert_eq!(d.protocol, None);
    assert_eq!(d.address_family, net::AddressFamily::Inet);
}

#[test]
fn test_decide_allow_all_default_is_log() {
    let rs = ruleset("", None);
    let d = decide(
        &rs,
        Some("com.x.app"),
        None,
        Some("x.example.com"),
        None,
        443,
        6,
    );
    assert_eq!(d, NeDecision::Log);
}

#[test]
fn test_decide_block_all_denies_unknown() {
    let rs = ruleset("mode = \"block\"\n", None);
    let d = decide(
        &rs,
        None,
        Some("/x"),
        Some("x.example.com"),
        Some("9.9.9.9"),
        443,
        6,
    );
    assert_eq!(d, NeDecision::Deny);
}

#[test]
fn test_decide_user_rule_denies_process() {
    let rs = ruleset(
        "",
        Some(
            "name = \"block\"\nprocess = \"/usr/bin/curl\"\ndest = \"tracker.example.com\"\naction = \"deny\"\n",
        ),
    );
    let denied = decide(
        &rs,
        None,
        Some("/usr/bin/curl"),
        Some("tracker.example.com"),
        None,
        443,
        6,
    );
    assert_eq!(denied, NeDecision::Deny);
}

#[test]
fn test_decide_parity_with_ruleset_decide_for() {
    // The FFI decision must equal `RuleSet::decide_for` for the equivalent
    // process + destination on a table of fixtures.
    let rs = ruleset(
        "mode = \"block\"\n\n[[allowlist]]\napp = \"/usr/bin/curl\"\nhost = \"allowed.example.com\"\n",
        None,
    );
    let fixtures: &[(Option<&str>, &str, &str)] = &[
        (Some("/usr/bin/curl"), "allowed.example.com", "1.1.1.1"),
        (Some("/usr/bin/curl"), "blocked.example.com", "2.2.2.2"),
        (Some("/Applications/Foo.app"), "foo.example.com", "3.3.3.3"),
    ];
    for &(path, host, ip) in fixtures {
        let via_ffi = decide(&rs, None, path, Some(host), Some(ip), 443, 6);
        let identity = build_identity(None, path);
        let dest = build_destination(Some(host), Some(ip), 443, 6);
        let via_core = NeDecision::from_action(rs.decide_for(&identity, &dest).action);
        assert_eq!(via_ffi, via_core, "parity mismatch for {path:?} -> {host}");
    }
}
