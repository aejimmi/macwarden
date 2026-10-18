//! Tests for the decide-time Apple-programs floor (R4).

use super::*;
use net::{
    AddressFamily, DestMatcher, HostPattern, NetworkAction, NetworkRule, ProcessMatcher,
    RuleDuration, RuleSet,
};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

fn block_all_ruleset() -> RuleSet {
    RuleSet {
        default_action: NetworkAction::Deny,
        ..RuleSet::default()
    }
}

fn apple_process(path: &str, code_id: &str, apple_signed: bool) -> ProcessIdentity {
    ProcessIdentity {
        pid: 1,
        uid: 501,
        path: PathBuf::from(path),
        code_id: Some(code_id.to_owned()),
        team_id: None,
        is_valid_signature: Some(true),
        is_apple_signed: Some(apple_signed),
    }
}

fn dest(host: &str) -> Destination {
    Destination {
        host: Some(host.to_owned()),
        ip: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        port: None,
        protocol: None,
        address_family: AddressFamily::Inet,
    }
}

#[test]
fn test_apple_signed_non_graylisted_allowed_under_block_all() {
    let rs = block_all_ruleset();
    let p = apple_process(
        "/Applications/Safari.app/Contents/MacOS/Safari",
        "com.apple.Safari",
        true,
    );
    let d = decide_with_policy(&rs, &p, None, &dest("some.host"), true);
    assert_eq!(d.action, NetworkAction::Allow);
}

#[test]
fn test_graylisted_apple_binary_still_denied() {
    let rs = block_all_ruleset();
    let curl = apple_process("/usr/bin/curl", "com.apple.curl", true);
    let d = decide_with_policy(&rs, &curl, None, &dest("some.host"), true);
    assert_eq!(d.action, NetworkAction::Deny);
}

#[test]
fn test_flag_off_no_carveout() {
    let rs = block_all_ruleset();
    let p = apple_process(
        "/Applications/Safari.app/Contents/MacOS/Safari",
        "com.apple.Safari",
        true,
    );
    let d = decide_with_policy(&rs, &p, None, &dest("some.host"), false);
    assert_eq!(d.action, NetworkAction::Deny);
}

#[test]
fn test_not_apple_signed_no_carveout() {
    let rs = block_all_ruleset();
    let p = apple_process("/Applications/Foo.app", "com.foo.Bar", false);
    let d = decide_with_policy(&rs, &p, None, &dest("some.host"), true);
    assert_eq!(d.action, NetworkAction::Deny);
}

#[test]
fn test_explicit_user_deny_beats_carveout() {
    let mut rs = block_all_ruleset();
    rs.user_rules.push(NetworkRule {
        id: net::RuleId(5),
        name: "block safari to evil".to_owned(),
        process: ProcessMatcher::code_id("com.apple.Safari").expect("code id"),
        destination: DestMatcher {
            host: Some(HostPattern::new("evil.com").expect("host")),
            ..Default::default()
        },
        action: NetworkAction::Deny,
        duration: RuleDuration::Permanent,
        enabled: true,
        note: None,
    });
    rs.sort_user_rules();
    let p = apple_process(
        "/Applications/Safari.app/Contents/MacOS/Safari",
        "com.apple.Safari",
        true,
    );
    let d = decide_with_policy(&rs, &p, None, &dest("evil.com"), true);
    assert_eq!(d.action, NetworkAction::Deny, "explicit user Deny must win");
}

#[test]
fn test_safelist_allow_unaffected() {
    let rs = block_all_ruleset();
    // A non-Apple process to an essential domain is allowed via Tier 0; the
    // shim must not disturb that (it is already Allow, not the default Deny).
    let p = apple_process("/bin/app", "com.x.y", false);
    let d = decide_with_policy(&rs, &p, None, &dest("ocsp.apple.com"), true);
    assert_eq!(d.action, NetworkAction::Allow);
}
