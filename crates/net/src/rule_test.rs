#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::connection::{AddressFamily, Destination, ProcessIdentity};
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
// HostPattern tests
// ---------------------------------------------------------------------------

#[test]
fn test_host_pattern_exact_match() {
    let pat = HostPattern::new("=apple.com").expect("valid pattern");
    assert!(pat.matches("apple.com"));
    assert!(!pat.matches("x.apple.com"));
    assert!(!pat.matches("evilapple.com"));
}

#[test]
fn test_host_pattern_subdomain_walking() {
    let pat = HostPattern::new("apple.com").expect("valid pattern");
    assert!(pat.matches("apple.com"));
    assert!(pat.matches("x.apple.com"));
    assert!(pat.matches("deep.sub.apple.com"));
    assert!(!pat.matches("evilapple.com"));
    assert!(!pat.matches("notapple.com"));
}

#[test]
fn test_host_pattern_glob() {
    let pat = HostPattern::new("*.analytics.*").expect("valid pattern");
    assert!(pat.matches("sdk.analytics.google.com"));
    assert!(pat.matches("api.analytics.example.org"));
    assert!(!pat.matches("analytics")); // No dots to match the wildcards.
}

#[test]
fn test_host_pattern_case_insensitive() {
    let pat = HostPattern::new("apple.com").expect("valid pattern");
    assert!(pat.matches("Apple.COM"));
    assert!(pat.matches("APPLE.COM"));
    assert!(pat.matches("apple.com"));

    let exact = HostPattern::new("=Apple.COM").expect("valid pattern");
    assert!(exact.matches("apple.com"));
    assert!(exact.matches("APPLE.COM"));
}

// ---------------------------------------------------------------------------
// DestMatcher tests
// ---------------------------------------------------------------------------

#[test]
fn test_dest_matcher_compound_and() {
    let dm = DestMatcher {
        host: Some(HostPattern::new("apple.com").expect("valid")),
        port: Some(PortMatcher::Single(443)),
        ..Default::default()
    };

    // Both host and port match.
    assert!(dm.matches(&make_dest(Some("apple.com"), Some(443))));
    // Host matches but port does not.
    assert!(!dm.matches(&make_dest(Some("apple.com"), Some(80))));
    // Port matches but host does not.
    assert!(!dm.matches(&make_dest(Some("evil.com"), Some(443))));
}

#[test]
fn test_dest_matcher_all_none_matches_any() {
    let dm = DestMatcher::default();
    assert!(dm.matches(&make_dest(Some("anything.com"), Some(12345))));
    assert!(dm.matches(&make_dest(None, None)));
}

// ---------------------------------------------------------------------------
// ProcessMatcher tests
// ---------------------------------------------------------------------------

#[test]
fn test_process_matcher_code_id_glob() {
    let pm = ProcessMatcher::code_id("com.apple.*").expect("valid");
    let safari = make_process("/Applications/Safari.app", Some("com.apple.Safari"));
    let chrome = make_process("/Applications/Chrome.app", Some("com.google.Chrome"));
    let unsigned = make_process("/tmp/tool", None);

    assert!(pm.matches(&safari));
    assert!(!pm.matches(&chrome));
    assert!(!pm.matches(&unsigned));
}

#[test]
fn test_process_matcher_path() {
    let pm = ProcessMatcher::path("/usr/bin/*").expect("valid");
    let curl = make_process("/usr/bin/curl", None);
    let app = make_process("/Applications/Foo.app", None);

    assert!(pm.matches(&curl));
    assert!(!pm.matches(&app));
}

#[test]
fn test_process_matcher_any() {
    let pm = ProcessMatcher::Any;
    assert!(pm.matches(&make_process("/anything", None)));
    assert!(pm.matches(&make_process("/other", Some("com.foo.bar"))));
}

// ---------------------------------------------------------------------------
// PortMatcher tests
// ---------------------------------------------------------------------------

#[test]
fn test_port_matcher_single() {
    let pm = PortMatcher::Single(443);
    assert!(pm.matches(443));
    assert!(!pm.matches(80));
}

#[test]
fn test_port_matcher_range() {
    let pm = PortMatcher::Range(1024, 65535);
    assert!(pm.matches(8080));
    assert!(pm.matches(1024));
    assert!(pm.matches(65535));
    assert!(!pm.matches(80));
    assert!(!pm.matches(443));
}

// ---------------------------------------------------------------------------
// Specificity tests
// ---------------------------------------------------------------------------

#[test]
fn test_process_specificity_ordering() {
    let any = ProcessMatcher::Any;
    let code = ProcessMatcher::code_id("com.apple.Safari").expect("valid");
    let path = ProcessMatcher::path("/usr/bin/curl").expect("valid");

    assert!(code.specificity() > any.specificity());
    assert_eq!(code.specificity(), path.specificity());
}

#[test]
fn test_dest_specificity_ordering() {
    let any = DestMatcher::default();
    let host_only = DestMatcher {
        host: Some(HostPattern::new("apple.com").expect("valid")),
        ..Default::default()
    };
    let host_and_port = DestMatcher {
        host: Some(HostPattern::new("apple.com").expect("valid")),
        port: Some(PortMatcher::Single(443)),
        ..Default::default()
    };

    assert!(host_and_port.specificity() > host_only.specificity());
    assert!(host_only.specificity() > any.specificity());
}

#[test]
fn test_exact_beats_glob_in_process() {
    let exact = ProcessMatcher::code_id("com.apple.Safari").expect("valid");
    let glob = ProcessMatcher::code_id("com.apple.*").expect("valid");

    assert!(exact.is_exact());
    assert!(!glob.is_exact());
}

// ---------------------------------------------------------------------------
// NetworkAction and Protocol display
// ---------------------------------------------------------------------------

#[test]
fn test_network_action_display() {
    assert_eq!(NetworkAction::Allow.to_string(), "allow");
    assert_eq!(NetworkAction::Deny.to_string(), "deny");
    assert_eq!(NetworkAction::Log.to_string(), "log");
}

#[test]
fn test_protocol_display() {
    use crate::rule::Protocol;
    assert_eq!(Protocol::Tcp.to_string(), "TCP");
    assert_eq!(Protocol::Udp.to_string(), "UDP");
}

#[test]
fn test_rule_id_display() {
    let id = RuleId(42);
    assert_eq!(id.to_string(), "rule#42");
    let id0 = RuleId(0);
    assert_eq!(id0.to_string(), "rule#0");
}

// ---------------------------------------------------------------------------
// DestMatcher::is_any
// ---------------------------------------------------------------------------

#[test]
fn test_dest_matcher_is_any_when_all_none() {
    let dm = DestMatcher::default();
    assert!(dm.is_any(), "all-None DestMatcher should be is_any");
}

#[test]
fn test_dest_matcher_is_not_any_with_host() {
    let dm = DestMatcher {
        host: Some(HostPattern::new("apple.com").expect("valid")),
        ..Default::default()
    };
    assert!(
        !dm.is_any(),
        "DestMatcher with host set should not be is_any"
    );
}

#[test]
fn test_dest_matcher_is_not_any_with_port() {
    let dm = DestMatcher {
        port: Some(PortMatcher::Single(443)),
        ..Default::default()
    };
    assert!(!dm.is_any());
}

// ---------------------------------------------------------------------------
// DestMatcher::matches with IP
// ---------------------------------------------------------------------------

#[test]
fn test_dest_matcher_ip_cidr_match() {
    use std::str::FromStr;
    let dm = DestMatcher {
        ip: Some("192.168.0.0/16".parse().expect("valid CIDR")),
        ..Default::default()
    };
    let in_range = Destination {
        host: None,
        ip: std::net::IpAddr::from_str("192.168.1.100").expect("valid IP"),
        port: None,
        protocol: None,
        address_family: crate::connection::AddressFamily::Inet,
    };
    let out_of_range = Destination {
        host: None,
        ip: std::net::IpAddr::from_str("10.0.0.1").expect("valid IP"),
        port: None,
        protocol: None,
        address_family: crate::connection::AddressFamily::Inet,
    };
    assert!(
        dm.matches(&in_range),
        "192.168.1.100 should be in 192.168.0.0/16"
    );
    assert!(
        !dm.matches(&out_of_range),
        "10.0.0.1 should not be in 192.168.0.0/16"
    );
}

// ---------------------------------------------------------------------------
// ProcessMatcher serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_process_matcher_serde_any() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct W {
        process: ProcessMatcher,
    }
    let w = W {
        process: ProcessMatcher::Any,
    };
    let s = toml::to_string(&w).expect("serialize");
    let back: W = toml::from_str(&s).expect("deserialize");
    assert_eq!(back.process.pattern(), "*");
}

#[test]
fn test_process_matcher_serde_code_id() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct W {
        process: ProcessMatcher,
    }
    let w = W {
        process: ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
    };
    let s = toml::to_string(&w).expect("serialize");
    let back: W = toml::from_str(&s).expect("deserialize");
    assert_eq!(back.process.pattern(), "com.apple.Safari");
}

#[test]
fn test_process_matcher_serde_path() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct W {
        process: ProcessMatcher,
    }
    let w = W {
        process: ProcessMatcher::path("/usr/bin/curl").expect("valid"),
    };
    let s = toml::to_string(&w).expect("serialize");
    let back: W = toml::from_str(&s).expect("deserialize");
    assert_eq!(back.process.pattern(), "/usr/bin/curl");
}

#[test]
fn test_process_matcher_serde_error_on_empty_map() {
    // A map with none of the expected keys should error.
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct W {
        process: ProcessMatcher,
    }
    let bad = r#"[process]
unknown_key = "value"
"#;
    let result: std::result::Result<W, _> = toml::from_str(bad);
    assert!(
        result.is_err(),
        "ProcessMatcher with no recognized key should fail to deserialize"
    );
}

// ---------------------------------------------------------------------------
// PortMatcher: boundary values
// ---------------------------------------------------------------------------

#[test]
fn test_port_matcher_range_boundaries_exact() {
    let pm = PortMatcher::Range(443, 443);
    assert!(pm.matches(443));
    assert!(!pm.matches(442));
    assert!(!pm.matches(444));
}

#[test]
fn test_port_matcher_full_range() {
    let pm = PortMatcher::Range(0, 65535);
    assert!(pm.matches(0));
    assert!(pm.matches(65535));
    assert!(pm.matches(8080));
}

#[test]
fn test_port_matcher_display() {
    assert_eq!(PortMatcher::Single(443).to_string(), "443");
    assert_eq!(PortMatcher::Range(1024, 65535).to_string(), "1024-65535");
}

// ---------------------------------------------------------------------------
// NetworkRule disabled
// ---------------------------------------------------------------------------

#[test]
fn test_disabled_rule_does_not_match() {
    let process = make_process("/usr/bin/curl", None);
    let dest = make_dest(Some("example.com"), None);
    let mut rule = NetworkRule {
        id: RuleId(1),
        name: "catch-all deny".to_owned(),
        process: ProcessMatcher::Any,
        destination: DestMatcher::default(),
        action: NetworkAction::Deny,
        duration: crate::rule::RuleDuration::Permanent,
        enabled: false,
        note: None,
    };
    assert!(
        !rule.matches(&process, &dest),
        "disabled rule must not match"
    );
    rule.enabled = true;
    assert!(rule.matches(&process, &dest), "enabled rule must match");
}

// ---------------------------------------------------------------------------
// ProcessMatcher::matches_connection — via process support
// ---------------------------------------------------------------------------

#[test]
fn test_matches_connection_via() {
    let pm = ProcessMatcher::code_id("com.apple.Safari").expect("valid");

    let direct = make_process(
        "/System/Library/Frameworks/WebKit.framework/XPCServices/com.apple.WebKit.Networking.xpc",
        Some("com.apple.WebKit.Networking"),
    );
    let via = make_process(
        "/Applications/Safari.app/Contents/MacOS/Safari",
        Some("com.apple.Safari"),
    );

    // Direct process does NOT match, but via process does.
    assert!(
        !pm.matches(&direct),
        "WebKit.Networking should not match Safari matcher directly"
    );
    assert!(
        pm.matches_connection(&direct, Some(&via)),
        "should match when via process is Safari"
    );
}

#[test]
fn test_matches_connection_no_via() {
    let pm = ProcessMatcher::code_id("com.apple.Safari").expect("valid");

    let safari = make_process("/Applications/Safari.app", Some("com.apple.Safari"));
    let chrome = make_process("/Applications/Chrome.app", Some("com.google.Chrome"));

    // Direct match, no via.
    assert!(
        pm.matches_connection(&safari, None),
        "Safari should match directly without via"
    );

    // No match, no via.
    assert!(
        !pm.matches_connection(&chrome, None),
        "Chrome should not match Safari matcher without via"
    );
}

// ---------------------------------------------------------------------------
// ProcessMatcher::TeamId tests
// ---------------------------------------------------------------------------

#[test]
fn test_team_id_matcher_matches() {
    let pm = ProcessMatcher::TeamId("EQHXZ8M8AV".to_owned());
    let process = ProcessIdentity {
        pid: 100,
        uid: 501,
        path: PathBuf::from("/Applications/Chrome.app"),
        code_id: Some("com.google.Chrome".to_owned()),
        team_id: Some("EQHXZ8M8AV".to_owned()),
        is_valid_signature: Some(true),
    };
    assert!(pm.matches(&process), "TeamId should match same team_id");
}

#[test]
fn test_team_id_matcher_no_match() {
    let pm = ProcessMatcher::TeamId("EQHXZ8M8AV".to_owned());
    let process = ProcessIdentity {
        pid: 100,
        uid: 501,
        path: PathBuf::from("/Applications/Other.app"),
        code_id: Some("com.other.App".to_owned()),
        team_id: Some("DIFFERENT01".to_owned()),
        is_valid_signature: Some(true),
    };
    assert!(
        !pm.matches(&process),
        "TeamId should not match different team_id"
    );
}

#[test]
fn test_team_id_matcher_missing_team_id() {
    let pm = ProcessMatcher::TeamId("EQHXZ8M8AV".to_owned());
    let process = make_process("/Applications/Unsigned.app", None);
    assert!(
        !pm.matches(&process),
        "TeamId should not match when process has no team_id"
    );
}

#[test]
fn test_team_id_specificity() {
    let team = ProcessMatcher::TeamId("EQHXZ8M8AV".to_owned());
    let code = ProcessMatcher::code_id("com.apple.Safari").expect("valid");
    let path = ProcessMatcher::path("/usr/bin/curl").expect("valid");
    let any = ProcessMatcher::Any;

    assert!(
        team.specificity() > code.specificity(),
        "TeamId specificity should be higher than CodeId"
    );
    assert!(
        team.specificity() > path.specificity(),
        "TeamId specificity should be higher than Path"
    );
    assert!(
        team.specificity() > any.specificity(),
        "TeamId specificity should be higher than Any"
    );
    assert_eq!(team.specificity(), 2);
}

#[test]
fn test_team_id_is_always_exact() {
    let pm = ProcessMatcher::TeamId("EQHXZ8M8AV".to_owned());
    assert!(pm.is_exact(), "TeamId should always be exact");
}

#[test]
fn test_team_id_pattern_returns_team_id() {
    let pm = ProcessMatcher::TeamId("EQHXZ8M8AV".to_owned());
    assert_eq!(pm.pattern(), "EQHXZ8M8AV");
}

#[test]
fn test_team_id_matches_connection_via() {
    let pm = ProcessMatcher::TeamId("EQHXZ8M8AV".to_owned());

    let direct = make_process("/usr/bin/helper", None);
    let via = ProcessIdentity {
        pid: 200,
        uid: 501,
        path: PathBuf::from("/Applications/Chrome.app"),
        code_id: Some("com.google.Chrome".to_owned()),
        team_id: Some("EQHXZ8M8AV".to_owned()),
        is_valid_signature: Some(true),
    };

    assert!(
        !pm.matches(&direct),
        "helper process should not match by team_id"
    );
    assert!(
        pm.matches_connection(&direct, Some(&via)),
        "should match via responsible process team_id"
    );
}

// ---------------------------------------------------------------------------
// ProcessMatcher::TeamId serde round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_team_id_serde_round_trip() {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct W {
        process: ProcessMatcher,
    }
    let w = W {
        process: ProcessMatcher::TeamId("EQHXZ8M8AV".to_owned()),
    };
    let s = toml::to_string(&w).expect("serialize");
    let back: W = toml::from_str(&s).expect("deserialize");
    assert_eq!(back.process.pattern(), "EQHXZ8M8AV");
}

#[test]
fn test_team_id_deser_from_toml() {
    #[derive(serde::Deserialize)]
    struct W {
        process: ProcessMatcher,
    }
    let toml_str = r#"
[process]
team_id = "MLZF7K7B5R"
"#;
    let w: W = toml::from_str(toml_str).expect("deserialize");
    assert_eq!(w.process.pattern(), "MLZF7K7B5R");
    assert!(w.process.is_exact());
}

#[test]
fn test_team_id_deser_empty_string_rejected() {
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct W {
        process: ProcessMatcher,
    }
    let toml_str = r#"
[process]
team_id = ""
"#;
    let result: std::result::Result<W, _> = toml::from_str(toml_str);
    assert!(
        result.is_err(),
        "empty team_id should be rejected during deserialization"
    );
}
