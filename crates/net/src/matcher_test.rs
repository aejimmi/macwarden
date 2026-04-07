use super::*;
use crate::connection::{AddressFamily, ConnectionEvent, Destination, ProcessIdentity};
use crate::rule::{
    DestMatcher, NetworkAction, NetworkRule, PortMatcher, ProcessMatcher, Protocol, RuleDuration,
    RuleId,
};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_process(path: &str, code_id: Option<&str>) -> ProcessIdentity {
    ProcessIdentity {
        pid: 100,
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
        ip: "93.184.216.34".parse::<IpAddr>().expect("valid IP"),
        port,
        protocol: Some(Protocol::Tcp),
        address_family: AddressFamily::Inet,
    }
}

fn make_event(process: ProcessIdentity, dest: Destination) -> ConnectionEvent {
    ConnectionEvent {
        timestamp: SystemTime::now(),
        process,
        via_process: None,
        destination: dest,
    }
}

fn make_rule(
    id: u64,
    name: &str,
    process: ProcessMatcher,
    dest: DestMatcher,
    action: NetworkAction,
) -> NetworkRule {
    NetworkRule {
        id: RuleId(id),
        name: name.to_owned(),
        process,
        destination: dest,
        action,
        duration: RuleDuration::Permanent,
        enabled: true,
        note: None,
    }
}

fn make_tracker(pattern: &str, category: &str, risk: BreakageRisk) -> TrackerRule {
    TrackerRule {
        pattern: HostPattern::new(pattern).expect("valid pattern"),
        category: category.to_owned(),
        breakage_risk: risk,
        description: format!("{category} tracker: {pattern}"),
    }
}

// ---------------------------------------------------------------------------
// Tier precedence tests
// ---------------------------------------------------------------------------

#[test]
fn test_user_rule_beats_group() {
    let mut rules = RuleSet::default();

    // User rule: allow Safari to analytics.com.
    rules.user_rules.push(make_rule(
        1,
        "Allow Safari analytics",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher {
            host: Some(HostPattern::new("analytics.com").expect("valid")),
            ..Default::default()
        },
        NetworkAction::Allow,
    ));

    // Group rule: deny all to analytics.com.
    rules.group_rules.push(GroupedRule {
        rule: make_rule(
            2,
            "Group deny analytics",
            ProcessMatcher::Any,
            DestMatcher {
                host: Some(HostPattern::new("analytics.com").expect("valid")),
                ..Default::default()
            },
            NetworkAction::Deny,
        ),
        group_name: "test-group".to_owned(),
        group_priority: 10,
    });

    rules.sort_user_rules();

    let event = make_event(
        make_process("/Applications/Safari.app", Some("com.apple.Safari")),
        make_dest(Some("analytics.com"), Some(443)),
    );

    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Allow);
    let matched = decision.matched_rule.expect("should have matched rule");
    assert_eq!(matched.tier, MatchTier::UserRule);
}

#[test]
fn test_user_rule_beats_tracker() {
    let mut rules = RuleSet::default();

    // User rule: allow Chrome to google-analytics.com.
    rules.user_rules.push(make_rule(
        1,
        "Allow Chrome GA",
        ProcessMatcher::code_id("com.google.Chrome").expect("valid"),
        DestMatcher {
            host: Some(HostPattern::new("google-analytics.com").expect("valid")),
            ..Default::default()
        },
        NetworkAction::Allow,
    ));

    // Tracker rule: deny google-analytics.com.
    rules.tracker_rules.push(make_tracker(
        "google-analytics.com",
        "analytics",
        BreakageRisk::None,
    ));

    rules.sort_user_rules();

    let event = make_event(
        make_process("/Applications/Chrome.app", Some("com.google.Chrome")),
        make_dest(Some("google-analytics.com"), Some(443)),
    );

    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Allow);
    let matched = decision.matched_rule.expect("should have matched rule");
    assert_eq!(matched.tier, MatchTier::UserRule);
}

#[test]
fn test_specificity_ordering() {
    let mut rules = RuleSet::default();

    // Global + any dest (least specific).
    rules.user_rules.push(make_rule(
        1,
        "Global any",
        ProcessMatcher::Any,
        DestMatcher::default(),
        NetworkAction::Log,
    ));

    // Global + host (more specific).
    rules.user_rules.push(make_rule(
        2,
        "Global host",
        ProcessMatcher::Any,
        DestMatcher {
            host: Some(HostPattern::new("apple.com").expect("valid")),
            ..Default::default()
        },
        NetworkAction::Deny,
    ));

    // Process + any dest.
    rules.user_rules.push(make_rule(
        3,
        "Process any",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher::default(),
        NetworkAction::Log,
    ));

    // Process + host (most specific).
    rules.user_rules.push(make_rule(
        4,
        "Process host",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher {
            host: Some(HostPattern::new("apple.com").expect("valid")),
            ..Default::default()
        },
        NetworkAction::Allow,
    ));

    rules.sort_user_rules();

    let event = make_event(
        make_process("/Applications/Safari.app", Some("com.apple.Safari")),
        make_dest(Some("apple.com"), Some(443)),
    );

    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Allow);
    let matched = decision.matched_rule.expect("should have matched rule");
    assert_eq!(matched.rule_name, "Process host");
}

#[test]
fn test_explicit_beats_glob() {
    let mut rules = RuleSet::default();

    // Glob pattern.
    rules.user_rules.push(make_rule(
        1,
        "Apple glob",
        ProcessMatcher::code_id("com.apple.*").expect("valid"),
        DestMatcher::default(),
        NetworkAction::Deny,
    ));

    // Exact pattern (same specificity tier, but exact beats glob).
    rules.user_rules.push(make_rule(
        2,
        "Safari exact",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher::default(),
        NetworkAction::Allow,
    ));

    rules.sort_user_rules();

    let event = make_event(
        make_process("/Applications/Safari.app", Some("com.apple.Safari")),
        make_dest(Some("example.com"), Some(443)),
    );

    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Allow);
    let matched = decision.matched_rule.expect("should have matched rule");
    assert_eq!(matched.rule_name, "Safari exact");
}

#[test]
fn test_tracker_critical_breakage_skipped() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Allow,
        ..Default::default()
    };

    // Critical tracker: should be skipped.
    rules.tracker_rules.push(make_tracker(
        "licensing.app.com",
        "analytics",
        BreakageRisk::Critical,
    ));

    let event = make_event(
        make_process("/Applications/App.app", Some("com.example.App")),
        make_dest(Some("licensing.app.com"), Some(443)),
    );

    let decision = rules.decide(&event);
    // Should fall through to default (Allow), not be denied by the tracker.
    assert_eq!(decision.action, NetworkAction::Allow);
    assert!(decision.matched_rule.is_none());
}

#[test]
fn test_tracker_non_critical_denied() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Allow,
        ..Default::default()
    };

    rules.tracker_rules.push(make_tracker(
        "google-analytics.com",
        "analytics",
        BreakageRisk::None,
    ));

    let event = make_event(
        make_process("/Applications/Chrome.app", Some("com.google.Chrome")),
        make_dest(Some("google-analytics.com"), Some(443)),
    );

    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Deny);
    let matched = decision.matched_rule.expect("should match tracker");
    assert_eq!(
        matched.tier,
        MatchTier::Tracker {
            category: "analytics".to_owned()
        }
    );
}

#[test]
fn test_blocklist_match() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Allow,
        ..Default::default()
    };

    rules.blocklist_domains.push(BlocklistEntry {
        domain: "ad.example.com".to_owned(),
        list_name: "test-list".to_owned(),
    });

    let event = make_event(
        make_process("/usr/bin/curl", None),
        make_dest(Some("ad.example.com"), Some(80)),
    );

    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Deny);
    let matched = decision.matched_rule.expect("should match blocklist");
    assert_eq!(
        matched.tier,
        MatchTier::Blocklist {
            list_name: "test-list".to_owned()
        }
    );
}

#[test]
fn test_blocklist_subdomain_match() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Allow,
        ..Default::default()
    };

    rules.blocklist_domains.push(BlocklistEntry {
        domain: "tracker.com".to_owned(),
        list_name: "peter-lowe".to_owned(),
    });

    // Subdomain should match.
    let event = make_event(
        make_process("/usr/bin/curl", None),
        make_dest(Some("api.tracker.com"), Some(443)),
    );
    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Deny);

    // But "eviltracker.com" should NOT match.
    let event2 = make_event(
        make_process("/usr/bin/curl", None),
        make_dest(Some("eviltracker.com"), Some(443)),
    );
    let decision2 = rules.decide(&event2);
    assert_eq!(decision2.action, NetworkAction::Allow);
}

#[test]
fn test_default_action_when_no_match() {
    let rules = RuleSet {
        default_action: NetworkAction::Deny,
        ..Default::default()
    };

    let event = make_event(
        make_process("/usr/bin/curl", None),
        make_dest(Some("unknown.example.com"), Some(443)),
    );

    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Deny);
    assert!(decision.matched_rule.is_none());
}

#[test]
fn test_explain_output_traces_tier() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Allow,
        ..Default::default()
    };

    rules.user_rules.push(make_rule(
        1,
        "Block Safari tracking",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher {
            host: Some(HostPattern::new("tracker.net").expect("valid")),
            ..Default::default()
        },
        NetworkAction::Deny,
    ));
    rules.sort_user_rules();

    let process = make_process("/Applications/Safari.app", Some("com.apple.Safari"));
    let dest = make_dest(Some("tracker.net"), Some(443));

    let explanation = rules.explain(&process, &dest);
    assert!(
        explanation.contains("user-rule"),
        "should contain tier name, got: {explanation}"
    );
    assert!(
        explanation.contains("Block Safari tracking"),
        "should contain rule name, got: {explanation}"
    );
}

#[test]
fn test_disabled_rules_skipped() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Allow,
        ..Default::default()
    };

    let mut rule = make_rule(
        1,
        "Disabled deny",
        ProcessMatcher::Any,
        DestMatcher::default(),
        NetworkAction::Deny,
    );
    rule.enabled = false;
    rules.user_rules.push(rule);
    rules.sort_user_rules();

    let event = make_event(
        make_process("/usr/bin/curl", None),
        make_dest(Some("example.com"), Some(443)),
    );

    let decision = rules.decide(&event);
    // Disabled rule should be skipped, falling through to default Allow.
    assert_eq!(decision.action, NetworkAction::Allow);
}

// ---------------------------------------------------------------------------
// Empty RuleSet
// ---------------------------------------------------------------------------

#[test]
fn test_empty_ruleset_returns_default_allow() {
    let rules = RuleSet {
        default_action: NetworkAction::Allow,
        ..Default::default()
    };
    let event = make_event(
        make_process("/usr/bin/curl", None),
        make_dest(Some("example.com"), Some(443)),
    );
    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Allow);
    assert!(
        decision.matched_rule.is_none(),
        "empty ruleset: no matched rule"
    );
}

#[test]
fn test_empty_ruleset_returns_default_deny() {
    let rules = RuleSet {
        default_action: NetworkAction::Deny,
        ..Default::default()
    };
    let event = make_event(
        make_process("/usr/bin/curl", None),
        make_dest(Some("unknown.example.com"), Some(80)),
    );
    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Deny);
    assert!(decision.matched_rule.is_none());
}

// ---------------------------------------------------------------------------
// Destination with no hostname (direct-IP) against a host rule
// ---------------------------------------------------------------------------

#[test]
fn test_host_rule_does_not_match_no_hostname_dest() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Allow,
        ..Default::default()
    };
    rules.user_rules.push(make_rule(
        1,
        "Deny apple.com",
        ProcessMatcher::Any,
        DestMatcher {
            host: Some(HostPattern::new("apple.com").expect("valid")),
            ..Default::default()
        },
        NetworkAction::Deny,
    ));
    rules.sort_user_rules();

    // Destination has no hostname — only an IP. The host rule should NOT fire.
    let dest = Destination {
        host: None,
        ip: "17.253.144.10".parse().expect("valid"),
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        address_family: crate::connection::AddressFamily::Inet,
    };
    let event = ConnectionEvent {
        timestamp: std::time::SystemTime::now(),
        process: make_process("/usr/bin/curl", None),
        via_process: None,
        destination: dest,
    };
    let decision = rules.decide(&event);
    assert_eq!(
        decision.action,
        NetworkAction::Allow,
        "host rule should not match a no-hostname destination"
    );
}

// ---------------------------------------------------------------------------
// Tracker rule does not match a no-hostname destination
// ---------------------------------------------------------------------------

#[test]
fn test_tracker_rule_no_hostname_dest_falls_to_default() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Allow,
        ..Default::default()
    };
    rules.tracker_rules.push(make_tracker(
        "google-analytics.com",
        "analytics",
        BreakageRisk::None,
    ));

    let dest = Destination {
        host: None,
        ip: "216.58.217.142".parse().expect("valid"),
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        address_family: crate::connection::AddressFamily::Inet,
    };
    let event = ConnectionEvent {
        timestamp: std::time::SystemTime::now(),
        process: make_process("/usr/bin/curl", None),
        via_process: None,
        destination: dest,
    };
    let decision = rules.decide(&event);
    assert_eq!(
        decision.action,
        NetworkAction::Allow,
        "tracker rule requires hostname; no-hostname dest should fall through"
    );
}

// ---------------------------------------------------------------------------
// Safelist tier — explain output
// ---------------------------------------------------------------------------

#[test]
fn test_safelist_explain_output_mentions_essential() {
    let rules = RuleSet {
        default_action: NetworkAction::Deny,
        ..Default::default()
    };
    let process = make_process("/usr/bin/curl", None);
    let dest = make_dest(Some("ocsp.apple.com"), Some(443));
    let explanation = rules.explain(&process, &dest);
    assert!(
        explanation.contains("safe-list") || explanation.contains("essential"),
        "safelist explain output should mention safe-list or essential, got: {explanation}"
    );
}

#[test]
fn test_safelist_always_allows_even_with_deny_rule() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Deny,
        ..Default::default()
    };
    // User deny rule targeting the OCSP domain.
    rules.user_rules.push(make_rule(
        1,
        "Deny ocsp",
        ProcessMatcher::Any,
        DestMatcher {
            host: Some(HostPattern::new("ocsp.apple.com").expect("valid")),
            ..Default::default()
        },
        NetworkAction::Deny,
    ));
    rules.sort_user_rules();

    let event = make_event(
        make_process("/usr/bin/curl", None),
        make_dest(Some("ocsp.apple.com"), Some(443)),
    );
    let decision = rules.decide(&event);
    // Safelist (Tier 0) runs before user rules (Tier 1).
    assert_eq!(
        decision.action,
        NetworkAction::Allow,
        "safelist must override even an explicit deny user rule"
    );
    let matched = decision.matched_rule.expect("should have matched rule");
    assert_eq!(matched.tier, crate::connection::MatchTier::SafeList);
}

// ---------------------------------------------------------------------------
// IPv6 destination
// ---------------------------------------------------------------------------

#[test]
fn test_ipv6_dest_matches_any_dest_rule() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Deny,
        ..Default::default()
    };
    rules.user_rules.push(make_rule(
        1,
        "Allow Safari all",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher::default(),
        NetworkAction::Allow,
    ));
    rules.sort_user_rules();

    let dest = Destination {
        host: Some("apple.com".to_owned()),
        ip: "2001:db8::1".parse().expect("valid IPv6"),
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        address_family: crate::connection::AddressFamily::Inet6,
    };
    let event = ConnectionEvent {
        timestamp: std::time::SystemTime::now(),
        process: make_process("/Applications/Safari.app", Some("com.apple.Safari")),
        via_process: None,
        destination: dest,
    };
    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Allow);
}

// ---------------------------------------------------------------------------
// Group beats tracker
// ---------------------------------------------------------------------------

#[test]
fn test_group_rule_beats_tracker() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Allow,
        ..Default::default()
    };

    // Group rule: allow sentry.io (override tracker block).
    rules.group_rules.push(GroupedRule {
        rule: make_rule(
            100,
            "Allow sentry group",
            ProcessMatcher::Any,
            DestMatcher {
                host: Some(HostPattern::new("sentry.io").expect("valid")),
                ..Default::default()
            },
            NetworkAction::Allow,
        ),
        group_name: "dev-tools".to_owned(),
        group_priority: 10,
    });

    // Tracker rule: deny sentry.io.
    rules.tracker_rules.push(make_tracker(
        "sentry.io",
        "analytics",
        BreakageRisk::Degraded,
    ));

    let event = make_event(
        make_process("/Applications/VSCode.app", Some("com.microsoft.VSCode")),
        make_dest(Some("sentry.io"), Some(443)),
    );
    let decision = rules.decide(&event);
    assert_eq!(
        decision.action,
        NetworkAction::Allow,
        "group rule should beat tracker rule"
    );
    let matched = decision.matched_rule.expect("should have matched rule");
    assert_eq!(
        matched.tier,
        crate::connection::MatchTier::RuleGroup {
            group_name: "dev-tools".to_owned()
        }
    );
}

// ---------------------------------------------------------------------------
// Blocklist beats tracker (both in lower tiers — blocklist matches first
// only when it's a direct-domain entry, since tracker uses HostPattern)
// ---------------------------------------------------------------------------

#[test]
fn test_default_action_log_produces_log_decision() {
    let rules = RuleSet {
        default_action: NetworkAction::Log,
        ..Default::default()
    };
    let event = make_event(
        make_process("/usr/bin/curl", None),
        make_dest(Some("nowhere.example.com"), Some(443)),
    );
    let decision = rules.decide(&event);
    assert_eq!(decision.action, NetworkAction::Log);
    assert!(decision.matched_rule.is_none());
    assert!(
        decision.explanation.contains("profile-default") || decision.explanation.contains("LOGGED"),
        "explanation should mention profile-default or LOGGED, got: {}",
        decision.explanation
    );
}

#[test]
fn test_session_and_permanent_duration() {
    let mut rules = RuleSet::default();

    // Permanent rule.
    rules.user_rules.push(make_rule(
        1,
        "Permanent allow",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher {
            host: Some(HostPattern::new("apple.com").expect("valid")),
            ..Default::default()
        },
        NetworkAction::Allow,
    ));

    // Session rule (higher specificity via port).
    let mut session_rule = make_rule(
        2,
        "Session deny",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher {
            host: Some(HostPattern::new("apple.com").expect("valid")),
            port: Some(PortMatcher::Single(8080)),
            ..Default::default()
        },
        NetworkAction::Deny,
    );
    session_rule.duration = RuleDuration::Session;
    rules.user_rules.push(session_rule);

    rules.sort_user_rules();

    // Port 8080 should match the session deny rule.
    let event_8080 = make_event(
        make_process("/Applications/Safari.app", Some("com.apple.Safari")),
        make_dest(Some("apple.com"), Some(8080)),
    );
    let decision = rules.decide(&event_8080);
    assert_eq!(decision.action, NetworkAction::Deny);

    // Port 443 should match the permanent allow rule.
    let event_443 = make_event(
        make_process("/Applications/Safari.app", Some("com.apple.Safari")),
        make_dest(Some("apple.com"), Some(443)),
    );
    let decision2 = rules.decide(&event_443);
    assert_eq!(decision2.action, NetworkAction::Allow);
}

// ---------------------------------------------------------------------------
// Via-process matching
// ---------------------------------------------------------------------------

#[test]
fn test_via_process_match() {
    let mut rules = RuleSet::default();

    // Rule targets Safari by code_id.
    rules.user_rules.push(make_rule(
        1,
        "Allow Safari",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher::default(),
        NetworkAction::Allow,
    ));
    rules.sort_user_rules();

    // Connection from WebKit.Networking with via=Safari.
    let event = ConnectionEvent {
        timestamp: SystemTime::now(),
        process: make_process(
            "/System/Library/Frameworks/WebKit.framework/Versions/A/XPCServices/com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking",
            Some("com.apple.WebKit.Networking"),
        ),
        via_process: Some(make_process(
            "/Applications/Safari.app/Contents/MacOS/Safari",
            Some("com.apple.Safari"),
        )),
        destination: make_dest(Some("example.com"), Some(443)),
    };

    let decision = rules.decide(&event);
    assert_eq!(
        decision.action,
        NetworkAction::Allow,
        "rule for Safari should match via responsible process"
    );
}

#[test]
fn test_via_process_direct_still_works() {
    let mut rules = RuleSet::default();

    rules.user_rules.push(make_rule(
        1,
        "Allow Safari",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher::default(),
        NetworkAction::Allow,
    ));
    rules.sort_user_rules();

    // Connection directly from Safari (no via).
    let event = make_event(
        make_process("/Applications/Safari.app", Some("com.apple.Safari")),
        make_dest(Some("example.com"), Some(443)),
    );

    let decision = rules.decide(&event);
    assert_eq!(
        decision.action,
        NetworkAction::Allow,
        "rule for Safari should still match the direct process"
    );
}

#[test]
fn test_via_process_neither_matches() {
    let mut rules = RuleSet {
        default_action: NetworkAction::Deny,
        ..Default::default()
    };

    rules.user_rules.push(make_rule(
        1,
        "Allow Safari",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher::default(),
        NetworkAction::Allow,
    ));
    rules.sort_user_rules();

    // Connection from Chrome with no via.
    let event = make_event(
        make_process("/Applications/Chrome.app", Some("com.google.Chrome")),
        make_dest(Some("example.com"), Some(443)),
    );

    let decision = rules.decide(&event);
    assert_eq!(
        decision.action,
        NetworkAction::Deny,
        "Safari rule should not match Chrome (no via)"
    );
}

#[test]
fn test_via_process_explain_shows_via() {
    let mut rules = RuleSet::default();

    rules.user_rules.push(make_rule(
        1,
        "Allow Safari",
        ProcessMatcher::code_id("com.apple.Safari").expect("valid"),
        DestMatcher::default(),
        NetworkAction::Allow,
    ));
    rules.sort_user_rules();

    let process = make_process(
        "/System/Library/Frameworks/WebKit.framework/XPCServices/com.apple.WebKit.Networking.xpc",
        Some("com.apple.WebKit.Networking"),
    );
    let via = make_process(
        "/Applications/Safari.app/Contents/MacOS/Safari",
        Some("com.apple.Safari"),
    );
    let dest = make_dest(Some("example.com"), Some(443));

    let decision = rules.decide_for_via(&process, Some(&via), &dest);
    assert!(
        decision
            .explanation
            .contains("Matched via responsible process"),
        "explain should mention via process, got: {}",
        decision.explanation,
    );
    assert!(
        decision.explanation.contains("com.apple.Safari"),
        "explain should mention Safari, got: {}",
        decision.explanation,
    );
    assert!(
        decision.explanation.contains("com.apple.WebKit.Networking"),
        "explain should mention the direct process, got: {}",
        decision.explanation,
    );
}
