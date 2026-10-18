#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::field_reassign_with_default
)]

use std::sync::Arc;

use ipc::protocol::{
    Capability, ErrorKind, ExecTarget, HistoryScope, Request, Response, RuleTarget, WireDuration,
    WireRuleChange, WireVerdict,
};

use super::super::error::Result;
use super::super::snapshot::{ConnectionScanner, LiveConn};
use super::super::state::ServerState;
use super::*;

fn conn(code_id: &str, host: &str) -> LiveConn {
    LiveConn {
        code_id: Some(code_id.to_owned()),
        process: "proc".to_owned(),
        pid: 1,
        path: Some("/Applications/App.app".to_owned()),
        host: Some(host.to_owned()),
        ip: "1.2.3.4".parse().ok(),
        port: 443,
        protocol: "TCP".to_owned(),
        bytes_in: 10,
        bytes_out: 5,
        is_apple_signed: None,
        cpu: 0.0,
        mem_bytes: 0,
        ..LiveConn::default()
    }
}

/// Build a warmed state: the connection sample is seeded into the cache the way
/// the background sampler would, so handlers read it without scanning.
fn state(caps: Vec<Capability>, conns: Vec<LiveConn>) -> (tempfile::TempDir, Arc<ServerState>) {
    state_seeded(caps, conns, true)
}

fn state_seeded(
    caps: Vec<Capability>,
    conns: Vec<LiveConn>,
    warmed: bool,
) -> (tempfile::TempDir, Arc<ServerState>) {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("net-rules");
    // A scanner that panics if called: proves handlers read the cache, not scan().
    let scanner: Arc<dyn ConnectionScanner> = Arc::new(PanicScanner);
    let st = ServerState::new("test".to_owned(), caps, rules_dir, scanner, None, None).unwrap();
    if warmed {
        st.store_conns(conns);
    }
    (dir, Arc::new(st))
}

/// A scanner that must never be called on the request path.
struct PanicScanner;

impl ConnectionScanner for PanicScanner {
    fn scan(&self) -> Result<Vec<LiveConn>> {
        panic!("request handlers must not scan inline — read the cached sample");
    }
}

#[test]
fn test_get_snapshot_empty_before_first_sample() {
    // With no sample stored yet, the snapshot handler answers empty promptly
    // (the cache is empty) rather than scanning.
    let (_dir, st) = state_seeded(
        vec![Capability::Mutations],
        vec![conn("com.example.app", "example.test")],
        false,
    );
    match handle_request(&st, &Request::GetSnapshot) {
        Response::Snapshot {
            apps, generation, ..
        } => {
            assert!(apps.is_empty(), "pre-sample snapshot must be empty");
            assert_eq!(generation, 0);
        }
        other => panic!("expected Snapshot, got {other:?}"),
    }
}

#[test]
fn test_get_snapshot_reads_cached_sample_without_scanning() {
    // The seeded cache (via a PanicScanner) proves the snapshot is served from
    // the cache; a scan would panic the test.
    let (_dir, st) = state(
        vec![Capability::Mutations],
        vec![conn("com.example.app", "example.test")],
    );
    match handle_request(&st, &Request::GetSnapshot) {
        Response::Snapshot { apps, .. } => assert_eq!(apps.len(), 1),
        other => panic!("expected Snapshot, got {other:?}"),
    }
}

#[test]
fn test_app_detail_reads_cached_sample_without_scanning() {
    // Detail is derived from the cached sample (PanicScanner would panic on a
    // scan), and resolves the requested app.
    let (_dir, st) = state(
        vec![Capability::Mutations],
        vec![conn("com.example.app", "example.test")],
    );
    match handle_request(
        &st,
        &Request::GetAppDetail {
            id: "com.example.app".to_owned(),
        },
    ) {
        Response::Detail { detail } => {
            let detail = detail.expect("detail for a known app");
            assert_eq!(detail.bundle_id, "com.example.app");
        }
        other => panic!("expected Detail, got {other:?}"),
    }
}

#[test]
fn test_get_snapshot_returns_apps() {
    let (_dir, st) = state(
        vec![Capability::Mutations],
        vec![conn("com.example.app", "example.test")],
    );
    match handle_request(&st, &Request::GetSnapshot) {
        Response::Snapshot {
            apps, generation, ..
        } => {
            assert_eq!(apps.len(), 1);
            assert_eq!(generation, 0);
        }
        other => panic!("expected Snapshot, got {other:?}"),
    }
}

#[test]
fn test_set_rule_blocks_writes_file_and_bumps_generation() {
    let (dir, st) = state(
        vec![Capability::Mutations],
        vec![conn("com.example.app", "example.test")],
    );
    let request = Request::SetRule {
        target: RuleTarget::App {
            code_id: "com.example.app".to_owned(),
        },
        allow: false,
        duration: WireDuration::Permanent,
    };
    match handle_request(&st, &request) {
        Response::RuleAck {
            applied,
            generation,
            verdict,
        } => {
            assert!(applied);
            assert_eq!(generation, 1);
            assert_eq!(verdict, WireVerdict::Blocked);
        }
        other => panic!("expected RuleAck, got {other:?}"),
    }

    let rule_file = dir
        .path()
        .join("net-rules")
        .join("block-com-example-app.toml");
    assert!(rule_file.exists(), "the deny rule file must be written");

    // The next snapshot reflects the just-applied block against the live ruleset.
    match handle_request(&st, &Request::GetSnapshot) {
        Response::Snapshot {
            apps, generation, ..
        } => {
            assert_eq!(generation, 1);
            assert_eq!(apps[0].domains[0].verdict, WireVerdict::Blocked);
        }
        other => panic!("expected Snapshot, got {other:?}"),
    }
}

fn block(code_id: &str) -> WireRuleChange {
    WireRuleChange {
        target: RuleTarget::App {
            code_id: code_id.to_owned(),
        },
        allow: false,
        duration: WireDuration::Session,
    }
}

#[test]
fn test_set_rules_applies_batch_and_bumps_generation_once() {
    // A batch of two blocks applies as ONE mutation: a single reload bumps the
    // generation exactly once (to 1), not once per entry.
    let (_dir, st) = state(
        vec![Capability::Mutations],
        vec![conn("com.example.app", "example.test")],
    );
    let request = Request::SetRules {
        rules: vec![block("com.example.app"), block("com.other.app")],
    };
    match handle_request(&st, &request) {
        Response::RulesAck {
            applied,
            generation,
        } => {
            assert!(applied);
            assert_eq!(generation, 1, "one reload for the whole batch");
        }
        other => panic!("expected RulesAck, got {other:?}"),
    }
    // The snapshot reflects the applied block, still at generation 1.
    match handle_request(&st, &Request::GetSnapshot) {
        Response::Snapshot {
            apps, generation, ..
        } => {
            assert_eq!(generation, 1);
            assert_eq!(apps[0].domains[0].verdict, WireVerdict::Blocked);
        }
        other => panic!("expected Snapshot, got {other:?}"),
    }
}

#[test]
fn test_set_rules_mixed_targets_apply() {
    // A batch mixing an App and an AppDomain target validates and applies.
    let (_dir, st) = state(
        vec![Capability::Mutations],
        vec![conn("com.example.app", "example.test")],
    );
    let request = Request::SetRules {
        rules: vec![
            block("com.example.app"),
            WireRuleChange {
                target: RuleTarget::AppDomain {
                    code_id: "com.other.app".to_owned(),
                    host: "tracker.example".to_owned(),
                },
                allow: false,
                duration: WireDuration::Session,
            },
        ],
    };
    match handle_request(&st, &request) {
        Response::RulesAck { applied, .. } => assert!(applied),
        other => panic!("expected RulesAck, got {other:?}"),
    }
}

#[test]
fn test_set_rules_empty_batch_is_bad_request() {
    let (_dir, st) = state(vec![Capability::Mutations], vec![]);
    match handle_request(&st, &Request::SetRules { rules: vec![] }) {
        Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[test]
fn test_set_rules_over_cap_is_bad_request() {
    let (_dir, st) = state(vec![Capability::Mutations], vec![]);
    let rules = (0..200).map(|i| block(&format!("com.app{i}"))).collect();
    match handle_request(&st, &Request::SetRules { rules }) {
        Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::BadRequest),
        other => panic!("expected BadRequest, got {other:?}"),
    }
}

#[test]
fn test_set_rules_requires_mutations_capability() {
    let (_dir, st) = state(vec![], vec![]);
    match handle_request(
        &st,
        &Request::SetRules {
            rules: vec![block("com.example.app")],
        },
    ) {
        Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::Unsupported),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn test_set_rule_session_changes_verdict_without_file() {
    let (dir, st) = state(
        vec![Capability::Mutations],
        vec![conn("com.example.app", "example.test")],
    );
    let request = Request::SetRule {
        target: RuleTarget::App {
            code_id: "com.example.app".to_owned(),
        },
        allow: false,
        duration: WireDuration::Session,
    };
    let response = handle_request(&st, &request);
    assert!(matches!(
        response,
        Response::RuleAck {
            verdict: WireVerdict::Blocked,
            ..
        }
    ));
    // Session rules write no file.
    let rule_file = dir
        .path()
        .join("net-rules")
        .join("block-com-example-app.toml");
    assert!(
        !rule_file.exists(),
        "session rules must not persist to disk"
    );
}

#[test]
fn test_set_rule_without_capability_is_unsupported() {
    let (_dir, st) = state(vec![], vec![]);
    let request = Request::SetRule {
        target: RuleTarget::Domain {
            host: "example.test".to_owned(),
        },
        allow: false,
        duration: WireDuration::Permanent,
    };
    assert!(matches!(
        handle_request(&st, &request),
        Response::Error {
            kind: ErrorKind::Unsupported,
            ..
        }
    ));
}

#[test]
fn test_set_exec_policy_is_unsupported() {
    let (_dir, st) = state(vec![Capability::Mutations], vec![]);
    let request = Request::SetExecPolicy {
        target: ExecTarget::CodeId("com.example.app".to_owned()),
        deny: true,
    };
    assert!(matches!(
        handle_request(&st, &request),
        Response::Error {
            kind: ErrorKind::Unsupported,
            ..
        }
    ));
}

#[test]
fn test_history_without_metrics_is_unsupported() {
    let (_dir, st) = state(vec![Capability::Mutations], vec![]);
    let request = Request::GetHistory {
        scope: HistoryScope::Today,
        app_id: None,
    };
    assert!(matches!(
        handle_request(&st, &request),
        Response::Error {
            kind: ErrorKind::Unsupported,
            ..
        }
    ));
}

#[test]
fn test_domain_detail_unknown_returns_none() {
    let (_dir, st) = state(
        vec![Capability::Mutations],
        vec![conn("com.example.app", "example.test")],
    );
    let request = Request::GetDomainDetail {
        host: "unknown.test".to_owned(),
    };
    match handle_request(&st, &request) {
        Response::Detail { detail } => assert!(detail.is_none()),
        other => panic!("expected Detail, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// R7 policy capability gating + routing
// ---------------------------------------------------------------------------

#[test]
fn test_get_profile_without_policy_cap_is_unsupported() {
    let (_dir, st) = state(vec![Capability::Mutations], vec![]);
    match handle_request(&st, &Request::GetProfile) {
        Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::Unsupported),
        other => panic!("expected Unsupported error, got {other:?}"),
    }
}

#[test]
fn test_set_mode_without_policy_cap_is_unsupported() {
    let (_dir, st) = state(vec![Capability::Mutations], vec![]);
    let req = Request::SetMode {
        mode: ipc::protocol::WireMode::BlockAll,
    };
    match handle_request(&st, &req) {
        Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::Unsupported),
        other => panic!("expected Unsupported error, got {other:?}"),
    }
}

#[test]
fn test_get_profile_with_policy_cap_returns_profile() {
    let (_dir, st) = state(vec![Capability::Policy], vec![]);
    match handle_request(&st, &Request::GetProfile) {
        Response::Profile { profile } => {
            assert!(
                !profile.groups.is_empty(),
                "built-in groups must be listed in the profile"
            );
        }
        other => panic!("expected Profile, got {other:?}"),
    }
}

#[test]
fn test_add_allow_entry_invalid_host_without_policy_cap_is_unsupported() {
    // The capability gate must reject before any validation/disk write.
    let (_dir, st) = state(vec![Capability::Mutations], vec![]);
    let req = Request::AddAllowListEntry {
        entry: ipc::protocol::WireAllowEntry {
            app: None,
            team_id: None,
            host: Some("bad host".to_owned()),
            ip: None,
            note: None,
        },
    };
    match handle_request(&st, &req) {
        Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::Unsupported),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// banwatch handlers (spec 010 R8)
// ---------------------------------------------------------------------------

/// Build a state with the banwatch service enabled over the temp base dir.
fn state_with_banwatch() -> (tempfile::TempDir, Arc<ServerState>) {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("net-rules");
    let scanner: Arc<dyn ConnectionScanner> = Arc::new(PanicScanner);
    let service = super::super::banwatch_svc::BanwatchService::open(dir.path(), None)
        .unwrap()
        .expect("banwatch enabled by default");
    let st = ServerState::new(
        "test".to_owned(),
        vec![Capability::Mutations, Capability::BanWatch],
        rules_dir,
        scanner,
        None,
        None,
    )
    .unwrap()
    .with_banwatch(Some(Arc::new(service)));
    (dir, Arc::new(st))
}

#[test]
fn test_get_bans_without_capability_is_unsupported() {
    let (_dir, st) = state(vec![Capability::Mutations], vec![]);
    match handle_request(&st, &Request::GetBans) {
        Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::Unsupported),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn test_set_ban_without_capability_is_unsupported() {
    let (_dir, st) = state(vec![Capability::Mutations], vec![]);
    let req = Request::SetBan {
        ip: "203.0.113.7".to_owned(),
        ban: true,
        ban_secs: None,
        detector: None,
    };
    match handle_request(&st, &req) {
        Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::Unsupported),
        other => panic!("expected Unsupported, got {other:?}"),
    }
}

#[test]
fn test_get_bans_empty_then_set_ban_then_listed() {
    let (_dir, st) = state_with_banwatch();

    // Initially no bans.
    match handle_request(&st, &Request::GetBans) {
        Response::Bans { bans } => assert!(bans.is_empty()),
        other => panic!("expected Bans, got {other:?}"),
    }

    // Manually ban an IP; the ack applies and bumps the generation.
    let ban_req = Request::SetBan {
        ip: "203.0.113.7".to_owned(),
        ban: true,
        ban_secs: Some(3600),
        detector: None,
    };
    let gen_after_ban = match handle_request(&st, &ban_req) {
        Response::BanAck {
            applied,
            generation,
        } => {
            assert!(applied);
            generation
        }
        other => panic!("expected BanAck, got {other:?}"),
    };
    assert!(gen_after_ban > 0, "reload bumps the generation");

    // The ban now lists.
    match handle_request(&st, &Request::GetBans) {
        Response::Bans { bans } => {
            assert_eq!(bans.len(), 1);
            assert_eq!(bans[0].ip, "203.0.113.7");
            assert_eq!(bans[0].source, "manual");
        }
        other => panic!("expected Bans, got {other:?}"),
    }

    // And the live rule set now denies a flow to that IP (enforcement path).
    let ruleset = st.ruleset();
    use net::{AddressFamily, Destination, NetworkAction, ProcessIdentity};
    let process = ProcessIdentity {
        pid: 0,
        uid: 0,
        path: "/x".into(),
        code_id: None,
        team_id: None,
        is_valid_signature: None,
        is_apple_signed: None,
    };
    let dest = Destination {
        host: None,
        ip: "203.0.113.7".parse().unwrap(),
        port: Some(443),
        protocol: None,
        address_family: AddressFamily::Inet,
    };
    assert_eq!(
        ruleset.decide_for(&process, &dest).action,
        NetworkAction::Deny,
        "a manually-banned IP is denied through the live rule set",
    );

    // Unban and confirm the list empties.
    let unban_req = Request::SetBan {
        ip: "203.0.113.7".to_owned(),
        ban: false,
        ban_secs: None,
        detector: None,
    };
    match handle_request(&st, &unban_req) {
        Response::BanAck { applied, .. } => assert!(applied),
        other => panic!("expected BanAck, got {other:?}"),
    }
    match handle_request(&st, &Request::GetBans) {
        Response::Bans { bans } => assert!(bans.is_empty()),
        other => panic!("expected Bans, got {other:?}"),
    }
}

#[test]
fn test_set_ban_invalid_ip_is_refused() {
    let (_dir, st) = state_with_banwatch();
    let req = Request::SetBan {
        ip: "not-an-ip".to_owned(),
        ban: true,
        ban_secs: None,
        detector: None,
    };
    match handle_request(&st, &req) {
        Response::Error { kind, .. } => assert_eq!(kind, ErrorKind::Refused),
        other => panic!("expected Refused, got {other:?}"),
    }
}

#[test]
fn test_sample_age_is_none_before_first_sample() {
    // No sample stored: age is None so the panel can tell "cold start" from
    // "wedged sampler".
    let (_dir, st) = state_seeded(vec![Capability::Mutations], Vec::new(), false);
    assert_eq!(st.sample_age_ms(), None);
}

#[test]
fn test_sample_age_is_populated_after_a_sample() {
    // Once the sampler stores a sample, an age is available (a small,
    // monotonic-in-real-time value).
    let (_dir, st) = state_seeded(vec![Capability::Mutations], Vec::new(), false);
    st.store_conns(vec![conn("com.example.app", "example.test")]);
    let age = st.sample_age_ms().expect("age present after a sample");
    assert!(
        age < 60_000,
        "a just-stored sample must be fresh, got {age}ms"
    );
}

#[test]
fn test_snapshot_generation_never_exceeds_ruleset_generation_under_reload() {
    // #2 ordering invariant: `handle_snapshot` reads the generation before the
    // ruleset, so a reload landing mid-build can only make the ruleset newer
    // than the stamp — the stamped generation is never ahead of live state.
    // Hammer reload() on one thread while snapshotting on another and assert the
    // stamped generation is always <= the generation observed right after.
    let (_dir, st) = state(
        vec![Capability::Mutations],
        vec![conn("com.example.app", "example.test")],
    );
    let reloader = {
        let st = Arc::clone(&st);
        std::thread::spawn(move || {
            for _ in 0..500 {
                let _ = st.reload();
            }
        })
    };
    for _ in 0..2000 {
        let stamped = match handle_request(&st, &Request::GetSnapshot) {
            Response::Snapshot { generation, .. } => generation,
            other => panic!("expected Snapshot, got {other:?}"),
        };
        let after = st.generation();
        assert!(
            stamped <= after,
            "stamped generation {stamped} must never exceed live generation {after}"
        );
    }
    reloader.join().unwrap();
}
