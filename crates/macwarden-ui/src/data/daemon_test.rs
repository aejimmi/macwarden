#![allow(clippy::indexing_slicing, clippy::panic)]

use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use ipc::codec::{CodecError, read_message, write_message};
use ipc::protocol::{
    Capability, ErrorKind, PROTOCOL_VERSION, Request, Response, RuleTarget, WireAllowEntry,
    WireAppRow, WireDetail, WireDomainRow, WireFlow, WireGroupState, WireMode, WireProfile,
    WireSignature, WireTotals, WireVerdict,
};

use super::*;
use crate::data::model::{AppRow, Signature, Verdict};
use crate::data::source::PanelSource;
use crate::state::Route;

/// A canned snapshot: one app with one tracker destination and two blocked
/// trackers in the footer.
fn canned_snapshot() -> Response {
    Response::Snapshot {
        apps: vec![WireAppRow {
            id: "com.example.app".to_string(),
            name: "Example".to_string(),
            bundle_path: Some("/Applications/Example.app".to_string()),
            allowed: true,
            known_bad: false,
            down_bytes: 100,
            up_bytes: 50,
            flow: WireFlow::Active(2048),
            is_system: false,
            domains: vec![WireDomainRow {
                host: "tracker.example".to_string(),
                country: Some("US".to_string()),
                verdict: WireVerdict::Tracker,
                rate_bps: 512,
                total_bytes: 4096,
                sockets: 1,
                allowed: false,
            }],
        }],
        net_rows: Vec::new(),
        procs: Vec::new(),
        proc_groups: Vec::new(),
        totals: WireTotals {
            down_bytes: 100,
            up_bytes: 50,
            trackers_blocked: 2,
            connections: 3,
            down_bps: 512,
            up_bps: 64,
        },
        generation: 1,
        sample_age_ms: Some(5),
    }
}

fn canned_detail() -> WireDetail {
    WireDetail {
        name: "Example".to_string(),
        bundle_id: "com.example.app".to_string(),
        bundle_path: Some("/Applications/Example.app".to_string()),
        in_bytes: 10,
        out_bytes: 20,
        path: "/Applications/Example.app/Contents/MacOS/Example".to_string(),
        user: "kingkong".to_string(),
        signature: WireSignature::Apple,
        openbinary: "known good".to_string(),
        hostnames: vec!["tracker.example".to_string()],
        ips: vec!["1.2.3.4".to_string()],
        ports: vec!["443/tcp".to_string()],
        allowed_count: 4,
        denied_count: 1,
        allowed: true,
    }
}

/// A canned default profile: Allow-All, one enabled group, empty allow-list.
fn canned_profile() -> WireProfile {
    WireProfile {
        mode: WireMode::AllowAll,
        allow_apple_programs: false,
        allow_dns_traffic: true,
        groups: vec![WireGroupState {
            name: "gaming".to_string(),
            description: "Game platforms".to_string(),
            enabled: false,
            default_enabled: false,
            domain_count: 34,
        }],
        allowlist: Vec::new(),
    }
}

/// A stub daemon speaking the real protocol over a socketpair: handshake,
/// snapshot, detail, rule-ack, and the stateful policy mutations. It keeps a
/// live `profile` so mutations echo the updated state, exactly like the real
/// daemon's `ProfileAck`. A short read timeout lets it notice the `stop` flag
/// while otherwise blocked reading the next request.
fn spawn_stub(
    server: UnixStream,
    capabilities: Vec<Capability>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let _ = server.set_read_timeout(Some(Duration::from_millis(100)));
        let mut writer = server.try_clone().expect("clone server stream");
        let mut reader = BufReader::new(server);
        let mut profile = canned_profile();
        let mut generation = 1u64;
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let request: Request = match read_message(&mut reader) {
                Ok(request) => request,
                Err(CodecError::Io(e))
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    continue;
                }
                Err(_) => break,
            };
            let response = match request {
                Request::Hello { .. } => Response::Welcome {
                    protocol_version: PROTOCOL_VERSION,
                    daemon_version: "test-daemon".to_string(),
                    capabilities: capabilities.clone(),
                },
                Request::GetSnapshot => canned_snapshot(),
                Request::GetAppDetail { .. }
                | Request::GetProcDetail { .. }
                | Request::GetDomainDetail { .. } => Response::Detail {
                    detail: Some(canned_detail()),
                },
                Request::SetRule { .. } => Response::RuleAck {
                    applied: true,
                    generation: 7,
                    verdict: WireVerdict::Blocked,
                },
                Request::GetProfile => Response::Profile {
                    profile: profile.clone(),
                },
                other => handle_policy(other, &mut profile, &mut generation),
            };
            if write_message(&mut writer, &response).is_err() {
                break;
            }
        }
    })
}

/// Apply a policy mutation to the stub's live profile and return the echoing
/// `ProfileAck` (or a `BadRequest` for an obviously-invalid allow entry, so the
/// panel's rejection path is exercised). Non-policy requests yield `Unsupported`.
fn handle_policy(request: Request, profile: &mut WireProfile, generation: &mut u64) -> Response {
    match request {
        Request::SetMode { mode } => profile.mode = mode,
        Request::SetAppleAllow { allow } => profile.allow_apple_programs = allow,
        Request::SetDnsAllow { allow } => profile.allow_dns_traffic = allow,
        Request::SetGroupEnabled { group, enabled } => {
            if let Some(state) = profile.groups.iter_mut().find(|g| g.name == group) {
                state.enabled = enabled;
            }
        }
        Request::AddAllowListEntry { entry } => {
            if entry.host.as_deref().is_some_and(|h| h.contains(' ')) {
                return Response::Error {
                    kind: ErrorKind::BadRequest,
                    message: "invalid host".to_string(),
                };
            }
            profile.allowlist.push(entry);
        }
        Request::RemoveAllowListEntry { entry } => profile.allowlist.retain(|e| e != &entry),
        _ => {
            return Response::Error {
                kind: ErrorKind::Unsupported,
                message: String::new(),
            };
        }
    }
    *generation += 1;
    Response::ProfileAck {
        generation: *generation,
        profile: profile.clone(),
    }
}

/// A host-only allow entry, the common panel case.
fn host_entry(host: &str) -> WireAllowEntry {
    WireAllowEntry {
        app: None,
        team_id: None,
        host: Some(host.to_string()),
        ip: None,
        note: None,
    }
}

/// Build a `DaemonSource` wired to a stub daemon over a socketpair: run the
/// handshake by hand (mirroring what `ipc::client::connect` does before handing
/// the panel a post-handshake stream), then hand the stream to `from_parts`.
fn connect_source(capabilities: Vec<Capability>) -> (DaemonSource, Arc<AtomicBool>) {
    let (client, server) = UnixStream::pair().expect("socketpair");
    let stop = Arc::new(AtomicBool::new(false));
    spawn_stub(server, capabilities, Arc::clone(&stop));

    let mut hs_writer = client.try_clone().expect("clone client stream");
    write_message(
        &mut hs_writer,
        &Request::Hello {
            protocol_version: PROTOCOL_VERSION,
            client_version: "test".to_string(),
        },
    )
    .expect("write hello");
    let mut hs_reader = BufReader::new(client.try_clone().expect("clone client read half"));
    let welcome: Response = read_message(&mut hs_reader).expect("read welcome");
    let caps = match welcome {
        Response::Welcome { capabilities, .. } => capabilities,
        other => panic!("expected Welcome, got {other:?}"),
    };

    let source = DaemonSource::from_parts(
        client,
        caps,
        "test-daemon".to_string(),
        Box::new(|| None),
        Box::new(|| None),
    )
    .expect("build daemon source");
    (source, stop)
}

/// Poll until the worker has published a snapshot (or a short deadline lapses).
fn wait_for_apps(source: &DaemonSource) -> Vec<AppRow> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let apps = source.apps();
        if !apps.is_empty() || Instant::now() >= deadline {
            return apps;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn test_daemon_source_handshakes_and_maps_snapshot() {
    let (source, _stop) = connect_source(vec![Capability::Mutations]);
    assert_eq!(source.name(), "daemon");
    assert!(source.is_live());
    assert_eq!(source.daemon_version(), "test-daemon");

    let apps = wait_for_apps(&source);
    assert_eq!(apps.len(), 1);
    assert_eq!(apps[0].id, "com.example.app");
    assert_eq!(apps[0].flow, crate::data::model::Flow::Active(2048));
    assert_eq!(apps[0].domains.len(), 1);
    assert_eq!(apps[0].domains[0].verdict, Verdict::Tracker);

    let totals = source.totals();
    assert_eq!(totals.trackers_blocked, 2);
    assert_eq!(totals.connections, 3);
    assert_eq!(source.generation(), 1);
}

#[test]
fn test_content_version_bumps_once_then_stays_stable() {
    let (source, _stop) = connect_source(vec![Capability::Mutations]);
    wait_for_apps(&source);
    // The first real snapshot differs from the empty default, so the worker
    // republishes and bumps the version at least once.
    let v = source
        .content_version()
        .expect("a live source reports a content version");
    assert!(v >= 1, "first real snapshot bumps the version, got {v}");
    // The stub replays a byte-for-byte identical snapshot every poll. The worker
    // must not republish or bump the version for those, so the panel can skip
    // an idle per-second layout+paint. Wait across several poll intervals.
    thread::sleep(SNAPSHOT_INTERVAL * 3 + Duration::from_millis(200));
    assert_eq!(
        source.content_version(),
        Some(v),
        "identical snapshots must not bump the content version"
    );
}

#[test]
fn test_app_detail_round_trips_through_daemon() {
    let (source, _stop) = connect_source(vec![Capability::Mutations]);
    wait_for_apps(&source);
    let detail = source
        .app_detail("com.example.app")
        .expect("detail present");
    assert_eq!(detail.name, "Example");
    assert_eq!(detail.signature, Signature::Apple);
    assert_eq!(detail.openbinary, "known good");
    assert_eq!(detail.allowed_count, 4);
}

#[test]
fn test_set_rule_sends_mutation_and_reports_applied() {
    let (source, _stop) = connect_source(vec![Capability::Mutations]);
    wait_for_apps(&source);
    let applied = source.set_rule(
        &RuleTarget::App {
            code_id: "com.example.app".to_string(),
        },
        false,
    );
    assert!(applied);
}

#[test]
fn test_set_rule_without_capability_is_local_only() {
    let (source, _stop) = connect_source(Vec::new());
    wait_for_apps(&source);
    let applied = source.set_rule(
        &RuleTarget::Domain {
            host: "tracker.example".to_string(),
        },
        false,
    );
    assert!(!applied);
}

#[test]
fn test_detail_backend_resolves_route_off_thread() {
    let (source, _stop) = connect_source(vec![Capability::Mutations]);
    wait_for_apps(&source);
    let backend = source
        .detail_backend()
        .expect("daemon exposes a detail backend");
    // Resolve a route the way the panel does from its background executor: move
    // the Send handle onto another thread and query there.
    let handle = thread::spawn(move || {
        let detail = backend
            .detail(&Route::App("com.example.app".to_string()))
            .expect("detail present");
        assert_eq!(detail.name, "Example");
        assert_eq!(detail.allowed_count, 4);
        backend.set_rule(
            &RuleTarget::App {
                code_id: "com.example.app".to_string(),
            },
            false,
        )
    });
    assert!(handle.join().expect("backend thread"));
}

#[test]
fn test_detail_backend_set_rule_denied_without_capability() {
    let (source, _stop) = connect_source(Vec::new());
    wait_for_apps(&source);
    let backend = source.detail_backend().expect("backend present");
    // No Mutations capability — the handle reports the rule was not applied so
    // the panel can revert its optimistic toggle.
    let applied = backend.set_rule(
        &RuleTarget::App {
            code_id: "com.example.app".to_string(),
        },
        false,
    );
    assert!(!applied);
}

#[test]
fn test_enforcement_active_true_with_network_enforcement_capability() {
    // Spec 009 R4: the panel's honesty affordance keys off exactly this signal.
    // When the daemon's handshake advertises NetworkEnforcement, the source
    // must report enforcement as active — but only while it is live.
    let (source, _stop) =
        connect_source(vec![Capability::Mutations, Capability::NetworkEnforcement]);
    wait_for_apps(&source);
    assert_eq!(source.runtime_status(), RuntimeStatus::Live);
    assert!(source.is_live());
    assert!(source.enforcement_active());
}

#[test]
fn test_enforcement_active_false_without_network_enforcement_capability() {
    // The capability-absent state: a live daemon that has every other
    // capability but not NetworkEnforcement must still read as not-enforcing,
    // so the panel keeps its "preview only" hint rather than defaulting open.
    let (source, _stop) = connect_source(vec![
        Capability::Mutations,
        Capability::Policy,
        Capability::Trace,
        Capability::History,
        Capability::Openbinary,
    ]);
    wait_for_apps(&source);
    assert!(!source.enforcement_active());
}

#[test]
fn test_enforcement_active_false_with_no_capabilities_at_all() {
    // The degenerate empty-capabilities handshake (e.g. a minimally-built
    // daemon) must not be mistaken for enforcement either.
    let (source, _stop) = connect_source(Vec::new());
    wait_for_apps(&source);
    assert!(!source.enforcement_active());
}

#[test]
fn test_policy_backend_absent_without_capability() {
    let (source, _stop) = connect_source(vec![Capability::Mutations]);
    wait_for_apps(&source);
    // No `Policy` capability advertised — the panel gets no policy backend, so
    // its mode / allow-list controls render disabled.
    assert!(source.policy_backend().is_none());
}

#[test]
fn test_get_profile_round_trips_through_daemon() {
    let (source, _stop) = connect_source(vec![Capability::Policy]);
    wait_for_apps(&source);
    let backend = source.policy_backend().expect("policy backend present");
    let profile = backend.get_profile().expect("profile present");
    assert_eq!(profile.mode, WireMode::AllowAll);
    assert!(profile.allow_dns_traffic);
    assert_eq!(profile.groups.len(), 1);
    assert!(profile.allowlist.is_empty());
}

#[test]
fn test_set_mode_echoes_block_all() {
    let (source, _stop) = connect_source(vec![Capability::Policy]);
    wait_for_apps(&source);
    let backend = source.policy_backend().expect("policy backend present");
    let echoed = backend.set_mode(WireMode::BlockAll).expect("ack profile");
    assert_eq!(echoed.mode, WireMode::BlockAll);
    // A follow-up read reflects the persisted mode (stateful stub).
    assert_eq!(
        backend.get_profile().map(|p| p.mode),
        Some(WireMode::BlockAll)
    );
}

#[test]
fn test_set_flags_and_group_toggle() {
    let (source, _stop) = connect_source(vec![Capability::Policy]);
    wait_for_apps(&source);
    let backend = source.policy_backend().expect("policy backend present");
    assert!(
        backend
            .set_apple_allow(true)
            .expect("apple ack")
            .allow_apple_programs
    );
    assert!(
        !backend
            .set_dns_allow(false)
            .expect("dns ack")
            .allow_dns_traffic
    );
    let echoed = backend
        .set_group_enabled("gaming".to_string(), true)
        .expect("group ack");
    assert!(
        echoed
            .groups
            .iter()
            .any(|g| g.name == "gaming" && g.enabled)
    );
}

#[test]
fn test_add_and_remove_allow_entry() {
    let (source, _stop) = connect_source(vec![Capability::Policy]);
    wait_for_apps(&source);
    let backend = source.policy_backend().expect("policy backend present");
    let entry = host_entry("*.googleapis.com");
    let after_add = backend.add_allow_entry(entry.clone()).expect("add ack");
    assert_eq!(after_add.allowlist, vec![entry.clone()]);
    let after_remove = backend.remove_allow_entry(entry).expect("remove ack");
    assert!(after_remove.allowlist.is_empty());
}

#[test]
fn test_add_invalid_entry_returns_none() {
    let (source, _stop) = connect_source(vec![Capability::Policy]);
    wait_for_apps(&source);
    let backend = source.policy_backend().expect("policy backend present");
    // A host with a space is rejected daemon-side (`BadRequest`); the backend
    // surfaces `None` so the panel reconciles by re-fetching, adding nothing.
    assert!(backend.add_allow_entry(host_entry("bad host")).is_none());
    assert!(backend.get_profile().expect("profile").allowlist.is_empty());
}

#[test]
fn test_policy_backend_off_thread() {
    let (source, _stop) = connect_source(vec![Capability::Policy]);
    wait_for_apps(&source);
    let backend = source.policy_backend().expect("policy backend present");
    // The panel moves the Send handle onto its background executor; mirror that
    // by driving a mutation from another thread.
    let handle = thread::spawn(move || backend.set_mode(WireMode::BlockAll).map(|p| p.mode));
    assert_eq!(handle.join().expect("thread"), Some(WireMode::BlockAll));
}

#[test]
fn test_disconnect_leaves_status_stale() {
    let (source, stop) = connect_source(vec![Capability::Mutations]);
    wait_for_apps(&source);
    assert_eq!(source.runtime_status(), RuntimeStatus::Live);

    // Close the stub; the reconnect closure yields `None`, so the source should
    // fall out of `Live` and serve its last cached snapshot while it retries.
    stop.store(true, Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(3);
    while source.runtime_status() == RuntimeStatus::Live && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert_ne!(source.runtime_status(), RuntimeStatus::Live);
    // The cached snapshot is still served during the grace window.
    assert_eq!(source.apps().len(), 1);
    // R8 honesty: a stale source must stop reading as live so the header drops
    // its "live" claim and shows the reconnecting affordance.
    assert!(!source.is_live());
}

#[test]
fn test_enforcement_active_degrades_when_daemon_dies() {
    // The core Defect B fix: a daemon that advertised NetworkEnforcement must
    // stop reporting enforcement once its connection is lost. Otherwise the
    // panel keeps painting live block affordances off a dead daemon's last
    // capabilities.
    let (source, stop) = connect_source(vec![Capability::NetworkEnforcement]);
    wait_for_apps(&source);
    assert!(source.enforcement_active());

    stop.store(true, Ordering::Relaxed);
    let deadline = Instant::now() + Duration::from_secs(3);
    while source.runtime_status() == RuntimeStatus::Live && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert_ne!(source.runtime_status(), RuntimeStatus::Live);
    assert!(
        !source.enforcement_active(),
        "a stale daemon must not keep reporting enforcement from its last caps"
    );
}

#[test]
fn test_to_rule_changes_maps_pairs_at_session_duration() {
    let changes = vec![
        (
            RuleTarget::App {
                code_id: "com.a".into(),
            },
            false,
        ),
        (
            RuleTarget::App {
                code_id: "com.b".into(),
            },
            true,
        ),
    ];
    let wire = to_rule_changes(&changes);
    assert_eq!(wire.len(), 2);
    assert_eq!(wire[0].duration, WireDuration::Session);
    assert!(!wire[0].allow);
    assert!(wire[1].allow);
    assert_eq!(
        wire[1].target,
        RuleTarget::App {
            code_id: "com.b".into()
        }
    );
}

#[test]
fn test_sample_is_stale_thresholds() {
    // A daemon too old to report the age forgoes the signal (treated fresh).
    assert!(!sample_is_stale(None));
    // A fresh sample is not stale; at/under the threshold stays live.
    assert!(!sample_is_stale(Some(0)));
    assert!(!sample_is_stale(Some(STALE_SAMPLE_MS)));
    // Past the threshold the view is stale even if the socket is healthy.
    assert!(sample_is_stale(Some(STALE_SAMPLE_MS + 1)));
    assert!(sample_is_stale(Some(60_000)));
}
