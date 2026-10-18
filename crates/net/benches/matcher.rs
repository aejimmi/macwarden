//! Hot-path benchmarks for the five-tier rule matcher.
//!
//! The matcher runs on EVERY connection/flow — in the daemon snapshot build and
//! (once live) per-flow in the NetworkExtension core where sub-ms matters. This
//! bench builds a realistic rule set (builtin tracker DB + network groups +
//! hundreds of synthetic user rules) and measures `RuleSet::decide_for` across
//! representative flow shapes.
//!
//! The dominant real-world case is `miss_full_scan`: a destination that matches
//! no rule, forcing a full traversal of every user rule, every group rule, and
//! every tracker rule before falling through to the default action.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use std::hint::black_box;

use appdb::AppDb;
use criterion::{Criterion, criterion_group, criterion_main};
use net::group::NetworkGroups;
use net::host::HostPattern;
use net::profile::{NetworkProfile, TrackerSettings};
use net::rule::{DestMatcher, NetworkAction, NetworkRule, ProcessMatcher, RuleDuration, RuleId};
use net::tracker::TrackerDatabase;
use net::{AddressFamily, BlocklistEntry, Destination, ProcessIdentity, Protocol, RuleSet};

/// Build a realistic rule set: all builtin trackers denied (~215 rules), all
/// builtin network groups, plus `user_rule_count` synthetic user rules and a
/// small blocklist. Default action is `Deny` (Block-All) so misses traverse the
/// full engine.
fn realistic_ruleset(user_rule_count: usize) -> RuleSet {
    let tracker_db = TrackerDatabase::load_builtin().expect("builtin tracker db");
    let groups = NetworkGroups::load_builtin().expect("builtin groups");
    let category_db = AppDb::load_builtin().expect("builtin app db");

    let profile = NetworkProfile {
        default: NetworkAction::Deny,
        // Deny every category so all ~215 tracker rules are live in the set.
        trackers: TrackerSettings {
            advertising: NetworkAction::Deny,
            analytics: NetworkAction::Deny,
            fingerprinting: NetworkAction::Deny,
            social: NetworkAction::Deny,
            breakage_detection: true,
        },
        groups: net::GroupSettings::default(),
        blocklists: net::BlocklistSettings::default(),
        rules: Vec::new(),
    };

    let mut ruleset = profile
        .resolve(&groups, &tracker_db, &category_db, &[])
        .expect("resolve ruleset");

    ruleset
        .user_rules
        .extend(synthetic_user_rules(user_rule_count));
    ruleset.blocklist_domains.extend(synthetic_blocklist());
    ruleset.sort_user_rules();
    ruleset.rebuild_blocklist_trie();
    ruleset
}

/// Fabricate `n` code-id + host scoped Allow rules. These deliberately never
/// match the benchmark flows, so a miss walks the entire list (worst case).
fn synthetic_user_rules(n: usize) -> Vec<NetworkRule> {
    (0..n)
        .map(|i| NetworkRule {
            id: RuleId(10_000 + i as u64),
            name: format!("synthetic-{i}"),
            process: ProcessMatcher::code_id(&format!("com.example.app{i}"))
                .expect("valid code id"),
            destination: DestMatcher {
                host: Some(HostPattern::new(&format!("api{i}.example{i}.com")).expect("host")),
                ..Default::default()
            },
            action: NetworkAction::Allow,
            duration: RuleDuration::Permanent,
            enabled: true,
            note: None,
        })
        .collect()
}

/// A handful of blocklist domains so the Tier-4 trie is non-empty.
fn synthetic_blocklist() -> Vec<BlocklistEntry> {
    [
        "ads.badnet.example",
        "malware.evil.example",
        "spam.junk.example",
    ]
    .iter()
    .map(|d| BlocklistEntry {
        domain: (*d).to_owned(),
        list_name: "bench-list".to_owned(),
    })
    .collect()
}

/// A process identity that no synthetic user rule targets.
fn bench_process() -> ProcessIdentity {
    ProcessIdentity {
        pid: 4321,
        uid: 501,
        path: PathBuf::from("/Applications/Bench.app/Contents/MacOS/Bench"),
        code_id: Some("com.bench.client".to_owned()),
        team_id: Some("ABCDE12345".to_owned()),
        is_valid_signature: Some(true),
        is_apple_signed: Some(false),
    }
}

/// Build a destination with a hostname.
fn host_dest(host: &str) -> Destination {
    Destination {
        host: Some(host.to_owned()),
        ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        address_family: AddressFamily::Inet,
    }
}

/// Build a destination with no hostname (IP-literal flow).
fn ip_dest() -> Destination {
    Destination {
        host: None,
        ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        address_family: AddressFamily::Inet,
    }
}

fn bench_decide(c: &mut Criterion) {
    let ruleset = realistic_ruleset(200);
    let process = bench_process();

    // A destination that matches nothing: full user + group + tracker scan.
    let miss = host_dest("unmatched-host.nonexistent-benchmark.example");
    // A real tracker domain (analytics) — Tier-3 hit after full user+group scan.
    let tracker = host_dest("google-analytics.com");
    // A safelist domain — Tier-0 short-circuit.
    let safe = host_dest("ocsp.apple.com");
    // A blocklist domain — Tier-4 trie hit after user+group+tracker scan.
    let blocked = host_dest("ads.badnet.example");
    // No hostname — host-based tiers skip quickly, IP path only.
    let ip_only = ip_dest();

    let mut group = c.benchmark_group("decide");

    group.bench_function("miss_full_scan", |b| {
        b.iter(|| ruleset.decide_for(black_box(&process), black_box(&miss)));
    });
    group.bench_function("tracker_hit", |b| {
        b.iter(|| ruleset.decide_for(black_box(&process), black_box(&tracker)));
    });
    group.bench_function("safelist_hit", |b| {
        b.iter(|| ruleset.decide_for(black_box(&process), black_box(&safe)));
    });
    group.bench_function("blocklist_hit", |b| {
        b.iter(|| ruleset.decide_for(black_box(&process), black_box(&blocked)));
    });
    group.bench_function("ip_only_no_host", |b| {
        b.iter(|| ruleset.decide_for(black_box(&process), black_box(&ip_only)));
    });

    group.finish();
}

/// Build an Allow-All rule set with the tracker shield OFF (the default live
/// posture): default action `Log`, no tracker rules, builtin groups only. This
/// is the cheap end of the snapshot's per-connection decide cost.
fn allow_all_ruleset(user_rule_count: usize) -> RuleSet {
    let tracker_db = TrackerDatabase::load_builtin().expect("builtin tracker db");
    let groups = NetworkGroups::load_builtin().expect("builtin groups");
    let category_db = AppDb::load_builtin().expect("builtin app db");

    // Default TrackerSettings = Log for every category -> resolve_trackers emits
    // no Deny tracker rules, matching a shield-disabled live set.
    let profile = NetworkProfile {
        default: NetworkAction::Log,
        trackers: TrackerSettings::default(),
        groups: net::GroupSettings::default(),
        blocklists: net::BlocklistSettings::default(),
        rules: Vec::new(),
    };
    let mut ruleset = profile
        .resolve(&groups, &tracker_db, &category_db, &[])
        .expect("resolve ruleset");
    ruleset
        .user_rules
        .extend(synthetic_user_rules(user_rule_count));
    ruleset.sort_user_rules();
    ruleset
}

/// A realistic mix of ~120 live connections: mostly first-party misses, a
/// scattering of trackers, plus IP-literal flows — modeling one panel sampler
/// tick. Each entry is the `(process, destination)` pair the snapshot builder
/// feeds to `decide_with_policy` per connection.
fn snapshot_connections() -> Vec<(ProcessIdentity, Destination)> {
    let process = bench_process();
    let mut conns = Vec::with_capacity(120);
    for i in 0..90 {
        conns.push((
            process.clone(),
            host_dest(&format!("edge{i}.first-party-cdn.example")),
        ));
    }
    for host in [
        "google-analytics.com",
        "doubleclick.net",
        "mixpanel.com",
        "amplitude.com",
    ] {
        for _ in 0..5 {
            conns.push((process.clone(), host_dest(host)));
        }
    }
    for _ in 0..10 {
        conns.push((process.clone(), ip_dest()));
    }
    conns
}

fn bench_snapshot_decide(c: &mut Criterion) {
    let conns = snapshot_connections();
    let block_all = realistic_ruleset(200);
    let allow_all = allow_all_ruleset(200);

    let mut group = c.benchmark_group("snapshot_decide");
    group.throughput(criterion::Throughput::Elements(conns.len() as u64));

    // Block-All + shield ON: the expensive posture (full tracker scan per miss).
    group.bench_function("block_all_shield_120_conns", |b| {
        b.iter(|| {
            for (proc, dest) in &conns {
                black_box(block_all.decide_for(black_box(proc), black_box(dest)));
            }
        });
    });
    // Allow-All + shield OFF: the default live posture.
    group.bench_function("allow_all_120_conns", |b| {
        b.iter(|| {
            for (proc, dest) in &conns {
                black_box(allow_all.decide_for(black_box(proc), black_box(dest)));
            }
        });
    });

    group.finish();
}

fn bench_host_pattern(c: &mut Criterion) {
    let pat = HostPattern::new("google-analytics.com").expect("pattern");
    let mut group = c.benchmark_group("host_pattern");

    // Already-lowercase host (the overwhelming common case from DNS).
    group.bench_function("match_lower_hit", |b| {
        b.iter(|| pat.matches(black_box("sub.google-analytics.com")));
    });
    group.bench_function("match_lower_miss", |b| {
        b.iter(|| pat.matches(black_box("unmatched.example.com")));
    });
    // Host with uppercase — must fold case.
    group.bench_function("match_mixed_case_hit", |b| {
        b.iter(|| pat.matches(black_box("Sub.Google-Analytics.COM")));
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_decide,
    bench_snapshot_decide,
    bench_host_pattern
);
criterion_main!(benches);
