use super::*;

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use crate::connection::{AddressFamily, Destination, ProcessIdentity};
use crate::rule::Protocol;

fn proc(path: &str) -> ProcessIdentity {
    ProcessIdentity {
        pid: 100,
        uid: 501,
        path: path.into(),
        code_id: None,
        team_id: None,
        is_valid_signature: None,
        is_apple_signed: None,
    }
}

fn dest(host: &str) -> Destination {
    Destination {
        host: Some(host.to_owned()),
        ip: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        address_family: AddressFamily::Inet,
    }
}

fn write(dir: &Path, name: &str, content: &str) {
    std::fs::write(dir.join(name), content).expect("write fixture");
}

fn write_rule(base: &Path, name: &str, content: &str) {
    let rules = base.join(NET_RULES_DIRNAME);
    std::fs::create_dir_all(&rules).expect("create net-rules");
    std::fs::write(rules.join(name), content).expect("write rule");
}

#[test]
fn test_empty_dir_builds_allow_all_default() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let rs = build_base_ruleset(dir.path(), &[]).expect("build base");
    // Allow-All default: an unmatched connection is logged, not denied.
    let d = rs.decide_for(
        &proc("/Applications/Unknown.app"),
        &dest("unknown.example.com"),
    );
    assert_eq!(d.action, NetworkAction::Log);
}

#[test]
fn test_block_mode_denies_unknown() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    write(dir.path(), NET_PROFILE_FILENAME, "mode = \"block\"\n");
    let rs = build_base_ruleset(dir.path(), &[]).expect("build base");
    let d = rs.decide_for(
        &proc("/Applications/Unknown.app"),
        &dest("unknown.example.com"),
    );
    assert_eq!(d.action, NetworkAction::Deny);
}

#[test]
fn test_block_mode_with_allowlist_carveout() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    write(
        dir.path(),
        NET_PROFILE_FILENAME,
        "mode = \"block\"\n\n[[allowlist]]\napp = \"/usr/bin/curl\"\nhost = \"allowed.example.com\"\n",
    );
    let rs = build_base_ruleset(dir.path(), &[]).expect("build base");

    // Carved-out app+host is allowed despite Block-All.
    let allowed = rs.decide_for(&proc("/usr/bin/curl"), &dest("allowed.example.com"));
    assert_eq!(allowed.action, NetworkAction::Allow);

    // A different host from the same app still falls through to Deny.
    let denied = rs.decide_for(&proc("/usr/bin/curl"), &dest("other.example.com"));
    assert_eq!(denied.action, NetworkAction::Deny);
}

#[test]
fn test_user_rule_file_denies_process() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    write_rule(
        dir.path(),
        "block-curl.toml",
        "name = \"Block curl tracker\"\nprocess = \"/usr/bin/curl\"\ndest = \"tracker.example.com\"\naction = \"deny\"\n",
    );
    let rs = load_live_ruleset(dir.path(), &[], &[]).expect("build live");

    let denied = rs.decide_for(&proc("/usr/bin/curl"), &dest("tracker.example.com"));
    assert_eq!(denied.action, NetworkAction::Deny);

    // A different process to the same host is unaffected (Allow-All default).
    let other = rs.decide_for(&proc("/usr/bin/other"), &dest("tracker.example.com"));
    assert_eq!(other.action, NetworkAction::Log);
}

#[test]
fn test_missing_net_rules_dir_is_ok() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let rs = load_live_ruleset(dir.path(), &[], &[]).expect("build live with no net-rules");
    let d = rs.decide_for(&proc("/x"), &dest("x.example.com"));
    assert_eq!(d.action, NetworkAction::Log);
}

#[test]
fn test_session_rule_is_applied() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let file = crate::user_rule::UserRuleFile {
        name: "session block".to_owned(),
        process: "/usr/bin/curl".to_owned(),
        dest: "session.example.com".to_owned(),
        dest_port: None,
        dest_ip: None,
        dest_protocol: None,
        team_id: None,
        action: NetworkAction::Deny,
        enabled: true,
        note: None,
    };
    let session = vec![file.to_network_rule(9000).expect("compile session rule")];
    let rs = load_live_ruleset(dir.path(), &session, &[]).expect("build live");
    let d = rs.decide_for(&proc("/usr/bin/curl"), &dest("session.example.com"));
    assert_eq!(d.action, NetworkAction::Deny);
}

#[test]
fn test_rule_mutation_writes_under_watched_base_dir() {
    // Spec 009 R5: the daemon needs NO new signaling channel to the sysext. Every
    // rule mutation writes a file under the same `base_dir` the NE provider's
    // `RuleWatcher` watches; the file change is itself the reload trigger. This
    // asserts that invariant at the loader boundary: a mutation (a `net-rules/`
    // file, as `net block` writes) lands under the watched base dir, and reloading
    // from that dir reflects it — no out-of-band notification involved.
    let base = tempfile::TempDir::new().expect("tempdir");

    // Baseline: no rule → Allow-All (Log).
    let before = load_live_ruleset(base.path(), &[], &[]).expect("build live baseline");
    assert_eq!(
        before
            .decide_for(&proc("/usr/bin/curl"), &dest("watched.example.com"))
            .action,
        NetworkAction::Log,
    );

    // The mutation: write the deny rule where `net block` writes it.
    write_rule(
        base.path(),
        "block-curl.toml",
        "name = \"watch trigger\"\nprocess = \"/usr/bin/curl\"\ndest = \"watched.example.com\"\naction = \"deny\"\n",
    );

    // Invariant 1: the written file is under the watched base dir (the reload
    // trigger the `RuleWatcher` vnode source fires on).
    let written = base.path().join(NET_RULES_DIRNAME).join("block-curl.toml");
    assert!(written.exists(), "mutation must produce a file on disk");
    assert!(
        written.starts_with(base.path()),
        "the rule file must live under the watched base dir, not elsewhere",
    );

    // Invariant 2: reloading from that same base dir (what `macwarden_ne_reload`
    // does in-process) now reflects the mutation.
    let after = load_live_ruleset(base.path(), &[], &[]).expect("build live after mutation");
    assert_eq!(
        after
            .decide_for(&proc("/usr/bin/curl"), &dest("watched.example.com"))
            .action,
        NetworkAction::Deny,
    );
}

#[test]
fn test_rule_file_deletion_reverts_on_reload() {
    // Spec 009 R5 ordering: the reverse of a mutation is also just a file
    // change under the watched base dir. Deleting a `net-rules/` file must be
    // reflected the same way an addition is -- the next reload sees the
    // deletion and reverts to the Allow-All default, with no stale in-memory
    // rule surviving.
    let base = tempfile::TempDir::new().expect("tempdir");
    write_rule(
        base.path(),
        "block-curl.toml",
        "name = \"watch trigger\"\nprocess = \"/usr/bin/curl\"\ndest = \"watched.example.com\"\naction = \"deny\"\n",
    );
    let with_rule = load_live_ruleset(base.path(), &[], &[]).expect("build live with rule");
    assert_eq!(
        with_rule
            .decide_for(&proc("/usr/bin/curl"), &dest("watched.example.com"))
            .action,
        NetworkAction::Deny,
    );

    std::fs::remove_file(base.path().join(NET_RULES_DIRNAME).join("block-curl.toml"))
        .expect("delete rule file");

    let after_delete = load_live_ruleset(base.path(), &[], &[]).expect("build live after delete");
    assert_eq!(
        after_delete
            .decide_for(&proc("/usr/bin/curl"), &dest("watched.example.com"))
            .action,
        NetworkAction::Log,
        "a deleted rule file must not leave a stale rule behind on reload",
    );
}

#[test]
fn test_rule_file_overwrite_reflects_latest_content_on_reload() {
    // A mutation that *replaces* an existing file's content (the same filename
    // rewritten, as `net block`/`net unblock` on the same target would do) must
    // be picked up on the next reload -- not the file's original content.
    let base = tempfile::TempDir::new().expect("tempdir");
    write_rule(
        base.path(),
        "toggle.toml",
        "name = \"toggle\"\nprocess = \"/usr/bin/curl\"\ndest = \"toggle.example.com\"\naction = \"deny\"\n",
    );
    let denied = load_live_ruleset(base.path(), &[], &[]).expect("build live denied");
    assert_eq!(
        denied
            .decide_for(&proc("/usr/bin/curl"), &dest("toggle.example.com"))
            .action,
        NetworkAction::Deny,
    );

    // Overwrite the same file with the opposite action.
    write_rule(
        base.path(),
        "toggle.toml",
        "name = \"toggle\"\nprocess = \"/usr/bin/curl\"\ndest = \"toggle.example.com\"\naction = \"allow\"\n",
    );
    let allowed = load_live_ruleset(base.path(), &[], &[]).expect("build live allowed");
    assert_eq!(
        allowed
            .decide_for(&proc("/usr/bin/curl"), &dest("toggle.example.com"))
            .action,
        NetworkAction::Allow,
        "reload must reflect the overwritten file's new content, not the original",
    );
}

#[test]
fn test_reload_tolerates_malformed_rule_file_alongside_valid_one() {
    // Adversarial: a mutation lands a malformed/partial rule file (e.g. a
    // torn write observed mid-flush, or hand-edited garbage) in `net-rules/`
    // next to an otherwise-valid rule. The loader's per-file fail-open (skip
    // and warn, per `load_user_rules`) must mean the *whole* reload does not
    // error out and does not lose the valid rule -- the malformed file is
    // simply dropped, not fatal to the reload.
    let base = tempfile::TempDir::new().expect("tempdir");
    write_rule(
        base.path(),
        "valid.toml",
        "name = \"valid\"\nprocess = \"/usr/bin/curl\"\ndest = \"valid.example.com\"\naction = \"deny\"\n",
    );
    write_rule(base.path(), "torn.toml", "name = \"truncated\nproc");

    let rs = load_live_ruleset(base.path(), &[], &[]).expect(
        "a malformed sibling rule file must not fail the whole reload (per-file fail-open)",
    );
    assert_eq!(
        rs.decide_for(&proc("/usr/bin/curl"), &dest("valid.example.com"))
            .action,
        NetworkAction::Deny,
        "the valid rule file must still take effect despite the malformed sibling",
    );
}

#[test]
fn test_load_live_ruleset_on_nonexistent_base_dir_fails_open() {
    // First-boot / not-yet-created `~/.macwarden/` scenario: the base dir
    // itself (not just `net-rules/` under it) does not exist on disk yet. Both
    // the profile/shield configs and the rules directory must fail open to
    // their Allow-All defaults rather than erroring, since the daemon must be
    // able to build a live rule set before any file under the watched base dir
    // has ever been written.
    let parent = tempfile::TempDir::new().expect("tempdir");
    let never_created = parent.path().join("does-not-exist-yet");
    assert!(!never_created.exists());

    let rs = load_live_ruleset(&never_created, &[], &[])
        .expect("a wholly nonexistent base dir must still fail open, not error");
    assert_eq!(
        rs.decide_for(&proc("/x"), &dest("x.example.com")).action,
        NetworkAction::Log,
    );
}

#[test]
fn test_persisted_rule_and_conflicting_session_rule_same_specificity_persisted_wins() {
    // Reload ordering invariant: `load_live_ruleset` appends persisted
    // `net-rules/` files *before* the caller's in-memory session rules, then
    // stable-sorts by descending specificity. For two rules of identical
    // specificity (same process + dest pattern) with conflicting actions, the
    // persisted (disk) rule -- inserted first -- must win over the session
    // rule, since `decide_for` takes the first match in vec order. This pins
    // down which mutation "wins" a race between a daemon rule write and a
    // still-live in-memory session override, so it doesn't silently flip with
    // an unrelated refactor of the composition order.
    let base = tempfile::TempDir::new().expect("tempdir");
    write_rule(
        base.path(),
        "persisted-deny.toml",
        "name = \"persisted deny\"\nprocess = \"/usr/bin/curl\"\ndest = \"race.example.com\"\naction = \"deny\"\n",
    );
    let session_file = crate::user_rule::UserRuleFile {
        name: "session allow".to_owned(),
        process: "/usr/bin/curl".to_owned(),
        dest: "race.example.com".to_owned(),
        dest_port: None,
        dest_ip: None,
        dest_protocol: None,
        team_id: None,
        action: NetworkAction::Allow,
        enabled: true,
        note: None,
    };
    let session = vec![
        session_file
            .to_network_rule(9000)
            .expect("compile session rule"),
    ];

    let rs = load_live_ruleset(base.path(), &session, &[]).expect("build live with race");
    assert_eq!(
        rs.decide_for(&proc("/usr/bin/curl"), &dest("race.example.com"))
            .action,
        NetworkAction::Deny,
        "the persisted (disk) rule must take precedence over an equal-specificity \
         in-memory session rule",
    );
}

fn dest_ip(ip: IpAddr) -> Destination {
    Destination {
        host: None,
        ip,
        port: Some(443),
        protocol: Some(Protocol::Tcp),
        address_family: match ip {
            IpAddr::V4(_) => AddressFamily::Inet,
            IpAddr::V6(_) => AddressFamily::Inet6,
        },
    }
}

#[test]
fn test_banned_ip_is_denied_for_any_process() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let banned = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 66));

    // Without a ban (empty ban input), an Allow-All default logs the flow.
    let before = build_base_ruleset(dir.path(), &[]).expect("build base");
    assert_eq!(
        before.decide_for(&proc("/x"), &dest_ip(banned)).action,
        NetworkAction::Log,
    );

    // Supply the IP as an explicit ban input; the composed rule set now denies
    // any process to it.
    let after = build_base_ruleset(dir.path(), &[banned]).expect("build base after ban");
    assert_eq!(
        after.decide_for(&proc("/x"), &dest_ip(banned)).action,
        NetworkAction::Deny,
    );
    // A different IP is unaffected.
    let other = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 67));
    assert_eq!(
        after.decide_for(&proc("/x"), &dest_ip(other)).action,
        NetworkAction::Log,
    );
}

#[test]
fn test_ban_denies_through_live_ruleset_too() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let banned = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9));
    // The full live path (what the daemon serves) also carries a supplied ban.
    let rs = load_live_ruleset(dir.path(), &[], &[banned]).expect("build live");
    assert_eq!(
        rs.decide_for(&proc("/usr/bin/curl"), &dest_ip(banned))
            .action,
        NetworkAction::Deny,
    );
}

#[test]
fn test_ipv6_ban_is_denied() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let banned: IpAddr = "2001:db8::dead".parse().expect("v6");
    let rs = build_base_ruleset(dir.path(), &[banned]).expect("build base");
    assert_eq!(
        rs.decide_for(&proc("/x"), &dest_ip(banned)).action,
        NetworkAction::Deny,
    );
}

#[test]
fn test_ban_rules_sit_in_reserved_id_band() {
    let banned = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));
    let rules = ban_deny_rules(&[banned]);
    assert!(!rules.is_empty());
    assert!(
        rules
            .iter()
            .all(|r| r.id.0 >= BAN_RULE_ID_BASE && r.id.0 < 900_000),
        "ban rule ids must sit in the reserved band below session rules",
    );
}

#[test]
fn test_empty_ban_set_composes_no_ban_rules() {
    // A caller supplying no bans yields no ban rules.
    assert!(ban_deny_rules(&[]).is_empty());
}

#[test]
fn test_ban_deny_rules_preserves_every_supplied_ip() {
    // Regression guard for the WAL torn-read bug (#4): composition takes the ban
    // IP set as an explicit input, so it can never silently drop entries the way
    // a store-reopening reader could when racing a WAL compaction. Given N
    // distinct IPs the loader must emit exactly N Deny rules, one per IP, with no
    // loss and no duplication.
    let banned: Vec<IpAddr> = (0..64u8)
        .map(|i| IpAddr::V4(Ipv4Addr::new(203, 0, 113, i)))
        .collect();
    let rules = ban_deny_rules(&banned);
    assert_eq!(
        rules.len(),
        banned.len(),
        "every supplied ban IP must compose exactly one Deny rule — none dropped",
    );
    // Each supplied IP is denied for any process through the full base set.
    let rs = build_base_ruleset(tempfile::TempDir::new().expect("tempdir").path(), &banned)
        .expect("build base");
    for ip in &banned {
        assert_eq!(
            rs.decide_for(&proc("/x"), &dest_ip(*ip)).action,
            NetworkAction::Deny,
            "banned IP {ip} must be denied",
        );
    }
}

#[test]
fn test_malformed_profile_fails_open() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    write(dir.path(), NET_PROFILE_FILENAME, "mode = = broken ][");
    // Malformed config fails open to Allow-All; the base set still builds.
    let rs = build_base_ruleset(dir.path(), &[]).expect("build base with malformed config");
    let d = rs.decide_for(&proc("/x"), &dest("x.example.com"));
    assert_eq!(d.action, NetworkAction::Log);
}
