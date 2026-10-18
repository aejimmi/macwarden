use super::*;

use std::path::Path;

use crate::decision::NeDecision;

fn write_rule(base: &Path, name: &str, content: &str) {
    let rules = base.join("net-rules");
    std::fs::create_dir_all(&rules).expect("mkdir net-rules");
    std::fs::write(rules.join(name), content).expect("write rule");
}

const DENY_CURL: &str = "name = \"block\"\nprocess = \"/usr/bin/curl\"\ndest = \"tracker.example.com\"\naction = \"deny\"\n";

#[test]
fn test_load_from_empty_dir_is_allow_all() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ne = MacwardenNe::load(dir.path().to_path_buf()).expect("load");
    let d = ne.decide(None, Some("/x"), Some("x.example.com"), None, 443, 6);
    assert_eq!(d, NeDecision::Log);
}

#[test]
fn test_decide_reflects_user_rule() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    write_rule(dir.path(), "block-curl.toml", DENY_CURL);
    let ne = MacwardenNe::load(dir.path().to_path_buf()).expect("load");
    let d = ne.decide(
        None,
        Some("/usr/bin/curl"),
        Some("tracker.example.com"),
        None,
        443,
        6,
    );
    assert_eq!(d, NeDecision::Deny);
}

#[test]
fn test_reload_picks_up_changed_rule_file() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ne = MacwardenNe::load(dir.path().to_path_buf()).expect("load");

    // Before: no rule, allow-all default logs.
    let before = ne.decide(
        None,
        Some("/usr/bin/curl"),
        Some("tracker.example.com"),
        None,
        443,
        6,
    );
    assert_eq!(before, NeDecision::Log);

    // Write a deny rule, then reload.
    write_rule(dir.path(), "block-curl.toml", DENY_CURL);
    ne.reload().expect("reload");

    let after = ne.decide(
        None,
        Some("/usr/bin/curl"),
        Some("tracker.example.com"),
        None,
        443,
        6,
    );
    assert_eq!(after, NeDecision::Deny);
}

#[test]
#[allow(clippy::multiple_unsafe_ops_per_block)]
fn test_default_base_dir_prefers_macwarden_home() {
    let prev = std::env::var_os("MACWARDEN_HOME");

    // SAFETY: env mutation is restored below; no other test reads
    // MACWARDEN_HOME concurrently (they use `init_at`, not `init`).
    unsafe {
        std::env::set_var("MACWARDEN_HOME", "/tmp/mw-test-home");
    }
    let resolved = crate::handle::default_base_dir().expect("base dir");

    // SAFETY: restore the prior value (or clear it) to keep the env pristine.
    unsafe {
        match prev {
            Some(v) => std::env::set_var("MACWARDEN_HOME", v),
            None => std::env::remove_var("MACWARDEN_HOME"),
        }
    }
    assert_eq!(resolved, Path::new("/tmp/mw-test-home"));
}
