#![allow(clippy::unwrap_used, clippy::panic)]

use super::*;

#[test]
fn test_build_live_ruleset_missing_dir_is_ok() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let rs = build_live_ruleset(&missing, &[], &[]).unwrap();
    // No user rule *files* exist. The base profile may still inject synthetic
    // policy Allow rules (allow-list + the DNS carve-out, all in the reserved
    // `800_000+` id band), so assert only that no file/session rule leaked in.
    assert!(
        rs.user_rules
            .iter()
            .all(|r| r.id.0 >= net::ALLOWLIST_RULE_ID_BASE),
        "only reserved-band synthetic Allow rules should be present"
    );
}

#[test]
fn test_build_live_ruleset_loads_user_rule_files() {
    let dir = tempfile::tempdir().unwrap();
    let rules_dir = dir.path().join("net-rules");
    std::fs::create_dir_all(&rules_dir).unwrap();
    std::fs::write(
        rules_dir.join("block-example.toml"),
        "name = \"Block example\"\nprocess = \"com.example.app\"\n\
         dest = \"*\"\naction = \"deny\"\nenabled = true\n",
    )
    .unwrap();

    let rs = build_live_ruleset(&rules_dir, &[], &[]).unwrap();
    assert!(
        rs.user_rules.iter().any(|r| r.name == "Block example"),
        "the user rule file must be loaded into the live rule set"
    );
}
