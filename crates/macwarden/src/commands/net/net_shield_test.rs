#![allow(clippy::unwrap_used)]
use super::*;

use tempfile::TempDir;

// `ShieldConfig` and its serde/category semantics are owned and tested by
// `net::shield`. These tests cover the daemon's `base_dir`-parameterized
// load/save wrappers hermetically, against a `TempDir` — no `$HOME` touched.

#[test]
fn test_save_then_load_roundtrips_enabled_all() {
    let dir = TempDir::new().unwrap();
    let cfg = ShieldConfig::enabled_all();
    save_shield_config(dir.path(), &cfg).unwrap();

    // The file lands at base_dir/net-shield.toml.
    assert!(dir.path().join(SHIELD_FILENAME).is_file());

    let loaded = load_shield_config(dir.path());
    assert!(loaded.enabled, "round-tripped shield stays enabled");
    assert!(loaded.is_category_denied("advertising"));
    assert!(loaded.is_category_denied("analytics"));
    assert!(loaded.is_category_denied("fingerprinting"));
    assert!(loaded.is_category_denied("social"));
}

#[test]
fn test_save_then_load_roundtrips_partial() {
    let dir = TempDir::new().unwrap();
    let cfg = ShieldConfig::enabled_partial(&["advertising".to_owned()]);
    save_shield_config(dir.path(), &cfg).unwrap();

    let loaded = load_shield_config(dir.path());
    assert!(loaded.enabled);
    assert!(loaded.is_category_denied("advertising"));
    assert!(!loaded.is_category_denied("social"), "unlisted stays log");
}

#[test]
fn test_load_missing_file_is_default_disabled() {
    let dir = TempDir::new().unwrap();
    // Nothing written: fail-open to the disabled default.
    let loaded = load_shield_config(dir.path());
    assert!(!loaded.enabled);
    assert!(!loaded.is_category_denied("advertising"));
}

#[test]
fn test_load_malformed_file_fails_open_to_default() {
    let dir = TempDir::new().unwrap();
    std::fs::write(
        dir.path().join(SHIELD_FILENAME),
        b"this is not = valid ][ toml",
    )
    .unwrap();
    // A broken shield file must not brick the network — it loads as disabled.
    let loaded = load_shield_config(dir.path());
    assert!(
        !loaded.enabled,
        "malformed shield file fails open to disabled"
    );
}

#[cfg(unix)]
#[test]
fn test_saved_shield_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let dir = TempDir::new().unwrap();
    save_shield_config(dir.path(), &ShieldConfig::enabled_all()).unwrap();
    let mode = std::fs::metadata(dir.path().join(SHIELD_FILENAME))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "shield file must be owner-only");
}
