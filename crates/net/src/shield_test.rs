use super::*;

#[test]
fn test_default_is_disabled_and_logs() {
    let cfg = ShieldConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.advertising, "log");
    assert_eq!(cfg.analytics, "log");
    assert_eq!(cfg.fingerprinting, "log");
    assert_eq!(cfg.social, "log");
}

#[test]
fn test_enabled_all_denies_every_category() {
    let cfg = ShieldConfig::enabled_all();
    assert!(cfg.enabled);
    assert_eq!(cfg.category_action("advertising"), NetworkAction::Deny);
    assert_eq!(cfg.category_action("analytics"), NetworkAction::Deny);
    assert_eq!(cfg.category_action("fingerprinting"), NetworkAction::Deny);
    assert_eq!(cfg.category_action("social"), NetworkAction::Deny);
}

#[test]
fn test_enabled_partial_denies_only_named() {
    let cfg = ShieldConfig::enabled_partial(&["advertising".to_owned()]);
    assert!(cfg.enabled);
    assert!(cfg.is_category_denied("advertising"));
    assert!(!cfg.is_category_denied("analytics"));
    assert!(!cfg.is_category_denied("social"));
}

#[test]
fn test_enabled_partial_is_case_insensitive() {
    let cfg = ShieldConfig::enabled_partial(&["Advertising".to_owned()]);
    assert!(cfg.is_category_denied("advertising"));
}

#[test]
fn test_enabled_partial_ignores_unknown_category() {
    let cfg = ShieldConfig::enabled_partial(&["nonexistent".to_owned()]);
    assert!(cfg.enabled);
    assert!(!cfg.is_category_denied("advertising"));
}

#[test]
fn test_category_action_unknown_name_is_log() {
    let cfg = ShieldConfig::enabled_all();
    assert_eq!(cfg.category_action("nonexistent"), NetworkAction::Log);
}

#[test]
fn test_toml_roundtrip_preserves_state() {
    let cfg = ShieldConfig::enabled_partial(&["analytics".to_owned()]);
    let toml_str = toml::to_string_pretty(&cfg).expect("serialize");
    let parsed: ShieldConfig = toml::from_str(&toml_str).expect("deserialize");
    assert!(parsed.enabled);
    assert!(parsed.is_category_denied("analytics"));
    assert!(!parsed.is_category_denied("advertising"));
}

#[test]
fn test_deserialize_empty_yields_default() {
    let cfg: ShieldConfig = toml::from_str("").expect("deserialize empty");
    assert!(!cfg.enabled);
    assert_eq!(cfg.advertising, "log");
}

#[test]
fn test_load_missing_file_is_default() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let cfg = ShieldConfig::load(&dir.path().join(SHIELD_FILENAME));
    assert!(!cfg.enabled);
}

#[test]
fn test_load_malformed_file_fails_open_to_default() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join(SHIELD_FILENAME);
    std::fs::write(&path, "this is = not valid toml ][").expect("write");
    let cfg = ShieldConfig::load(&path);
    assert!(!cfg.enabled);
}

#[test]
fn test_load_valid_enabled_file() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let path = dir.path().join(SHIELD_FILENAME);
    std::fs::write(&path, ShieldConfig::enabled_all_toml()).expect("write");
    let cfg = ShieldConfig::load(&path);
    assert!(cfg.enabled);
    assert!(cfg.is_category_denied("advertising"));
}

impl ShieldConfig {
    fn enabled_all_toml() -> String {
        toml::to_string_pretty(&Self::enabled_all()).expect("serialize enabled_all")
    }
}
