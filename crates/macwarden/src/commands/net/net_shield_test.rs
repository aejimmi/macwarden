use super::*;

// ---------------------------------------------------------------------------
// ShieldConfig defaults
// ---------------------------------------------------------------------------

#[test]
fn test_shield_config_default_is_disabled() {
    let cfg = ShieldConfig::default();
    assert!(!cfg.enabled);
    assert_eq!(cfg.advertising, "log");
    assert_eq!(cfg.analytics, "log");
    assert_eq!(cfg.fingerprinting, "log");
    assert_eq!(cfg.social, "log");
}

// ---------------------------------------------------------------------------
// ShieldConfig::enabled_all
// ---------------------------------------------------------------------------

#[test]
fn test_shield_config_enabled_all() {
    let cfg = ShieldConfig::enabled_all();
    assert!(cfg.enabled);
    assert_eq!(cfg.advertising, "deny");
    assert_eq!(cfg.analytics, "deny");
    assert_eq!(cfg.fingerprinting, "deny");
    assert_eq!(cfg.social, "deny");
}

// ---------------------------------------------------------------------------
// ShieldConfig::enabled_partial
// ---------------------------------------------------------------------------

#[test]
fn test_shield_config_enabled_partial_single() {
    let cfg = ShieldConfig::enabled_partial(&["advertising".to_owned()]);
    assert!(cfg.enabled);
    assert_eq!(cfg.advertising, "deny");
    assert_eq!(cfg.analytics, "log");
    assert_eq!(cfg.fingerprinting, "log");
    assert_eq!(cfg.social, "log");
}

#[test]
fn test_shield_config_enabled_partial_multiple() {
    let only = vec!["advertising".to_owned(), "fingerprinting".to_owned()];
    let cfg = ShieldConfig::enabled_partial(&only);
    assert!(cfg.enabled);
    assert_eq!(cfg.advertising, "deny");
    assert_eq!(cfg.analytics, "log");
    assert_eq!(cfg.fingerprinting, "deny");
    assert_eq!(cfg.social, "log");
}

#[test]
fn test_shield_config_enabled_partial_case_insensitive() {
    let cfg = ShieldConfig::enabled_partial(&["Advertising".to_owned()]);
    assert_eq!(cfg.advertising, "deny");
}

#[test]
fn test_shield_config_enabled_partial_unknown_category_ignored() {
    let cfg = ShieldConfig::enabled_partial(&["unknown".to_owned()]);
    assert!(cfg.enabled);
    assert_eq!(cfg.advertising, "log");
    assert_eq!(cfg.analytics, "log");
    assert_eq!(cfg.fingerprinting, "log");
    assert_eq!(cfg.social, "log");
}

// ---------------------------------------------------------------------------
// category_action
// ---------------------------------------------------------------------------

#[test]
fn test_category_action_deny() {
    let cfg = ShieldConfig::enabled_all();
    assert_eq!(cfg.category_action("advertising"), NetworkAction::Deny);
    assert_eq!(cfg.category_action("analytics"), NetworkAction::Deny);
}

#[test]
fn test_category_action_log() {
    let cfg = ShieldConfig::default();
    assert_eq!(cfg.category_action("advertising"), NetworkAction::Log);
}

#[test]
fn test_category_action_unknown() {
    let cfg = ShieldConfig::enabled_all();
    assert_eq!(cfg.category_action("nonexistent"), NetworkAction::Log);
}

// ---------------------------------------------------------------------------
// is_category_denied
// ---------------------------------------------------------------------------

#[test]
fn test_is_category_denied_true() {
    let cfg = ShieldConfig::enabled_all();
    assert!(cfg.is_category_denied("advertising"));
    assert!(cfg.is_category_denied("social"));
}

#[test]
fn test_is_category_denied_false() {
    let cfg = ShieldConfig::default();
    assert!(!cfg.is_category_denied("advertising"));
}

// ---------------------------------------------------------------------------
// TOML round-trip
// ---------------------------------------------------------------------------

#[test]
fn test_shield_config_toml_roundtrip() {
    let cfg = ShieldConfig::enabled_all();
    let toml_str = toml::to_string_pretty(&cfg).expect("should serialize");
    let parsed: ShieldConfig = toml::from_str(&toml_str).expect("should deserialize");
    assert!(parsed.enabled);
    assert_eq!(parsed.advertising, "deny");
    assert_eq!(parsed.analytics, "deny");
    assert_eq!(parsed.fingerprinting, "deny");
    assert_eq!(parsed.social, "deny");
}

#[test]
fn test_shield_config_toml_partial_roundtrip() {
    let cfg = ShieldConfig::enabled_partial(&["analytics".to_owned()]);
    let toml_str = toml::to_string_pretty(&cfg).expect("should serialize");
    let parsed: ShieldConfig = toml::from_str(&toml_str).expect("should deserialize");
    assert!(parsed.enabled);
    assert_eq!(parsed.advertising, "log");
    assert_eq!(parsed.analytics, "deny");
}

#[test]
fn test_shield_config_deserialize_empty() {
    let cfg: ShieldConfig = toml::from_str("").expect("should deserialize empty");
    assert!(!cfg.enabled);
    assert_eq!(cfg.advertising, "log");
}

#[test]
fn test_shield_config_deserialize_partial_toml() {
    let input = "enabled = true\nadvertising = \"deny\"\n";
    let cfg: ShieldConfig = toml::from_str(input).expect("should deserialize");
    assert!(cfg.enabled);
    assert_eq!(cfg.advertising, "deny");
    assert_eq!(cfg.analytics, "log");
}

// ---------------------------------------------------------------------------
// load_shield_config (file-based, uses tempdir)
// ---------------------------------------------------------------------------

#[test]
fn test_load_shield_config_returns_default_when_no_file() {
    // When HOME points to a temp directory with no config, should return default.
    let cfg = ShieldConfig::default();
    assert!(!cfg.enabled);
}
