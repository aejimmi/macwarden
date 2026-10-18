#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::needless_raw_string_hashes
)]
use super::*;

use tempfile::TempDir;

fn write_config(body: &str) -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join(CONFIG_FILENAME);
    std::fs::write(&path, body).unwrap();
    (dir, path)
}

#[test]
fn test_missing_file_is_defaults() {
    let dir = TempDir::new().unwrap();
    let cfg = BanwatchConfig::load(&dir.path().join("nope.toml"));
    assert!(cfg.enabled);
    assert_eq!(cfg.ban_time, 3_600);
    assert!(cfg.repeat_blocked.enabled);
    assert!(!cfg.auth_failure.enabled);
    assert!(!cfg.port_scan.enabled);
}

#[test]
fn test_full_config_parses() {
    let (_d, path) = write_config(
        r#"
[banwatch]
enabled = true
ban_time = "2h"
ban_time_increment = false
ban_time_multipliers = [1, 3, 9]
ban_time_maxtime = "1d"
ban_count_decay = "7d"
ignoreip = ["203.0.113.0/24"]
ignore_self = false

[detectors.repeat-blocked]
enabled = true
max_retry = 7
find_time = "5m"

[detectors.auth-failure]
enabled = true
max_retry = 3
find_time = "15m"

[detectors.port-scan]
enabled = true
distinct_ports = 20
syn_rate = 200
find_time = "30s"
"#,
    );
    let cfg = BanwatchConfig::load(&path);
    assert_eq!(cfg.ban_time, 7_200);
    assert!(!cfg.ban_time_increment);
    assert_eq!(cfg.ban_time_multipliers, vec![1, 3, 9]);
    assert_eq!(cfg.ban_time_maxtime, 86_400);
    assert_eq!(cfg.ban_count_decay, 604_800);
    assert_eq!(cfg.ignoreip, vec!["203.0.113.0/24".to_owned()]);
    assert!(!cfg.ignore_self);
    assert_eq!(cfg.repeat_blocked.max_retry, 7);
    assert_eq!(cfg.repeat_blocked.find_time, 300);
    assert!(cfg.auth_failure.enabled);
    assert_eq!(cfg.auth_failure.find_time, 900);
    assert!(cfg.port_scan.enabled);
    assert_eq!(cfg.port_scan.distinct_ports, 20);
    assert_eq!(cfg.port_scan.syn_rate, 200);
    assert_eq!(cfg.port_scan.find_time, 30);
}

#[test]
fn test_malformed_toml_is_defaults() {
    let (_d, path) = write_config("this is not = valid = toml [[[");
    let cfg = BanwatchConfig::load(&path);
    assert_eq!(cfg.ban_time, 3_600);
}

#[test]
fn test_bad_duration_falls_back_to_field_default() {
    let (_d, path) = write_config(
        r#"
[banwatch]
ban_time = "banana"
find_time = "10m"
"#,
    );
    let cfg = BanwatchConfig::load(&path);
    assert_eq!(cfg.ban_time, 3_600, "bad ban_time -> default");
}

#[test]
fn test_partial_config_keeps_other_defaults() {
    let (_d, path) = write_config(
        r#"
[banwatch]
enabled = false
"#,
    );
    let cfg = BanwatchConfig::load(&path);
    assert!(!cfg.enabled);
    // Untouched fields keep defaults.
    assert!(cfg.repeat_blocked.enabled);
    assert_eq!(cfg.ban_time, 3_600);
}

#[test]
fn test_detector_params_map() {
    let cfg = BanwatchConfig::default();
    let params = cfg.detector_params();
    assert!(params.contains_key(crate::record::DETECTOR_REPEAT_BLOCKED));
    // Port-scan engine params always ban on the first analyzer signal.
    let ps = params.get(crate::record::DETECTOR_PORT_SCAN).unwrap();
    assert_eq!(ps.max_retry, 1);
}
