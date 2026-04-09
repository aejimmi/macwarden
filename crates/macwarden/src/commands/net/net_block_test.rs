#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

// ---------------------------------------------------------------------------
// make_slug
// ---------------------------------------------------------------------------

#[test]
fn test_make_slug_app_only() {
    assert_eq!(make_slug(Some("Spotify"), None), "spotify");
}

#[test]
fn test_make_slug_host_only() {
    assert_eq!(
        make_slug(None, Some("tracker.example.com")),
        "tracker-example-com"
    );
}

#[test]
fn test_make_slug_app_and_host() {
    assert_eq!(
        make_slug(Some("Spotify"), Some("scdn.co")),
        "spotify-scdn-co"
    );
}

#[test]
fn test_make_slug_special_chars() {
    assert_eq!(make_slug(Some("My App!"), None), "my-app-");
}

// ---------------------------------------------------------------------------
// generate_rule_toml
// ---------------------------------------------------------------------------

#[test]
fn test_generate_rule_toml_app_only() {
    let toml = generate_rule_toml(Some("Spotify"), Some("com.spotify.client"), None);
    assert!(toml.contains("process = \"com.spotify.client\""));
    assert!(toml.contains("dest = \"*\""));
    assert!(toml.contains("action = \"deny\""));
    assert!(toml.contains("Block Spotify (all traffic)"));
}

#[test]
fn test_generate_rule_toml_host_only() {
    let toml = generate_rule_toml(None, None, Some("tracker.com"));
    assert!(toml.contains("process = \"*\""));
    assert!(toml.contains("dest = \"tracker.com\""));
    assert!(toml.contains("action = \"deny\""));
    assert!(toml.contains("Block tracker.com (all apps)"));
}

#[test]
fn test_generate_rule_toml_app_and_host() {
    let toml = generate_rule_toml(
        Some("Chrome"),
        Some("com.google.Chrome"),
        Some("ads.google.com"),
    );
    assert!(toml.contains("process = \"com.google.Chrome\""));
    assert!(toml.contains("dest = \"ads.google.com\""));
    assert!(toml.contains("Block Chrome -> ads.google.com"));
}

// ---------------------------------------------------------------------------
// resolve_app
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_app_code_id_passthrough() {
    let db = AppDb::from_sources(&[]).expect("empty db");
    let result = resolve_app("com.example.app", &db).expect("should accept code_id");
    assert_eq!(result, "com.example.app");
}

#[test]
fn test_resolve_app_by_name() {
    let db = AppDb::load_builtin().expect("builtin db");
    let result = resolve_app("Safari", &db).expect("should resolve Safari");
    assert_eq!(result, "com.apple.Safari");
}

#[test]
fn test_resolve_app_unknown_name() {
    let db = AppDb::load_builtin().expect("builtin db");
    let result = resolve_app("NonExistentApp12345", &db);
    assert!(result.is_err());
}
