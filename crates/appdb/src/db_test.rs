#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;

// ---------------------------------------------------------------------------
// AppDb::from_sources — basic loading
// ---------------------------------------------------------------------------

#[test]
fn test_from_sources_minimal_profile() {
    let toml = r#"
code_id = "com.example.app"
name = "Example"
"#;
    let db = AppDb::from_sources(&[toml]).expect("should parse minimal profile");
    assert_eq!(db.len(), 1);
    let profile = db.lookup("com.example.app").expect("should find profile");
    assert_eq!(profile.name, "Example");
    assert!(profile.category.is_none());
    assert!(profile.developer.is_none());
    assert!(profile.description.is_none());
    assert!(profile.connections.is_empty());
}

#[test]
fn test_from_sources_full_profile() {
    let toml = r#"
code_id = "com.example.full"
name = "Full App"
developer = "Example Corp."
category = "productivity"
description = "A fully described app"

[[connections]]
host = "example.com"
purpose = "Account sync"
if_denied = "Cannot sync data"
risk = "degraded"

[[connections]]
host = "analytics.example.com"
purpose = "Telemetry"
risk = "none"
"#;
    let db = AppDb::from_sources(&[toml]).expect("should parse full profile");
    let profile = db.lookup("com.example.full").expect("should find profile");
    assert_eq!(profile.developer.as_deref(), Some("Example Corp."));
    assert_eq!(profile.category, Some(AppCategory::Productivity));
    assert_eq!(profile.connections.len(), 2);
    assert_eq!(profile.connections[0].host, "example.com");
    assert_eq!(
        profile.connections[0].if_denied.as_deref(),
        Some("Cannot sync data")
    );
}

#[test]
fn test_from_sources_invalid_toml() {
    let bad = "this is not valid toml [[[";
    let result = AppDb::from_sources(&[bad]);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// AppDb::load_builtin — embedded data integrity
// ---------------------------------------------------------------------------

#[test]
fn test_load_builtin() {
    let db = AppDb::load_builtin().expect("builtin profiles should load");
    assert!(
        db.len() >= 20,
        "should have at least 20 builtin profiles, got {}",
        db.len()
    );
}

#[test]
fn test_load_builtin_all_have_code_id_and_name() {
    let db = AppDb::load_builtin().expect("builtin profiles should load");
    for profile in db.entries() {
        assert!(!profile.code_id.is_empty(), "code_id must not be empty");
        assert!(!profile.name.is_empty(), "name must not be empty");
    }
}

#[test]
fn test_load_builtin_no_duplicate_code_ids() {
    let db = AppDb::load_builtin().expect("builtin profiles should load");
    let mut seen = std::collections::HashSet::new();
    for profile in db.entries() {
        assert!(
            seen.insert(&profile.code_id),
            "duplicate code_id: {}",
            profile.code_id
        );
    }
}

// ---------------------------------------------------------------------------
// AppDb::categorize
// ---------------------------------------------------------------------------

#[test]
fn test_categorize_known_app() {
    let db = AppDb::load_builtin().expect("builtin profiles should load");
    assert_eq!(
        db.categorize("com.apple.Safari"),
        Some(AppCategory::Browser),
    );
    assert_eq!(
        db.categorize("com.tinyspeck.slackmacgap"),
        Some(AppCategory::Communication),
    );
    assert_eq!(
        db.categorize("com.valvesoftware.steam"),
        Some(AppCategory::Gaming),
    );
}

#[test]
fn test_categorize_unknown_app() {
    let db = AppDb::load_builtin().expect("builtin profiles should load");
    assert_eq!(db.categorize("com.random.unknownapp"), None);
}

// ---------------------------------------------------------------------------
// AppDb::apps_in
// ---------------------------------------------------------------------------

#[test]
fn test_apps_in_browser() {
    let db = AppDb::load_builtin().expect("builtin profiles should load");
    let browsers = db.apps_in(AppCategory::Browser);
    assert_eq!(browsers.len(), 4, "should have 4 browsers");
    let names: Vec<&str> = browsers.iter().map(|p| p.name.as_str()).collect();
    assert!(names.contains(&"Safari"));
    assert!(names.contains(&"Chrome"));
    assert!(names.contains(&"Firefox"));
    assert!(names.contains(&"Arc"));
}

#[test]
fn test_apps_in_covers_all_categories() {
    let db = AppDb::load_builtin().expect("builtin profiles should load");
    let total: usize = [
        AppCategory::Browser,
        AppCategory::Communication,
        AppCategory::Productivity,
        AppCategory::Media,
        AppCategory::Design,
        AppCategory::Development,
        AppCategory::Cloud,
        AppCategory::System,
        AppCategory::Security,
        AppCategory::Gaming,
        AppCategory::Utility,
    ]
    .iter()
    .map(|&cat| db.apps_in(cat).len())
    .sum();
    // Some profiles may have no category set, so total <= db.len().
    assert!(
        total <= db.len(),
        "categorized apps ({total}) should not exceed total ({})",
        db.len()
    );
}

// ---------------------------------------------------------------------------
// AppDb::expand_category
// ---------------------------------------------------------------------------

#[test]
fn test_expand_category_browser() {
    let db = AppDb::load_builtin().expect("builtin profiles should load");
    let ids = db.expand_category(AppCategory::Browser);
    assert_eq!(ids.len(), 4);
    assert!(ids.contains(&"com.apple.Safari".to_owned()));
    assert!(ids.contains(&"com.google.Chrome".to_owned()));
    assert!(ids.contains(&"org.mozilla.firefox".to_owned()));
    assert!(ids.contains(&"company.thebrowser.Browser".to_owned()));
}

#[test]
fn test_expand_empty_category() {
    let db = AppDb::from_sources(&[]).expect("empty db should load");
    let ids = db.expand_category(AppCategory::Browser);
    assert!(ids.is_empty());
}

// ---------------------------------------------------------------------------
// AppDb::lookup
// ---------------------------------------------------------------------------

#[test]
fn test_lookup_returns_full_profile() {
    let db = AppDb::load_builtin().expect("builtin profiles should load");
    let safari = db.lookup("com.apple.Safari").expect("Safari should exist");
    assert_eq!(safari.name, "Safari");
    assert_eq!(safari.developer.as_deref(), Some("Apple Inc."));
    assert_eq!(safari.category, Some(AppCategory::Browser));
}

#[test]
fn test_lookup_missing_returns_none() {
    let db = AppDb::load_builtin().expect("builtin profiles should load");
    assert!(db.lookup("com.nonexistent.app").is_none());
}

// ---------------------------------------------------------------------------
// AppCategory::Display
// ---------------------------------------------------------------------------

#[test]
fn test_app_category_display_all_variants() {
    assert_eq!(AppCategory::Browser.to_string(), "browser");
    assert_eq!(AppCategory::Communication.to_string(), "communication");
    assert_eq!(AppCategory::Productivity.to_string(), "productivity");
    assert_eq!(AppCategory::Media.to_string(), "media");
    assert_eq!(AppCategory::Design.to_string(), "design");
    assert_eq!(AppCategory::Development.to_string(), "development");
    assert_eq!(AppCategory::Cloud.to_string(), "cloud");
    assert_eq!(AppCategory::System.to_string(), "system");
    assert_eq!(AppCategory::Security.to_string(), "security");
    assert_eq!(AppCategory::Gaming.to_string(), "gaming");
    assert_eq!(AppCategory::Utility.to_string(), "utility");
}
