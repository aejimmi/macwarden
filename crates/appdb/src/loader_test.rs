use crate::db::AppDb;

#[test]
fn test_all_embedded_sources_parse() {
    // Verifies every file in APP_PROFILE_SOURCES is valid TOML
    // conforming to the AppProfile schema.
    let db = AppDb::from_sources(super::APP_PROFILE_SOURCES);
    assert!(
        db.is_ok(),
        "all embedded app profile sources must parse: {:?}",
        db.err()
    );
}

#[test]
fn test_source_count_matches_data_files() {
    // If you add a new TOML file to data/apps/ but forget to add an
    // include_str! line, this test should remind you (the count will
    // differ from what you expect). Update the expected count when
    // adding new apps.
    assert_eq!(
        super::APP_PROFILE_SOURCES.len(),
        20,
        "update this count when adding new app profiles"
    );
}
