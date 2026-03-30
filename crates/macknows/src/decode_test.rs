use super::*;
use crate::category::Category;
use crate::testutil;
use tempfile::TempDir;

#[test]
fn test_decode_joins_config_and_state() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let config_conn = testutil::create_fixture_config_db(dir.path());
    let state_conn = testutil::create_fixture_state_db(dir.path());

    let records = decode(&config_conn, &state_conn).expect("decode failed");
    assert_eq!(records.len(), 2);

    // Find the app usage record
    let app = records
        .iter()
        .find(|r| r.transform_name == "AppUsage_Aggregate")
        .expect("missing app record");

    assert_eq!(app.category, Category::Apps);
    assert_eq!(app.config_type, "Main");
    assert!(app.config_enabled);
    assert_eq!(app.event_count, 42);
    assert_eq!(app.fields.len(), 4); // 2 dimensions + 2 measures
    assert_eq!(app.fields[0].0, "appDescription");
    assert_eq!(app.fields[0].1, "Safari.app");
    assert_eq!(app.fields[2].0, "sum_of_activeTime");
    assert_eq!(app.fields[2].1, 3600);
}

#[test]
fn test_decode_location_record() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let config_conn = testutil::create_fixture_config_db(dir.path());
    let state_conn = testutil::create_fixture_state_db(dir.path());

    let records = decode(&config_conn, &state_conn).expect("decode failed");

    let loc = records
        .iter()
        .find(|r| r.transform_name == "LocationVisits_Sample")
        .expect("missing location record");

    assert_eq!(loc.category, Category::Location);
    assert_eq!(loc.config_type, "OptOut");
    assert_eq!(loc.fields.len(), 2); // 1 dimension + 1 measure
    assert_eq!(loc.fields[0].0, "locationType");
    assert_eq!(loc.fields[0].1, "home");
    assert_eq!(loc.fields[1].0, "visitCount");
    assert_eq!(loc.fields[1].1, 5);
}

#[test]
fn test_decode_skips_unknown_uuid() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let config_conn = testutil::create_fixture_config_db(dir.path());

    // Create state DB with an unknown UUID
    let state_path = dir.path().join("state.sqlite");
    let state_conn = rusqlite::Connection::open(&state_path).expect("failed to create state db");
    state_conn
        .execute_batch(
            "CREATE TABLE transform_metadata (
                transform_metadata_id INTEGER PRIMARY KEY,
                transform_uuid TEXT NOT NULL,
                transform_event_count INTEGER NOT NULL
            );
            CREATE TABLE transform_states (
                transform_metadata_id INTEGER,
                transform_key TEXT NOT NULL,
                transform_value TEXT NOT NULL
            );
            INSERT INTO transform_metadata VALUES (1, 'nonexistent-uuid', 1);
            INSERT INTO transform_states VALUES (1, '[\"x\"]', '[1]');",
        )
        .expect("failed to setup state");

    let records = decode(&config_conn, &state_conn).expect("decode should not fail");
    assert!(records.is_empty(), "unknown UUID should be skipped");
}

#[test]
fn test_decode_handles_malformed_key_json() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let config_conn = testutil::create_fixture_config_db(dir.path());

    let state_path = dir.path().join("state.sqlite");
    let state_conn = rusqlite::Connection::open(&state_path).expect("failed to create state db");
    state_conn
        .execute_batch(
            "CREATE TABLE transform_metadata (
                transform_metadata_id INTEGER PRIMARY KEY,
                transform_uuid TEXT NOT NULL,
                transform_event_count INTEGER NOT NULL
            );
            CREATE TABLE transform_states (
                transform_metadata_id INTEGER,
                transform_key TEXT NOT NULL,
                transform_value TEXT NOT NULL
            );
            INSERT INTO transform_metadata VALUES (1, 'test-uuid-app-1', 1);
            INSERT INTO transform_states VALUES (1, 'not-json', '[1]');",
        )
        .expect("failed to setup state");

    let records = decode(&config_conn, &state_conn).expect("decode should not fail");
    assert!(records.is_empty(), "malformed JSON should be skipped");
}

#[test]
fn test_decode_handles_dimension_count_mismatch() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let config_conn = testutil::create_fixture_config_db(dir.path());

    let state_path = dir.path().join("state.sqlite");
    let state_conn = rusqlite::Connection::open(&state_path).expect("failed to create state db");
    state_conn
        .execute_batch(
            "CREATE TABLE transform_metadata (
                transform_metadata_id INTEGER PRIMARY KEY,
                transform_uuid TEXT NOT NULL,
                transform_event_count INTEGER NOT NULL
            );
            CREATE TABLE transform_states (
                transform_metadata_id INTEGER,
                transform_key TEXT NOT NULL,
                transform_value TEXT NOT NULL
            );
            INSERT INTO transform_metadata VALUES (1, 'test-uuid-app-1', 1);
            -- Only 1 key value but transform expects 2 dimensions
            INSERT INTO transform_states VALUES (1, '[\"Safari.app\"]', '[3600, 15]');",
        )
        .expect("failed to setup state");

    let records = decode(&config_conn, &state_conn).expect("decode should not fail");
    assert_eq!(records.len(), 1);
    // Should have 1 dimension (shorter) + 2 measures = 3 fields
    assert_eq!(records[0].fields.len(), 3);
}
