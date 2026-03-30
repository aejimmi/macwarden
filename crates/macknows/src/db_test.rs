use super::*;
use crate::testutil;
use tempfile::TempDir;

#[test]
fn test_load_transform_defs_parses_valid_json() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let conn = testutil::create_fixture_config_db(dir.path());

    let defs = load_transform_defs(&conn).expect("failed to load transforms");
    assert_eq!(defs.len(), 2);

    let app = defs.get(&1).expect("missing transform_id 1");
    assert_eq!(app.name, "AppUsage_Aggregate");
    assert_eq!(app.dimensions.len(), 2);
    assert_eq!(app.measures.len(), 2);
    assert_eq!(app.dimensions[0].name, "appDescription");
    assert_eq!(app.measures[0].name, "sum_of_activeTime");
}

#[test]
fn test_load_transform_defs_skips_malformed_json() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let conn = testutil::create_fixture_config_db(dir.path());

    // Insert a row with bad JSON
    conn.execute(
        "INSERT INTO transforms (transform_id, transform_uuid, transform_def) VALUES (?1, ?2, ?3)",
        rusqlite::params![99, "bad-uuid", "not valid json"],
    )
    .expect("failed to insert bad transform");

    let defs = load_transform_defs(&conn).expect("should not fail");
    // The 2 valid ones still load, the bad one is skipped
    assert_eq!(defs.len(), 2);
    assert!(!defs.contains_key(&99));
}

#[test]
fn test_load_event_names() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let conn = testutil::create_fixture_config_db(dir.path());

    let names = load_event_names(&conn).expect("failed to load events");
    assert_eq!(names.len(), 2);
    assert_eq!(
        names.get(&1).expect("missing event 1"),
        "com.apple.osanalytics.appUsage"
    );
    assert_eq!(
        names.get(&2).expect("missing event 2"),
        "com.apple.locationd.visits"
    );
}

#[test]
fn test_load_transform_events() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let conn = testutil::create_fixture_config_db(dir.path());

    let te = load_transform_events(&conn).expect("failed to load transform_events");
    assert_eq!(te.len(), 2);
    assert_eq!(te.get(&1).expect("missing transform 1"), &vec![1i64]);
    assert_eq!(te.get(&2).expect("missing transform 2"), &vec![2i64]);
}

#[test]
fn test_load_config_info() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let conn = testutil::create_fixture_config_db(dir.path());

    let ci = load_config_info(&conn).expect("failed to load config_info");
    assert_eq!(ci.len(), 2);

    let main = ci.get(&1).expect("missing config for transform 1");
    assert_eq!(main.config_type, "Main");
    assert!(main.config_enabled);

    let optout = ci.get(&2).expect("missing config for transform 2");
    assert_eq!(optout.config_type, "OptOut");
}

#[test]
fn test_load_transform_states() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let conn = testutil::create_fixture_state_db(dir.path());

    let states = load_transform_states(&conn).expect("failed to load states");
    assert_eq!(states.len(), 2);
    assert_eq!(states[0].transform_uuid, "test-uuid-app-1");
    assert_eq!(states[0].event_count, 42);
}

#[test]
fn test_load_queried_states() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let conn = testutil::create_fixture_state_db(dir.path());

    let qs = load_queried_states(&conn).expect("failed to load queried_states");
    assert_eq!(qs.len(), 2);
    assert_eq!(qs[0].0, "lowPowerModeEnabled");
    assert_eq!(qs[0].1, "false");
}

#[test]
fn test_load_agg_sessions() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let conn = testutil::create_fixture_state_db(dir.path());

    let sessions = load_agg_sessions(&conn).expect("failed to load agg_sessions");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].period_type, 0);
    assert_eq!(sessions[0].period_label(), "daily");
}

#[test]
fn test_load_queried_states_missing_table() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let path = dir.path().join("empty.sqlite");
    let conn = Connection::open(&path).expect("failed to create db");

    let qs = load_queried_states(&conn).expect("should handle missing table");
    assert!(qs.is_empty());
}

#[test]
fn test_load_events_with_counts() {
    let dir = TempDir::new().expect("failed to create tempdir");
    let conn = testutil::create_fixture_config_db(dir.path());

    let events = load_events_with_counts(&conn).expect("failed to load events");
    assert_eq!(events.len(), 2);

    // Both events have 1 transform each
    for e in &events {
        assert_eq!(e.transform_count, 1);
    }
}
