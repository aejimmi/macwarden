//! Test fixture utilities for creating in-memory or on-disk SQLite databases.

use rusqlite::Connection;
use std::path::Path;

/// Create a config.sqlite fixture with known test data at the given path.
///
/// Contains 2 events, 2 transforms, and associated mappings.
pub fn create_fixture_config_db(dir: &Path) -> Connection {
    let path = dir.join("config.sqlite");
    let conn = Connection::open(&path).expect("failed to create fixture config db");

    conn.execute_batch(
        "CREATE TABLE events (
            event_id INTEGER PRIMARY KEY,
            event_name TEXT NOT NULL
        );
        CREATE TABLE transforms (
            transform_id INTEGER PRIMARY KEY,
            transform_uuid TEXT NOT NULL,
            transform_def TEXT NOT NULL,
            sampling_id INTEGER
        );
        CREATE TABLE transform_events (
            event_id INTEGER,
            transform_id INTEGER
        );
        CREATE TABLE configs (
            config_id INTEGER PRIMARY KEY,
            config_uuid TEXT,
            config_type TEXT NOT NULL,
            config_enabled INTEGER NOT NULL,
            config_header TEXT
        );
        CREATE TABLE config_transforms (
            config_id INTEGER,
            transform_id INTEGER
        );",
    )
    .expect("failed to create config schema");

    // Insert events
    conn.execute_batch(
        "INSERT INTO events (event_id, event_name) VALUES
            (1, 'com.apple.osanalytics.appUsage'),
            (2, 'com.apple.locationd.visits');",
    )
    .expect("failed to insert events");

    // Insert transforms with JSON definitions
    let app_def = serde_json::json!({
        "name": "AppUsage_Aggregate",
        "type": "aggregate",
        "uuid": "test-uuid-app-1",
        "dimensions": [
            {"name": "appDescription", "type": "string"},
            {"name": "foreground", "type": "string"}
        ],
        "measures": [
            {"name": "sum_of_activeTime", "function": "sum", "type": "int"},
            {"name": "Count", "function": "count", "type": "int"}
        ]
    });

    let loc_def = serde_json::json!({
        "name": "LocationVisits_Sample",
        "type": "sample",
        "uuid": "test-uuid-loc-1",
        "dimensions": [
            {"name": "locationType", "type": "string"}
        ],
        "measures": [
            {"name": "visitCount", "function": "sum", "type": "int"}
        ]
    });

    conn.execute(
        "INSERT INTO transforms (transform_id, transform_uuid, transform_def) VALUES (?1, ?2, ?3)",
        rusqlite::params![1, "test-uuid-app-1", app_def.to_string()],
    )
    .expect("failed to insert app transform");

    conn.execute(
        "INSERT INTO transforms (transform_id, transform_uuid, transform_def) VALUES (?1, ?2, ?3)",
        rusqlite::params![2, "test-uuid-loc-1", loc_def.to_string()],
    )
    .expect("failed to insert loc transform");

    // Map events to transforms
    conn.execute_batch(
        "INSERT INTO transform_events (event_id, transform_id) VALUES (1, 1);
         INSERT INTO transform_events (event_id, transform_id) VALUES (2, 2);",
    )
    .expect("failed to insert transform_events");

    // Insert configs
    conn.execute_batch(
        "INSERT INTO configs (config_id, config_uuid, config_type, config_enabled) VALUES
            (1, 'config-main-1', 'Main', 1),
            (2, 'config-optout-1', 'OptOut', 1);
         INSERT INTO config_transforms (config_id, transform_id) VALUES
            (1, 1),
            (2, 2);",
    )
    .expect("failed to insert configs");

    conn
}

/// Create a state.sqlite fixture with known test data at the given path.
///
/// Contains matching state rows for the config fixture transforms.
pub fn create_fixture_state_db(dir: &Path) -> Connection {
    let path = dir.join("state.sqlite");
    let conn = Connection::open(&path).expect("failed to create fixture state db");

    conn.execute_batch(
        "CREATE TABLE transform_metadata (
            transform_metadata_id INTEGER PRIMARY KEY,
            transform_uuid TEXT NOT NULL,
            transform_event_count INTEGER NOT NULL,
            rollover_session_id INTEGER,
            agg_session_id INTEGER
        );
        CREATE TABLE transform_states (
            transform_metadata_id INTEGER,
            transform_key TEXT NOT NULL,
            transform_value TEXT NOT NULL,
            rollover_session_id INTEGER
        );
        CREATE TABLE agg_session (
            agg_session_start_timestamp TEXT,
            agg_session_end_boundary TEXT,
            agg_session_period INTEGER
        );
        CREATE TABLE queried_states (
            queried_state_name TEXT NOT NULL,
            queried_state_value TEXT
        );",
    )
    .expect("failed to create state schema");

    // Insert metadata matching config UUIDs
    conn.execute_batch(
        "INSERT INTO transform_metadata
            (transform_metadata_id, transform_uuid, transform_event_count)
         VALUES
            (1, 'test-uuid-app-1', 42),
            (2, 'test-uuid-loc-1', 7);",
    )
    .expect("failed to insert transform_metadata");

    // Insert state rows with JSON arrays
    conn.execute(
        "INSERT INTO transform_states (transform_metadata_id, transform_key, transform_value) \
         VALUES (?1, ?2, ?3)",
        rusqlite::params![1, r#"["Safari.app","true"]"#, r#"[3600, 15]"#,],
    )
    .expect("failed to insert app state");

    conn.execute(
        "INSERT INTO transform_states (transform_metadata_id, transform_key, transform_value) \
         VALUES (?1, ?2, ?3)",
        rusqlite::params![2, r#"["home"]"#, r#"[5]"#,],
    )
    .expect("failed to insert loc state");

    // Insert agg_session
    conn.execute_batch(
        "INSERT INTO agg_session
            (agg_session_start_timestamp, agg_session_end_boundary, agg_session_period)
         VALUES
            ('2026-03-30T00:09:02', '2026-03-31T00:00:00', 0);",
    )
    .expect("failed to insert agg_session");

    // Insert queried_states
    conn.execute_batch(
        "INSERT INTO queried_states (queried_state_name, queried_state_value) VALUES
            ('lowPowerModeEnabled', 'false'),
            ('wiFiRadioTech', '11AX');",
    )
    .expect("failed to insert queried_states");

    conn
}
