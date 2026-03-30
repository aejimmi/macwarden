//! macknows — Apple telemetry decoder library.
//!
//! Reads the analyticsd SQLite databases (`config.sqlite` and `state.sqlite`)
//! and cross-references transform definitions with collected state data to
//! produce labeled, categorized, human-readable telemetry records.
//!
//! # Usage
//!
//! ```no_run
//! use std::path::Path;
//!
//! let config = Path::new("/private/var/db/analyticsd/config.sqlite");
//! let state = Path::new("/private/var/db/analyticsd/state.sqlite");
//!
//! let records = macknows::decode_databases(config, state).unwrap();
//! let events = macknows::list_events(config).unwrap();
//! let summary = macknows::summary(config, state).unwrap();
//! ```

pub mod category;
pub mod db;
pub mod decode;
pub mod error;
pub mod output;
pub mod schema;

#[cfg(test)]
mod testutil;

use crate::error::{MacknowsError, Result};
use crate::schema::{DecodedRecord, EventInfo, Summary};
use rusqlite::Connection;
use std::collections::HashMap;
use std::path::Path;
use tracing::warn;

/// Decode all collected telemetry from the analyticsd databases.
///
/// Opens both databases read-only, copies them to a temporary directory to
/// avoid WAL lock contention, then joins config transforms with state data.
pub fn decode_databases(config_path: &Path, state_path: &Path) -> Result<Vec<DecodedRecord>> {
    let (config_conn, state_conn, _tmpdir) = open_databases(config_path, state_path)?;
    decode::decode(&config_conn, &state_conn)
}

/// List all event types from config.sqlite with categories and transform counts.
pub fn list_events(config_path: &Path) -> Result<Vec<EventInfo>> {
    let (config_conn, _tmpdir) = open_single_db(config_path)?;
    db::load_events_with_counts(&config_conn)
}

/// Generate a high-level summary of collected telemetry.
pub fn summary(config_path: &Path, state_path: &Path) -> Result<Summary> {
    let (config_conn, state_conn, _tmpdir) = open_databases(config_path, state_path)?;
    let records = decode::decode(&config_conn, &state_conn)?;

    let mut category_counts: HashMap<crate::category::Category, usize> = HashMap::new();
    let mut event_counts: HashMap<String, usize> = HashMap::new();
    let mut opt_out_count = 0usize;
    let mut main_count = 0usize;

    for r in &records {
        *category_counts.entry(r.category).or_default() += 1;
        if let Some(name) = r.event_names.first() {
            *event_counts.entry(name.clone()).or_default() += 1;
        }
        match r.config_type.as_str() {
            "OptOut" => opt_out_count += 1,
            _ => main_count += 1,
        }
    }

    let mut cat_vec: Vec<_> = category_counts.into_iter().collect();
    cat_vec.sort_by(|a, b| b.1.cmp(&a.1));

    let mut top_events: Vec<_> = event_counts.into_iter().collect();
    top_events.sort_by(|a, b| b.1.cmp(&a.1));
    top_events.truncate(20);

    let collection_periods = db::load_agg_sessions(&state_conn)?;
    let queried_states = db::load_queried_states(&state_conn)?;

    Ok(Summary {
        category_counts: cat_vec,
        opt_out_count,
        main_count,
        total_records: records.len(),
        top_events,
        collection_periods,
        queried_states,
    })
}

/// Open both databases by copying to a temp directory first.
///
/// Returns the connections and the [`tempfile::TempDir`] guard — the temp
/// directory is deleted when the guard is dropped, so the caller must hold it.
fn open_databases(
    config_path: &Path,
    state_path: &Path,
) -> Result<(Connection, Connection, tempfile::TempDir)> {
    validate_path(config_path)?;
    validate_path(state_path)?;

    let tmpdir = tempfile::TempDir::new().map_err(|e| MacknowsError::Io { source: e })?;

    let config_copy = tmpdir.path().join("config.sqlite");
    let state_copy = tmpdir.path().join("state.sqlite");

    std::fs::copy(config_path, &config_copy)?;
    std::fs::copy(state_path, &state_copy)?;

    // Also copy WAL/SHM files if they exist (for consistency)
    copy_if_exists(config_path, "config.sqlite-wal", tmpdir.path());
    copy_if_exists(config_path, "config.sqlite-shm", tmpdir.path());
    copy_if_exists(state_path, "state.sqlite-wal", tmpdir.path());
    copy_if_exists(state_path, "state.sqlite-shm", tmpdir.path());

    let config_conn =
        Connection::open_with_flags(&config_copy, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| MacknowsError::DatabaseOpen {
                source: e,
                path: config_path.to_path_buf(),
            })?;

    let state_conn =
        Connection::open_with_flags(&state_copy, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
            .map_err(|e| MacknowsError::DatabaseOpen {
                source: e,
                path: state_path.to_path_buf(),
            })?;

    Ok((config_conn, state_conn, tmpdir))
}

/// Open a single database by copying to a temp directory first.
fn open_single_db(db_path: &Path) -> Result<(Connection, tempfile::TempDir)> {
    validate_path(db_path)?;

    let tmpdir = tempfile::TempDir::new().map_err(|e| MacknowsError::Io { source: e })?;

    let file_name = db_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("db.sqlite"));
    let copy_path = tmpdir.path().join(file_name);
    std::fs::copy(db_path, &copy_path)?;

    let conn = Connection::open_with_flags(&copy_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| MacknowsError::DatabaseOpen {
            source: e,
            path: db_path.to_path_buf(),
        })?;

    Ok((conn, tmpdir))
}

/// Validate that a database file exists.
fn validate_path(path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(MacknowsError::DatabaseNotFound {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

/// Copy a sibling file (WAL/SHM) if it exists next to the source database.
fn copy_if_exists(db_path: &Path, sibling_name: &str, dest_dir: &Path) {
    if let Some(parent) = db_path.parent() {
        let sibling = parent.join(sibling_name);
        if sibling.exists()
            && let Err(e) = std::fs::copy(&sibling, dest_dir.join(sibling_name))
        {
            warn!(
                path = %sibling.display(),
                error = %e,
                "failed to copy WAL/SHM sibling file (non-fatal)"
            );
        }
    }
}
