//! SQLite query functions for reading analyticsd databases.

use crate::category::categorize;
use crate::error::{MacknowsError, Result};
use crate::schema::{CollectionPeriod, ConfigInfo, EventInfo, TransformDef, TransformStateRow};
use rusqlite::Connection;
use std::collections::HashMap;
use tracing::warn;

/// Load all transform definitions from config.sqlite.
///
/// Returns a map of `transform_id` to the parsed [`TransformDef`].
/// Malformed JSON in `transform_def` is logged and skipped.
pub fn load_transform_defs(conn: &Connection) -> Result<HashMap<i64, TransformDef>> {
    let mut stmt = conn
        .prepare("SELECT transform_id, transform_def FROM transforms")
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "prepare transforms query".into(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let def_json: String = row.get(1)?;
            Ok((id, def_json))
        })
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "query transforms".into(),
        })?;

    let mut defs = HashMap::new();
    for row in rows {
        let (id, def_json) = row.map_err(|e| MacknowsError::Query {
            source: e,
            context: "read transform row".into(),
        })?;

        match serde_json::from_str::<TransformDef>(&def_json) {
            Ok(def) => {
                defs.insert(id, def);
            }
            Err(e) => {
                warn!(
                    transform_id = id,
                    error = %e,
                    "skipping transform with malformed JSON definition"
                );
            }
        }
    }
    Ok(defs)
}

/// Load the transform_uuid for each transform_id from config.sqlite.
///
/// Returns a map of `transform_id` to `transform_uuid`.
pub fn load_transform_uuids(conn: &Connection) -> Result<HashMap<i64, String>> {
    let mut stmt = conn
        .prepare("SELECT transform_id, transform_uuid FROM transforms")
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "prepare transform_uuid query".into(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let uuid: String = row.get(1)?;
            Ok((id, uuid))
        })
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "query transform_uuids".into(),
        })?;

    let mut map = HashMap::new();
    for row in rows {
        let (id, uuid) = row.map_err(|e| MacknowsError::Query {
            source: e,
            context: "read transform_uuid row".into(),
        })?;
        map.insert(id, uuid);
    }
    Ok(map)
}

/// Load event_id -> event_name mappings from config.sqlite.
pub fn load_event_names(conn: &Connection) -> Result<HashMap<i64, String>> {
    let mut stmt = conn
        .prepare("SELECT event_id, event_name FROM events")
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "prepare events query".into(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            let id: i64 = row.get(0)?;
            let name: String = row.get(1)?;
            Ok((id, name))
        })
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "query events".into(),
        })?;

    let mut map = HashMap::new();
    for row in rows {
        let (id, name) = row.map_err(|e| MacknowsError::Query {
            source: e,
            context: "read event row".into(),
        })?;
        map.insert(id, name);
    }
    Ok(map)
}

/// Load transform_id -> Vec<event_id> mappings from config.sqlite.
pub fn load_transform_events(conn: &Connection) -> Result<HashMap<i64, Vec<i64>>> {
    let mut stmt = conn
        .prepare("SELECT event_id, transform_id FROM transform_events")
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "prepare transform_events query".into(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            let event_id: i64 = row.get(0)?;
            let transform_id: i64 = row.get(1)?;
            Ok((event_id, transform_id))
        })
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "query transform_events".into(),
        })?;

    let mut map: HashMap<i64, Vec<i64>> = HashMap::new();
    for row in rows {
        let (event_id, transform_id) = row.map_err(|e| MacknowsError::Query {
            source: e,
            context: "read transform_event row".into(),
        })?;
        map.entry(transform_id).or_default().push(event_id);
    }
    Ok(map)
}

/// Load config info (type + enabled) per transform_id from config.sqlite.
///
/// Joins `config_transforms` with `configs` to get config metadata.
pub fn load_config_info(conn: &Connection) -> Result<HashMap<i64, ConfigInfo>> {
    let mut stmt = conn
        .prepare(
            "SELECT ct.transform_id, c.config_type, c.config_enabled \
             FROM config_transforms ct \
             JOIN configs c ON ct.config_id = c.config_id",
        )
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "prepare config_info query".into(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            let transform_id: i64 = row.get(0)?;
            let config_type: String = row.get(1)?;
            let config_enabled: bool = row.get(2)?;
            Ok((transform_id, config_type, config_enabled))
        })
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "query config_info".into(),
        })?;

    let mut map = HashMap::new();
    for row in rows {
        let (tid, ctype, enabled) = row.map_err(|e| MacknowsError::Query {
            source: e,
            context: "read config_info row".into(),
        })?;
        map.insert(
            tid,
            ConfigInfo {
                config_type: ctype,
                config_enabled: enabled,
            },
        );
    }
    Ok(map)
}

/// Load all transform state rows from state.sqlite.
pub fn load_transform_states(conn: &Connection) -> Result<Vec<TransformStateRow>> {
    let mut stmt = conn
        .prepare(
            "SELECT tm.transform_uuid, ts.transform_key, ts.transform_value, \
                    tm.transform_event_count \
             FROM transform_states ts \
             JOIN transform_metadata tm \
               ON ts.transform_metadata_id = tm.transform_metadata_id",
        )
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "prepare transform_states query".into(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(TransformStateRow {
                transform_uuid: row.get(0)?,
                transform_key: row.get(1)?,
                transform_value: row.get(2)?,
                event_count: row.get::<_, i64>(3).map(|v| v as u64)?,
            })
        })
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "query transform_states".into(),
        })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| MacknowsError::Query {
            source: e,
            context: "read transform_state row".into(),
        })?);
    }
    Ok(result)
}

/// Load all events with transform counts from config.sqlite, for the `events` subcommand.
pub fn load_events_with_counts(conn: &Connection) -> Result<Vec<EventInfo>> {
    let mut stmt = conn
        .prepare(
            "SELECT e.event_name, COUNT(te.transform_id) as tc \
             FROM events e \
             LEFT JOIN transform_events te ON e.event_id = te.event_id \
             GROUP BY e.event_id \
             ORDER BY tc DESC",
        )
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "prepare events_with_counts query".into(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            let name: String = row.get(0)?;
            let count: u32 = row.get(1)?;
            Ok((name, count))
        })
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "query events_with_counts".into(),
        })?;

    let mut result = Vec::new();
    for row in rows {
        let (name, count) = row.map_err(|e| MacknowsError::Query {
            source: e,
            context: "read event_with_count row".into(),
        })?;
        let category = categorize(&name);
        result.push(EventInfo {
            event_name: name,
            category,
            transform_count: count,
        });
    }
    Ok(result)
}

/// Load queried device state key-value pairs from state.sqlite.
pub fn load_queried_states(conn: &Connection) -> Result<Vec<(String, String)>> {
    let has_table = table_exists(conn, "queried_states")?;
    if !has_table {
        return Ok(Vec::new());
    }

    let mut stmt = conn
        .prepare("SELECT queried_state_name, queried_state_value FROM queried_states")
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "prepare queried_states query".into(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            let key: String = row.get(0)?;
            let val: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
            Ok((key, val))
        })
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "query queried_states".into(),
        })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| MacknowsError::Query {
            source: e,
            context: "read queried_state row".into(),
        })?);
    }
    Ok(result)
}

/// Load aggregation session periods from state.sqlite.
pub fn load_agg_sessions(conn: &Connection) -> Result<Vec<CollectionPeriod>> {
    let has_table = table_exists(conn, "agg_session")?;
    if !has_table {
        return Ok(Vec::new());
    }

    let mut stmt = conn
        .prepare(
            "SELECT agg_session_start_timestamp, agg_session_end_boundary, \
                    agg_session_period \
             FROM agg_session \
             ORDER BY agg_session_start_timestamp",
        )
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "prepare agg_session query".into(),
        })?;

    let rows = stmt
        .query_map([], |row| {
            Ok(CollectionPeriod {
                start_timestamp: row.get(0)?,
                end_boundary: row.get(1)?,
                period_type: row.get(2)?,
            })
        })
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: "query agg_session".into(),
        })?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.map_err(|e| MacknowsError::Query {
            source: e,
            context: "read agg_session row".into(),
        })?);
    }
    Ok(result)
}

/// Check whether a table exists in the database.
fn table_exists(conn: &Connection, table_name: &str) -> Result<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
            [table_name],
            |row| row.get(0),
        )
        .map_err(|e| MacknowsError::Query {
            source: e,
            context: format!("check table existence: {table_name}"),
        })?;
    Ok(count > 0)
}

#[cfg(test)]
#[path = "db_test.rs"]
mod db_test;
