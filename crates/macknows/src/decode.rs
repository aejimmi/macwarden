//! Join logic: cross-reference config transforms with state data to produce decoded records.

use crate::category::categorize;
use crate::db;
use crate::error::Result;
use crate::schema::{ConfigInfo, DecodedRecord, TransformDef};
use rusqlite::Connection;
use std::collections::HashMap;
use tracing::warn;

/// Assembled config-side data for a single transform, keyed by UUID.
struct TransformLookup {
    def: TransformDef,
    event_names: Vec<String>,
    config: ConfigInfo,
}

/// Decode all telemetry by joining config and state databases.
///
/// Loads transform definitions, event mappings, and config info from the config
/// database, then matches them against state rows via `transform_uuid`. Each
/// state row's key/value JSON arrays are zipped with the transform's
/// dimension/measure names to produce labeled fields.
pub fn decode(config_conn: &Connection, state_conn: &Connection) -> Result<Vec<DecodedRecord>> {
    let lookup = build_lookup(config_conn)?;
    let state_rows = db::load_transform_states(state_conn)?;

    let mut records = Vec::with_capacity(state_rows.len());

    for row in &state_rows {
        let Some(entry) = lookup.get(&row.transform_uuid) else {
            warn!(
                uuid = %row.transform_uuid,
                "state row references unknown transform UUID, skipping"
            );
            continue;
        };

        let fields = match zip_fields(entry, &row.transform_key, &row.transform_value) {
            Ok(f) => f,
            Err(e) => {
                warn!(
                    uuid = %row.transform_uuid,
                    error = %e,
                    "failed to decode fields, skipping record"
                );
                continue;
            }
        };

        let category = entry
            .event_names
            .first()
            .map_or(crate::category::Category::Other, |n| categorize(n));

        records.push(DecodedRecord {
            event_names: entry.event_names.clone(),
            transform_name: entry.def.name.clone(),
            category,
            config_type: entry.config.config_type.clone(),
            config_enabled: entry.config.config_enabled,
            fields,
            event_count: row.event_count,
        });
    }

    Ok(records)
}

/// Build the UUID-keyed lookup table from config.sqlite data.
fn build_lookup(config_conn: &Connection) -> Result<HashMap<String, TransformLookup>> {
    let defs = db::load_transform_defs(config_conn)?;
    let uuids = db::load_transform_uuids(config_conn)?;
    let event_names = db::load_event_names(config_conn)?;
    let transform_events = db::load_transform_events(config_conn)?;
    let config_info = db::load_config_info(config_conn)?;

    let mut lookup = HashMap::new();

    for (transform_id, def) in &defs {
        let Some(uuid) = uuids.get(transform_id) else {
            warn!(transform_id, "transform has no UUID mapping, skipping");
            continue;
        };
        let uuid = uuid.clone();

        let names: Vec<String> = transform_events
            .get(transform_id)
            .map(|eids| {
                eids.iter()
                    .filter_map(|eid| event_names.get(eid).cloned())
                    .collect()
            })
            .unwrap_or_default();

        let config = config_info
            .get(transform_id)
            .cloned()
            .unwrap_or(ConfigInfo {
                config_type: "Unknown".into(),
                config_enabled: false,
            });

        lookup.insert(
            uuid,
            TransformLookup {
                def: def.clone(),
                event_names: names,
                config,
            },
        );
    }

    Ok(lookup)
}

/// Zip dimension/measure names with key/value JSON arrays into labeled fields.
fn zip_fields(
    entry: &TransformLookup,
    key_json: &str,
    value_json: &str,
) -> std::result::Result<Vec<(String, serde_json::Value)>, String> {
    let keys: Vec<serde_json::Value> = match serde_json::from_str::<serde_json::Value>(key_json) {
        Ok(serde_json::Value::Array(arr)) => arr,
        Ok(serde_json::Value::Null) => Vec::new(),
        Ok(other) => vec![other],
        Err(e) => return Err(format!("invalid transform_key JSON: {e}")),
    };
    let values: Vec<serde_json::Value> = match serde_json::from_str::<serde_json::Value>(value_json)
    {
        Ok(serde_json::Value::Array(arr)) => arr,
        Ok(serde_json::Value::Null) => Vec::new(),
        Ok(other) => vec![other],
        Err(e) => return Err(format!("invalid transform_value JSON: {e}")),
    };

    let mut fields = Vec::new();

    // Zip dimensions with keys (shorter of the two)
    let dim_count = entry.def.dimensions.len().min(keys.len());
    for i in 0..dim_count {
        if let Some(dim) = entry.def.dimensions.get(i)
            && let Some(val) = keys.get(i)
        {
            fields.push((dim.name.clone(), val.clone()));
        }
    }

    // Zip measures with values (shorter of the two)
    let meas_count = entry.def.measures.len().min(values.len());
    for i in 0..meas_count {
        if let Some(meas) = entry.def.measures.get(i)
            && let Some(val) = values.get(i)
        {
            fields.push((meas.name.clone(), val.clone()));
        }
    }

    if entry.def.dimensions.len() != keys.len() {
        warn!(
            transform = %entry.def.name,
            dimensions = entry.def.dimensions.len(),
            keys = keys.len(),
            "dimension/key count mismatch, using shorter"
        );
    }

    if entry.def.measures.len() != values.len() {
        warn!(
            transform = %entry.def.name,
            measures = entry.def.measures.len(),
            values = values.len(),
            "measure/value count mismatch, using shorter"
        );
    }

    Ok(fields)
}

#[cfg(test)]
#[path = "decode_test.rs"]
mod decode_test;
