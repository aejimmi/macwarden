//! Types for representing analyticsd database contents.

use crate::category::Category;
use serde::{Deserialize, Serialize};

/// A transform definition parsed from the `transform_def` JSON column in config.sqlite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransformDef {
    /// Human-readable name of the transform (e.g. "AppUsage_Aggregate").
    pub name: String,
    /// Unique identifier matching state.sqlite entries.
    #[serde(default)]
    pub uuid: String,
    /// Transform type (e.g. "aggregate", "sample").
    #[serde(rename = "type", default)]
    pub transform_type: String,
    /// Dimension columns — keys in the aggregation.
    #[serde(default)]
    pub dimensions: Vec<Dimension>,
    /// Measure columns — aggregated values.
    #[serde(default)]
    pub measures: Vec<Measure>,
}

/// A dimension (grouping key) within a transform definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dimension {
    /// Column name for this dimension.
    pub name: String,
    /// Data type (e.g. "string", "int").
    #[serde(rename = "type", default)]
    pub dim_type: String,
}

/// A measure (aggregated value) within a transform definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Measure {
    /// Column name for this measure.
    pub name: String,
    /// Aggregation function (e.g. "sum", "count").
    #[serde(default)]
    pub function: String,
    /// Data type (e.g. "int", "float").
    #[serde(rename = "type", default)]
    pub value_type: String,
}

/// A decoded telemetry record produced by joining config and state databases.
#[derive(Debug, Clone, Serialize)]
pub struct DecodedRecord {
    /// Event names associated with this transform.
    pub event_names: Vec<String>,
    /// Name of the transform that produced this record.
    pub transform_name: String,
    /// Telemetry category derived from event name.
    pub category: Category,
    /// Config type: "OptOut" or "Main".
    pub config_type: String,
    /// Whether the config was enabled.
    pub config_enabled: bool,
    /// Labeled field values: dimension names + measure names zipped with their values.
    pub fields: Vec<(String, serde_json::Value)>,
    /// Number of events aggregated into this record.
    pub event_count: u64,
}

/// Config metadata associated with a transform.
#[derive(Debug, Clone, Serialize)]
pub struct ConfigInfo {
    /// Config type: "OptOut" or "Main".
    pub config_type: String,
    /// Whether the config is enabled.
    pub config_enabled: bool,
}

/// Information about an event type from config.sqlite.
#[derive(Debug, Clone, Serialize)]
pub struct EventInfo {
    /// Fully qualified event name.
    pub event_name: String,
    /// Category derived from the event name.
    pub category: Category,
    /// Number of transforms associated with this event.
    pub transform_count: u32,
}

/// High-level summary of collected telemetry.
#[derive(Debug, Clone, Serialize)]
pub struct Summary {
    /// Number of decoded records per category.
    pub category_counts: Vec<(Category, usize)>,
    /// Number of records from OptOut configs.
    pub opt_out_count: usize,
    /// Number of records from Main configs.
    pub main_count: usize,
    /// Total decoded records.
    pub total_records: usize,
    /// Top events by record count.
    pub top_events: Vec<(String, usize)>,
    /// Collection time periods from agg_session.
    pub collection_periods: Vec<CollectionPeriod>,
    /// Device state key-value pairs from queried_states.
    pub queried_states: Vec<(String, String)>,
}

/// A collection time period from the agg_session table.
#[derive(Debug, Clone, Serialize)]
pub struct CollectionPeriod {
    /// Start timestamp (ISO text, e.g. "2026-03-30T00:09:02").
    pub start_timestamp: String,
    /// End boundary timestamp (ISO text).
    pub end_boundary: String,
    /// Period type: 0=daily, 1=weekly, 2=monthly, 3=quarterly.
    pub period_type: i64,
}

impl CollectionPeriod {
    /// Returns a human-readable label for the period type.
    pub fn period_label(&self) -> &'static str {
        match self.period_type {
            0 => "daily",
            1 => "weekly",
            2 => "monthly",
            3 => "quarterly",
            _ => "unknown",
        }
    }
}

/// A raw row from the transform_states table before decoding.
#[derive(Debug, Clone)]
pub struct TransformStateRow {
    /// The transform UUID linking to config.sqlite.
    pub transform_uuid: String,
    /// JSON array of dimension values.
    pub transform_key: String,
    /// JSON array of measure values.
    pub transform_value: String,
    /// Number of events aggregated.
    pub event_count: u64,
}
