//! Output formatting for terminal tables and JSON.

use crate::schema::{DecodedRecord, EventInfo, Summary};
use std::fmt::Write;
use tabled::{Table, settings::Style};

/// Format decoded records as a human-readable table grouped by category.
pub fn format_decode_table(records: &[DecodedRecord]) -> String {
    if records.is_empty() {
        return "No records found.".into();
    }

    let mut rows: Vec<[String; 5]> = Vec::with_capacity(records.len());
    for r in records {
        let event = r
            .event_names
            .first()
            .cloned()
            .unwrap_or_else(|| "(none)".into());
        let fields_str = format_fields(&r.fields);
        rows.push([
            r.category.to_string(),
            event,
            r.transform_name.clone(),
            r.config_type.clone(),
            fields_str,
        ]);
    }

    let header = ["Category", "Event", "Transform", "Config", "Fields"];
    let mut table_rows = vec![header.map(String::from)];
    table_rows.extend(rows);

    Table::new(table_rows).with(Style::rounded()).to_string()
}

/// Format decoded records as JSON.
pub fn format_decode_json(records: &[DecodedRecord]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(records)
}

/// Format a summary as a human-readable report.
pub fn format_summary(summary: &Summary) -> String {
    let mut out = String::with_capacity(2048);

    out.push_str("=== macknows Telemetry Summary ===\n\n");

    // write! to String is infallible, but we must handle the Result
    let _ = writeln!(out, "Total decoded records: {}", summary.total_records);
    let _ = writeln!(
        out,
        "OptOut records: {} (collected regardless of settings)",
        summary.opt_out_count
    );
    let _ = writeln!(out, "Main records: {}", summary.main_count);
    out.push('\n');

    // Category breakdown
    out.push_str("--- Records by Category ---\n");
    let cat_rows: Vec<[String; 2]> = summary
        .category_counts
        .iter()
        .map(|(cat, count)| [cat.to_string(), count.to_string()])
        .collect();

    if !cat_rows.is_empty() {
        let mut header_rows = vec![["Category".into(), "Records".into()]];
        header_rows.extend(cat_rows);
        let table = Table::new(header_rows).with(Style::rounded()).to_string();
        out.push_str(&table);
        out.push('\n');
    }

    // Collection periods
    if !summary.collection_periods.is_empty() {
        out.push_str("\n--- Collection Periods ---\n");
        for period in &summary.collection_periods {
            let start = &period.start_timestamp;
            let end = &period.end_boundary;
            let _ = writeln!(out, "  {} | {} -> {}", period.period_label(), start, end);
        }
    }

    // Top events
    if !summary.top_events.is_empty() {
        out.push_str("\n--- Top Events (by record count) ---\n");
        let top_rows: Vec<[String; 2]> = summary
            .top_events
            .iter()
            .map(|(name, count)| [name.clone(), count.to_string()])
            .collect();
        let mut header_rows = vec![["Event".into(), "Records".into()]];
        header_rows.extend(top_rows);
        let table = Table::new(header_rows).with(Style::rounded()).to_string();
        out.push_str(&table);
        out.push('\n');
    }

    // Queried device state
    if !summary.queried_states.is_empty() {
        out.push_str("\n--- Device State ---\n");
        let state_rows: Vec<[String; 2]> = summary
            .queried_states
            .iter()
            .map(|(k, v)| [k.clone(), v.clone()])
            .collect();
        let mut header_rows = vec![["Key".into(), "Value".into()]];
        header_rows.extend(state_rows);
        let table = Table::new(header_rows).with(Style::rounded()).to_string();
        out.push_str(&table);
        out.push('\n');
    }

    out
}

/// Format event info as a human-readable table.
pub fn format_events_table(events: &[EventInfo]) -> String {
    if events.is_empty() {
        return "No events found.".into();
    }

    let mut table_rows = vec![["Event".into(), "Category".into(), "Transforms".into()]];

    for e in events {
        table_rows.push([
            e.event_name.clone(),
            e.category.to_string(),
            e.transform_count.to_string(),
        ]);
    }

    Table::new(table_rows).with(Style::rounded()).to_string()
}

/// Format event info as JSON.
pub fn format_events_json(events: &[EventInfo]) -> serde_json::Result<String> {
    serde_json::to_string_pretty(events)
}

/// Format a vector of labeled fields as a compact display string.
fn format_fields(fields: &[(String, serde_json::Value)]) -> String {
    if fields.is_empty() {
        return "(empty)".into();
    }

    fields
        .iter()
        .map(|(name, val)| format!("{name}={}", format_value(val)))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Format a single JSON value for display, keeping it compact.
fn format_value(val: &serde_json::Value) -> String {
    match val {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
        _ => val.to_string(),
    }
}

/// Format a microsecond timestamp as a human-readable date string.
fn format_timestamp(microseconds: i64) -> String {
    // Convert microseconds to seconds
    let secs = microseconds / 1_000_000;
    // Basic UTC formatting without pulling in chrono
    let days_since_epoch = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;

    // Simple date calculation from days since Unix epoch
    let (year, month, day) = days_to_ymd(days_since_epoch);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02} UTC")
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    // Algorithm from http://howardhinnant.github.io/date_algorithms.html
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
#[path = "output_test.rs"]
mod output_test;
