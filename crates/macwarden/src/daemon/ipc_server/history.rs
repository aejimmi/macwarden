//! History buckets (R5) answered from the metrics store.
//!
//! `Hour`/`Today` scope to `TimeRange::last_hours(1)`/`TimeRange::today()`;
//! `Session` scopes to the window since the daemon started — an honest
//! "this session" range rather than a session-only in-memory counter. Byte
//! totals come from the persisted `BandwidthSampled` signal so Hour/Today
//! survive daemon restarts. One coarse bucket spans the whole range; the DTO's
//! start/end fields let this grow into finer buckets without a protocol break.

use ipc::protocol::{HistoryBucket, HistoryScope};
use metrics::{MetricsStore, TimeRange};

use super::error::{Result, ServerError};

/// Build the history buckets for a scope, optionally scoped to one app.
///
/// `session_start_ms` is the daemon's start time in unix milliseconds, used for
/// the `Session` scope.
pub fn build_history(
    store: &MetricsStore,
    scope: HistoryScope,
    app_id: Option<&str>,
    session_start_ms: i64,
) -> Result<Vec<HistoryBucket>> {
    let range = range_for(scope, session_start_ms);
    let bucket = match app_id {
        Some(id) => app_bucket(store, id, &range)?,
        None => rollup_bucket(store, &range)?,
    };
    Ok(vec![bucket])
}

/// Resolve the scope to a metrics [`TimeRange`].
fn range_for(scope: HistoryScope, session_start_ms: i64) -> TimeRange {
    match scope {
        HistoryScope::Hour => TimeRange::last_hours(1),
        HistoryScope::Today => TimeRange::today(),
        HistoryScope::Session => {
            let now = now_ms();
            TimeRange::new(session_start_ms.min(now), now).unwrap_or_else(|_| TimeRange::today())
        }
    }
}

/// Machine-wide rollup bucket.
fn rollup_bucket(store: &MetricsStore, range: &TimeRange) -> Result<HistoryBucket> {
    let summary = store
        .summary(range)
        .map_err(|e| ServerError::Metrics(e.to_string()))?;
    let connections =
        summary.connections_allowed + summary.connections_denied + summary.connections_logged;
    let tracker_hits: u64 = summary.tracker_hits_by_category.values().copied().sum();

    let bandwidth = store
        .bandwidth_by_app(range)
        .map_err(|e| ServerError::Metrics(e.to_string()))?;
    let down_bytes: u64 = bandwidth.iter().map(|b| b.down_bytes).sum();
    let up_bytes: u64 = bandwidth.iter().map(|b| b.up_bytes).sum();

    Ok(HistoryBucket {
        start_ms: range.start.max(0) as u64,
        end_ms: range.end.max(0) as u64,
        app_id: None,
        connections,
        denied: summary.connections_denied,
        tracker_hits,
        down_bytes,
        up_bytes,
    })
}

/// Per-app bucket.
fn app_bucket(store: &MetricsStore, app_id: &str, range: &TimeRange) -> Result<HistoryBucket> {
    let stats = store
        .app_stats(app_id, range)
        .map_err(|e| ServerError::Metrics(e.to_string()))?;
    let tracker_hits = (stats.tracker_hit_rate * stats.connection_count as f64).round() as u64;

    let bandwidth = store
        .bandwidth_for_app(app_id, range)
        .map_err(|e| ServerError::Metrics(e.to_string()))?;

    Ok(HistoryBucket {
        start_ms: range.start.max(0) as u64,
        end_ms: range.end.max(0) as u64,
        app_id: Some(app_id.to_owned()),
        connections: stats.connection_count,
        denied: stats.denied_count,
        tracker_hits,
        down_bytes: bandwidth.down_bytes,
        up_bytes: bandwidth.up_bytes,
    })
}

/// Current unix time in milliseconds.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
#[path = "history_test.rs"]
mod history_test;
