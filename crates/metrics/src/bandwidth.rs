//! Per-app bandwidth aggregation over `BandwidthSampled` events.
//!
//! Split from `store.rs` to keep that file under the 500-line limit. As a
//! child module of `store` it can reach the private `MetricsStore::conn`
//! handle and the shared `collect_rows` helper.

use rusqlite::params;

use super::{MetricsStore, TimeRange, collect_rows};
use crate::error::{MetricsError, Result};

/// Total bytes transferred by a single app over a time range.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AppBandwidth {
    /// App identity (code signing identifier).
    pub app_id: String,
    /// Bytes received, summed over all samples in range.
    pub down_bytes: u64,
    /// Bytes sent, summed over all samples in range.
    pub up_bytes: u64,
}

impl MetricsStore {
    /// Total down/up bytes per app from `BandwidthSampled` events in `range`.
    ///
    /// One row per app that has at least one sample in the window, ordered by
    /// download volume descending. Returns an empty vector when no samples fall
    /// in the range.
    pub fn bandwidth_by_app(&self, range: &TimeRange) -> Result<Vec<AppBandwidth>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT app_id, \
                        SUM(json_extract(payload, '$.down_bytes')) as down, \
                        SUM(json_extract(payload, '$.up_bytes')) as up \
                 FROM events \
                 WHERE kind = 'bandwidth_sampled' AND app_id IS NOT NULL \
                 AND ts >= ?1 AND ts < ?2 \
                 GROUP BY app_id ORDER BY down DESC",
            )
            .map_err(|e| MetricsError::Query {
                operation: "bandwidth_by_app".into(),
                source: e,
            })?;

        let rows = stmt
            .query_map(params![range.start, range.end], |row| {
                Ok(AppBandwidth {
                    app_id: row.get(0)?,
                    down_bytes: row.get(1)?,
                    up_bytes: row.get(2)?,
                })
            })
            .map_err(|e| MetricsError::Query {
                operation: "bandwidth_by_app".into(),
                source: e,
            })?;

        collect_rows(rows, "bandwidth_by_app")
    }

    /// Total down/up bytes for a single app over `range`.
    ///
    /// Returns zeroed totals (never an error) when the app has no samples in the
    /// window, mirroring the `app_stats` single-app query shape.
    pub fn bandwidth_for_app(&self, app_id: &str, range: &TimeRange) -> Result<AppBandwidth> {
        self.conn
            .query_row(
                "SELECT \
                     COALESCE(SUM(json_extract(payload, '$.down_bytes')), 0), \
                     COALESCE(SUM(json_extract(payload, '$.up_bytes')), 0) \
                 FROM events \
                 WHERE kind = 'bandwidth_sampled' AND app_id = ?1 \
                 AND ts >= ?2 AND ts < ?3",
                params![app_id, range.start, range.end],
                |row| {
                    Ok(AppBandwidth {
                        app_id: app_id.to_owned(),
                        down_bytes: row.get(0)?,
                        up_bytes: row.get(1)?,
                    })
                },
            )
            .map_err(|e| MetricsError::Query {
                operation: "bandwidth_for_app".into(),
                source: e,
            })
    }
}

#[cfg(test)]
#[path = "bandwidth_test.rs"]
mod bandwidth_test;
