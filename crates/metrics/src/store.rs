//! SQLite-backed metrics storage.
//!
//! Handles schema initialization, event recording, time-range queries,
//! and retention pruning. Uses WAL journal mode for concurrent read/write
//! access (CLI reads while monitor writes).

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use tracing::{debug, info, warn};

use crate::error::{MetricsError, Result};
use crate::event::MetricEvent;

/// Default retention period: 90 days.
const DEFAULT_RETENTION: Duration = Duration::from_secs(90 * 24 * 3600);

/// Auto-prune interval: 24 hours.
const PRUNE_INTERVAL_SECS: u64 = 24 * 3600;

// ---------------------------------------------------------------------------
// Query result types
// ---------------------------------------------------------------------------

/// Aggregate summary across all metric domains.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Summary {
    /// Total events in the time range.
    pub total_events: u64,
    /// Network connections allowed.
    pub connections_allowed: u64,
    /// Network connections denied.
    pub connections_denied: u64,
    /// Network connections logged.
    pub connections_logged: u64,
    /// Service enforcement actions.
    pub enforcements: u64,
    /// Service drift corrections detected.
    pub drift_corrections: u64,
    /// Tracker hits by category name.
    pub tracker_hits_by_category: HashMap<String, u64>,
}

/// Per-app statistics within a time range.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AppStats {
    /// App identity (code signing identifier).
    pub app_id: String,
    /// Total network connections.
    pub connection_count: u64,
    /// Denied connections.
    pub denied_count: u64,
    /// Fraction of connections that hit a tracker (0.0–1.0).
    pub tracker_hit_rate: f64,
    /// Distinct destination domains.
    pub unique_domains: u64,
    /// Service enforcement actions referencing this app.
    pub enforcement_count: u64,
    /// Drift detections referencing this app.
    pub drift_count: u64,
}

/// A domain and its deny count.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DomainCount {
    /// Destination domain.
    pub domain: String,
    /// Number of times denied.
    pub count: u64,
}

/// An app and its connection counts.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AppCount {
    /// App identity (code signing identifier).
    pub app_id: String,
    /// Total connections.
    pub connection_count: u64,
    /// Denied connections.
    pub denied_count: u64,
}

/// A sensor activation/deactivation event.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SensorEvent {
    /// Unix epoch milliseconds.
    pub ts: i64,
    /// Device: "camera" or "microphone".
    pub device: String,
    /// State: "active" or "inactive".
    pub state: String,
    /// Process path, if captured.
    pub process_path: Option<String>,
    /// Code signing identity, if captured.
    pub code_id: Option<String>,
}

// ---------------------------------------------------------------------------
// Time range
// ---------------------------------------------------------------------------

/// A half-open time range `[start, end)` in Unix epoch milliseconds.
#[derive(Debug, Clone, Copy)]
pub struct TimeRange {
    /// Inclusive start (epoch ms).
    pub start: i64,
    /// Exclusive end (epoch ms).
    pub end: i64,
}

impl TimeRange {
    /// Creates a range from explicit bounds. Returns an error if `start > end`.
    pub fn new(start: i64, end: i64) -> Result<Self> {
        if start > end {
            return Err(MetricsError::InvalidRange { start, end });
        }
        Ok(Self { start, end })
    }

    /// Last `n` hours from now.
    pub fn last_hours(n: u64) -> Self {
        let now = now_epoch_ms();
        let start = now - (n as i64 * 3_600_000);
        Self { start, end: now }
    }

    /// Last `n` days from now.
    pub fn last_days(n: u64) -> Self {
        let now = now_epoch_ms();
        let start = now - (n as i64 * 86_400_000);
        Self { start, end: now }
    }

    /// From midnight today (local time approximation: UTC midnight) to now.
    pub fn today() -> Self {
        let now = now_epoch_ms();
        let start = now - (now % 86_400_000);
        Self { start, end: now }
    }

    /// Matches every possible timestamp.
    pub fn all() -> Self {
        Self {
            start: 0,
            end: i64::MAX,
        }
    }
}

// ---------------------------------------------------------------------------
// Metrics store
// ---------------------------------------------------------------------------

/// Unified read/write handle to the metrics SQLite database.
pub struct MetricsStore {
    conn: Connection,
}

impl MetricsStore {
    /// Opens (or creates) the metrics database at `path`.
    ///
    /// Creates parent directories, enables WAL mode, initializes schema,
    /// sets file permissions to 0600, and runs auto-prune if due.
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| MetricsError::Permissions {
                path: parent.display().to_string(),
                source: e,
            })?;
        }

        let conn = Connection::open(path).map_err(|e| MetricsError::Open {
            path: path.display().to_string(),
            source: e,
        })?;

        // WAL mode for concurrent read/write.
        conn.pragma_update(None, "journal_mode", "wal")
            .map_err(MetricsError::Schema)?;

        init_schema(&conn)?;
        set_permissions(path);

        let store = Self { conn };
        store.auto_prune()?;

        debug!(path = %path.display(), "metrics store opened");
        Ok(store)
    }

    /// Opens an in-memory database (for testing).
    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(|e| MetricsError::Open {
            path: ":memory:".into(),
            source: e,
        })?;
        init_schema(&conn)?;
        Ok(Self { conn })
    }

    // -- Recording -----------------------------------------------------------

    /// Records a single metric event with the current timestamp.
    pub fn record(&self, event: &MetricEvent) -> Result<()> {
        self.insert(now_epoch_ms(), event)
    }

    /// Records a metric event with an explicit timestamp (epoch ms).
    ///
    /// Useful for backfilling or testing.
    pub fn record_at(&self, ts: i64, event: &MetricEvent) -> Result<()> {
        self.insert(ts, event)
    }

    /// Inserts an event row with the given timestamp.
    fn insert(&self, ts: i64, event: &MetricEvent) -> Result<()> {
        let kind = event.kind();
        let payload = event.payload_json()?;

        self.conn
            .execute(
                "INSERT INTO events (ts, kind, app_id, domain, action, payload) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    ts,
                    kind,
                    event.app_id(),
                    event.domain(),
                    event.action(),
                    payload
                ],
            )
            .map_err(|e| MetricsError::Insert {
                kind: kind.to_owned(),
                source: e,
            })?;

        Ok(())
    }

    // -- Pruning -------------------------------------------------------------

    /// Deletes events older than `older_than` from now. Returns rows deleted.
    pub fn prune(&self, older_than: Duration) -> Result<u64> {
        // Zero duration means "delete everything" — use <= to avoid
        // missing events at exactly the current millisecond.
        let cutoff = now_epoch_ms() - older_than.as_millis() as i64;
        let op = if older_than.is_zero() {
            "DELETE FROM events WHERE ts <= ?1"
        } else {
            "DELETE FROM events WHERE ts < ?1"
        };
        let deleted = self
            .conn
            .execute(op, params![cutoff])
            .map_err(|e| MetricsError::Query {
                operation: "prune".into(),
                source: e,
            })?;

        // Store last-prune timestamp as epoch seconds in user_version.
        let now_secs = now_epoch_ms() / 1000;
        self.conn
            .pragma_update(None, "user_version", now_secs)
            .map_err(MetricsError::Schema)?;

        if deleted > 0 {
            info!(deleted, "pruned old metric events");
        }
        Ok(deleted as u64)
    }

    /// Runs prune with default retention if last prune was >24h ago.
    fn auto_prune(&self) -> Result<()> {
        let last_prune: i64 = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))
            .map_err(MetricsError::Schema)?;

        let now_secs = now_epoch_ms() / 1000;
        if now_secs - last_prune >= PRUNE_INTERVAL_SECS as i64 {
            debug!("auto-prune triggered (last: {last_prune}, now: {now_secs})");
            self.prune(DEFAULT_RETENTION)?;
        }
        Ok(())
    }

    // -- Queries -------------------------------------------------------------

    /// Aggregate summary across all domains within a time range.
    ///
    /// Uses a single aggregate query for scalar counts (atomic snapshot)
    /// plus `tracker_breakdown` for the category map.
    pub fn summary(&self, range: &TimeRange) -> Result<Summary> {
        let row = self
            .conn
            .query_row(
                "SELECT \
                     COUNT(*), \
                     COUNT(CASE WHEN kind = 'connection_decided' AND action = 'allow' \
                                THEN 1 END), \
                     COUNT(CASE WHEN kind = 'connection_decided' AND action = 'deny' \
                                THEN 1 END), \
                     COUNT(CASE WHEN kind = 'connection_decided' AND action = 'log' \
                                THEN 1 END), \
                     COUNT(CASE WHEN kind = 'service_enforced' THEN 1 END), \
                     COUNT(CASE WHEN kind = 'service_drift' THEN 1 END) \
                 FROM events WHERE ts >= ?1 AND ts < ?2",
                params![range.start, range.end],
                |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, u64>(1)?,
                        row.get::<_, u64>(2)?,
                        row.get::<_, u64>(3)?,
                        row.get::<_, u64>(4)?,
                        row.get::<_, u64>(5)?,
                    ))
                },
            )
            .map_err(|e| MetricsError::Query {
                operation: "summary".into(),
                source: e,
            })?;

        Ok(Summary {
            total_events: row.0,
            connections_allowed: row.1,
            connections_denied: row.2,
            connections_logged: row.3,
            enforcements: row.4,
            drift_corrections: row.5,
            tracker_hits_by_category: self.tracker_breakdown(range)?,
        })
    }

    /// Per-app statistics within a time range.
    pub fn app_stats(&self, app_id: &str, range: &TimeRange) -> Result<AppStats> {
        let connection_count: u64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events \
                 WHERE kind = 'connection_decided' AND app_id = ?1 \
                 AND ts >= ?2 AND ts < ?3",
                params![app_id, range.start, range.end],
                |row| row.get(0),
            )
            .map_err(|e| MetricsError::Query {
                operation: "app_stats/connection_count".into(),
                source: e,
            })?;

        let denied_count: u64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events \
                 WHERE kind = 'connection_decided' AND app_id = ?1 \
                 AND action = 'deny' AND ts >= ?2 AND ts < ?3",
                params![app_id, range.start, range.end],
                |row| row.get(0),
            )
            .map_err(|e| MetricsError::Query {
                operation: "app_stats/denied_count".into(),
                source: e,
            })?;

        let tracker_hits: u64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events \
                 WHERE kind = 'connection_decided' AND app_id = ?1 \
                 AND ts >= ?2 AND ts < ?3 \
                 AND json_extract(payload, '$.tracker_category') IS NOT NULL",
                params![app_id, range.start, range.end],
                |row| row.get(0),
            )
            .map_err(|e| MetricsError::Query {
                operation: "app_stats/tracker_hits".into(),
                source: e,
            })?;

        let tracker_hit_rate = if connection_count > 0 {
            tracker_hits as f64 / connection_count as f64
        } else {
            0.0
        };

        let unique_domains: u64 = self
            .conn
            .query_row(
                "SELECT COUNT(DISTINCT domain) FROM events \
                 WHERE kind = 'connection_decided' AND app_id = ?1 \
                 AND ts >= ?2 AND ts < ?3",
                params![app_id, range.start, range.end],
                |row| row.get(0),
            )
            .map_err(|e| MetricsError::Query {
                operation: "app_stats/unique_domains".into(),
                source: e,
            })?;

        let enforcement_count: u64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events \
                 WHERE kind = 'service_enforced' \
                 AND ts >= ?1 AND ts < ?2 \
                 AND json_extract(payload, '$.label') LIKE ?3",
                params![range.start, range.end, format!("%{app_id}%")],
                |row| row.get(0),
            )
            .map_err(|e| MetricsError::Query {
                operation: "app_stats/enforcement_count".into(),
                source: e,
            })?;

        let drift_count: u64 = self
            .conn
            .query_row(
                "SELECT COUNT(*) FROM events \
                 WHERE kind = 'service_drift' \
                 AND ts >= ?1 AND ts < ?2 \
                 AND json_extract(payload, '$.label') LIKE ?3",
                params![range.start, range.end, format!("%{app_id}%")],
                |row| row.get(0),
            )
            .map_err(|e| MetricsError::Query {
                operation: "app_stats/drift_count".into(),
                source: e,
            })?;

        Ok(AppStats {
            app_id: app_id.to_owned(),
            connection_count,
            denied_count,
            tracker_hit_rate,
            unique_domains,
            enforcement_count,
            drift_count,
        })
    }

    /// Most-denied domains, ordered by count descending.
    pub fn top_blocked(&self, range: &TimeRange, limit: usize) -> Result<Vec<DomainCount>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT domain, COUNT(*) as cnt FROM events \
                 WHERE kind = 'connection_decided' AND action = 'deny' \
                 AND domain IS NOT NULL \
                 AND ts >= ?1 AND ts < ?2 \
                 GROUP BY domain ORDER BY cnt DESC LIMIT ?3",
            )
            .map_err(|e| MetricsError::Query {
                operation: "top_blocked".into(),
                source: e,
            })?;

        let rows = stmt
            .query_map(params![range.start, range.end, limit as i64], |row| {
                Ok(DomainCount {
                    domain: row.get(0)?,
                    count: row.get(1)?,
                })
            })
            .map_err(|e| MetricsError::Query {
                operation: "top_blocked".into(),
                source: e,
            })?;

        collect_rows(rows, "top_blocked")
    }

    /// Apps with the most connections, ordered by total count descending.
    pub fn top_talkers(&self, range: &TimeRange, limit: usize) -> Result<Vec<AppCount>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT app_id, \
                        COUNT(*) as total, \
                        SUM(CASE WHEN action = 'deny' THEN 1 ELSE 0 END) as denied \
                 FROM events \
                 WHERE kind = 'connection_decided' AND app_id IS NOT NULL \
                 AND ts >= ?1 AND ts < ?2 \
                 GROUP BY app_id ORDER BY total DESC LIMIT ?3",
            )
            .map_err(|e| MetricsError::Query {
                operation: "top_talkers".into(),
                source: e,
            })?;

        let rows = stmt
            .query_map(params![range.start, range.end, limit as i64], |row| {
                Ok(AppCount {
                    app_id: row.get(0)?,
                    connection_count: row.get(1)?,
                    denied_count: row.get(2)?,
                })
            })
            .map_err(|e| MetricsError::Query {
                operation: "top_talkers".into(),
                source: e,
            })?;

        collect_rows(rows, "top_talkers")
    }

    /// Connection counts grouped by tracker category.
    pub fn tracker_breakdown(&self, range: &TimeRange) -> Result<HashMap<String, u64>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT json_extract(payload, '$.tracker_category') as cat, \
                        COUNT(*) as cnt \
                 FROM events \
                 WHERE kind = 'connection_decided' \
                 AND ts >= ?1 AND ts < ?2 \
                 AND cat IS NOT NULL \
                 GROUP BY cat",
            )
            .map_err(|e| MetricsError::Query {
                operation: "tracker_breakdown".into(),
                source: e,
            })?;

        let rows = stmt
            .query_map(params![range.start, range.end], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })
            .map_err(|e| MetricsError::Query {
                operation: "tracker_breakdown".into(),
                source: e,
            })?;

        let pairs: Vec<(String, u64)> = collect_rows(rows, "tracker_breakdown")?;
        Ok(pairs.into_iter().collect())
    }

    /// Sensor events in chronological order within a time range.
    pub fn sensor_timeline(&self, range: &TimeRange) -> Result<Vec<SensorEvent>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT ts, \
                        json_extract(payload, '$.device') as device, \
                        json_extract(payload, '$.state') as state, \
                        json_extract(payload, '$.process_path') as proc_path, \
                        json_extract(payload, '$.code_id') as code_id \
                 FROM events \
                 WHERE kind = 'sensor_triggered' \
                 AND ts >= ?1 AND ts < ?2 \
                 ORDER BY ts ASC",
            )
            .map_err(|e| MetricsError::Query {
                operation: "sensor_timeline".into(),
                source: e,
            })?;

        let rows = stmt
            .query_map(params![range.start, range.end], |row| {
                Ok(SensorEvent {
                    ts: row.get(0)?,
                    device: row.get(1)?,
                    state: row.get(2)?,
                    process_path: row.get(3)?,
                    code_id: row.get(4)?,
                })
            })
            .map_err(|e| MetricsError::Query {
                operation: "sensor_timeline".into(),
                source: e,
            })?;

        collect_rows(rows, "sensor_timeline")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Collects mapped rows into a `Vec`, converting row-level errors.
fn collect_rows<T>(
    rows: rusqlite::MappedRows<'_, impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<T>>,
    operation: &str,
) -> Result<Vec<T>> {
    rows.collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| MetricsError::Query {
            operation: format!("{operation}/row"),
            source: e,
        })
}

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

/// Creates tables and indexes if they don't exist.
fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            ts INTEGER NOT NULL,
            kind TEXT NOT NULL,
            app_id TEXT,
            domain TEXT,
            action TEXT,
            payload TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_kind_ts ON events(kind, ts);
        CREATE INDEX IF NOT EXISTS idx_app_ts ON events(app_id, ts);",
    )
    .map_err(MetricsError::Schema)
}

/// Best-effort chmod 0600 on Unix. Silently ignored on other platforms.
fn set_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            warn!(path = %path.display(), error = %e, "failed to set 0600 permissions");
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Current time as Unix epoch milliseconds.
fn now_epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
#[path = "store_test.rs"]
mod store_test;
