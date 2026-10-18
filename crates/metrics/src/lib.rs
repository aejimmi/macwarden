//! `metrics` -- SQLite-backed operational metrics store for macwarden.
//!
//! Collects events from all enforcement domains (services, ES, network,
//! sensors), persists them to `~/.macwarden/metrics.db`, and provides
//! time-range queries for dashboards.
//!
//! # Modules
//!
//! - [`error`] -- Error types for metrics operations
//! - [`event`] -- `MetricEvent` enum with nine variants
//! - [`store`] -- `MetricsStore` unified read/write handle

pub mod error;
pub mod event;
pub mod store;

// Re-export key types at crate root for convenience.
pub use error::MetricsError;
pub use event::MetricEvent;
pub use store::{
    AppBandwidth, AppCount, AppStats, BanEventRow, DomainCount, MetricsStore, SensorEvent, Summary,
    TimeRange,
};
