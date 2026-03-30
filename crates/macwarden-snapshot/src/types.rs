//! Snapshot data types.
//!
//! A [`Snapshot`] captures the state of services before enforcement actions
//! are applied, enabling rollback if needed.

use macwarden_core::{Action, ServiceState};
use serde::{Deserialize, Serialize};

/// A single service entry within a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// The launchd service label.
    pub label: String,
    /// The service state before any action was taken.
    pub prior_state: ServiceState,
    /// The enforcement action that was applied (or will be applied).
    pub action_taken: Action,
}

/// A point-in-time snapshot of service states before enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// ISO 8601 timestamp when the snapshot was created.
    pub timestamp: String,
    /// Name of the profile that triggered the snapshot.
    pub profile_name: String,
    /// Individual service entries captured in this snapshot.
    pub entries: Vec<SnapshotEntry>,
}
