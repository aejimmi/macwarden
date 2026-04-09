//! Etch-backed persistent storage for inventory records.
//!
//! Uses [`etchdb`] with a WAL backend for crash-safe persistence.
//! Records are keyed by canonical filesystem path.

use std::collections::BTreeMap;
use std::path::PathBuf;

use etchdb::{Replayable, Store, Transactable, WalBackend};
use serde::{Deserialize, Serialize};

use crate::error::InventoryError;
use crate::record::BinaryRecord;

// ---------------------------------------------------------------------------
// Etch state
// ---------------------------------------------------------------------------

/// Top-level etch state for binary inventory.
#[derive(Debug, Clone, Default, Serialize, Deserialize, Replayable, Transactable)]
pub struct InventoryDb {
    /// Binary records keyed by canonical filesystem path.
    #[etch(collection = 0)]
    pub records: BTreeMap<String, BinaryRecord>,
}

// ---------------------------------------------------------------------------
// Store wrapper
// ---------------------------------------------------------------------------

/// Persistent inventory store backed by etch WAL.
pub struct InventoryStore {
    inner: Store<InventoryDb, WalBackend<InventoryDb>>,
}

impl InventoryStore {
    /// Open (or create) the inventory store at `~/.macwarden/inventory/`.
    pub fn open() -> Result<Self, InventoryError> {
        let dir = resolve_store_dir()?;
        std::fs::create_dir_all(&dir).map_err(|e| {
            InventoryError::Store(format!(
                "failed to create store directory {}: {e}",
                dir.display()
            ))
        })?;

        let store = Store::<InventoryDb, WalBackend<InventoryDb>>::open_wal(dir)
            .map_err(|e| InventoryError::Store(format!("failed to open etch store: {e}")))?;

        Ok(Self { inner: store })
    }

    /// Open a store at a specific path (for testing).
    pub fn open_at(dir: PathBuf) -> Result<Self, InventoryError> {
        std::fs::create_dir_all(&dir).map_err(|e| {
            InventoryError::Store(format!(
                "failed to create store directory {}: {e}",
                dir.display()
            ))
        })?;

        let store = Store::<InventoryDb, WalBackend<InventoryDb>>::open_wal(dir)
            .map_err(|e| InventoryError::Store(format!("failed to open etch store: {e}")))?;

        Ok(Self { inner: store })
    }

    /// Insert or update a batch of records. Each record is keyed by its path.
    pub fn upsert_batch(&self, records: &[BinaryRecord]) -> Result<(), InventoryError> {
        self.inner
            .write(|tx| {
                for rec in records {
                    tx.records.put(rec.path.clone(), rec.clone());
                }
                Ok(())
            })
            .map_err(|e| InventoryError::Store(format!("write failed: {e}")))?;
        Ok(())
    }

    /// Reconcile the store: upsert current records, delete stale ones.
    pub fn reconcile(&self, records: &[BinaryRecord]) -> Result<(), InventoryError> {
        let current_paths: std::collections::HashSet<&str> =
            records.iter().map(|r| r.path.as_str()).collect();

        // Collect stale keys first (paths in store but not in current scan).
        let stale: Vec<String> = {
            let state = self.inner.read();
            state
                .records
                .keys()
                .filter(|k| !current_paths.contains(k.as_str()))
                .cloned()
                .collect()
        };

        self.inner
            .write(|tx| {
                for key in &stale {
                    tx.records.delete(key);
                }
                for rec in records {
                    tx.records.put(rec.path.clone(), rec.clone());
                }
                Ok(())
            })
            .map_err(|e| InventoryError::Store(format!("write failed: {e}")))?;
        Ok(())
    }

    /// Insert or update a single record.
    pub fn upsert(&self, record: &BinaryRecord) -> Result<(), InventoryError> {
        self.inner
            .write(|tx| {
                tx.records.put(record.path.clone(), record.clone());
                Ok(())
            })
            .map_err(|e| InventoryError::Store(format!("write failed: {e}")))?;
        Ok(())
    }

    /// Return all records in the store.
    pub fn all(&self) -> Vec<BinaryRecord> {
        let state = self.inner.read();
        state.records.values().cloned().collect()
    }

    /// Return records that have not been analyzed by openbinary yet.
    pub fn unanalyzed(&self) -> Vec<BinaryRecord> {
        let state = self.inner.read();
        state
            .records
            .values()
            .filter(|r| r.analyzed_at.is_none())
            .cloned()
            .collect()
    }

    /// Update a record's openbinary analysis result.
    pub fn save_analysis(
        &self,
        path: &str,
        analysis: serde_json::Value,
        timestamp: i64,
    ) -> Result<(), InventoryError> {
        self.inner
            .write(|tx| {
                if let Some(mut rec) = tx.records.get(&path.to_owned()).cloned() {
                    rec.openbinary = Some(analysis);
                    rec.analyzed_at = Some(timestamp);
                    tx.records.put(path.to_owned(), rec);
                }
                Ok(())
            })
            .map_err(|e| InventoryError::Store(format!("write failed: {e}")))?;
        Ok(())
    }

    /// Number of records in the store.
    pub fn len(&self) -> usize {
        self.inner.read().records.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Resolve the store directory path, expanding `~`.
fn resolve_store_dir() -> Result<PathBuf, InventoryError> {
    let home = std::env::var("HOME")
        .map_err(|_| InventoryError::Store("HOME environment variable not set".into()))?;
    Ok(PathBuf::from(home).join(".macwarden").join("inventory"))
}

#[cfg(test)]
#[path = "db_test.rs"]
mod db_test;
