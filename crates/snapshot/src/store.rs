//! Snapshot persistence layer.
//!
//! Stores snapshots as JSON files in a directory, named by timestamp.
//! ISO 8601 timestamps sort lexicographically, so filename ordering gives
//! chronological ordering for free.

use std::fs;
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::error::{Result, SnapshotError};
use crate::types::Snapshot;

/// Manages snapshot files on disk.
#[derive(Debug, Clone)]
pub struct SnapshotStore {
    /// Directory where snapshot JSON files are stored.
    dir: PathBuf,
}

impl SnapshotStore {
    /// Creates a new store backed by the given directory.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Creates the snapshot directory (and parents) if it does not exist.
    pub fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.dir)?;
        Ok(())
    }

    /// Serializes a snapshot to JSON and writes it to `<timestamp>.json`.
    ///
    /// Returns the path of the written file.
    pub fn write(&self, snapshot: &Snapshot) -> Result<PathBuf> {
        self.ensure_dir()?;

        let filename = format!("{}.json", snapshot.timestamp);
        let path = self.dir.join(&filename);

        let json = serde_json::to_string_pretty(snapshot)
            .map_err(|e| SnapshotError::Serialize(e.to_string()))?;

        fs::write(&path, json)?;
        debug!(path = %path.display(), "wrote snapshot");

        Ok(path)
    }

    /// Returns the most recent snapshot by lexicographic filename ordering.
    ///
    /// Returns `Ok(None)` if the directory is empty or does not exist.
    pub fn latest(&self) -> Result<Option<Snapshot>> {
        let entries = match self.list_paths() {
            Ok(entries) => entries,
            Err(SnapshotError::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        match entries.last() {
            Some((_name, path)) => {
                let snapshot = self.read(path)?;
                Ok(Some(snapshot))
            }
            None => Ok(None),
        }
    }

    /// Lists all snapshot files sorted by filename (chronological order).
    ///
    /// Returns pairs of `(filename_stem, path)`.
    pub fn list(&self) -> Result<Vec<(String, PathBuf)>> {
        self.list_paths()
    }

    /// Reads and deserializes a snapshot from a JSON file.
    #[allow(clippy::unused_self)]
    pub fn read(&self, path: &Path) -> Result<Snapshot> {
        if !path.exists() {
            return Err(SnapshotError::NotFound(path.display().to_string()));
        }

        let contents = fs::read_to_string(path)?;
        let snapshot: Snapshot = serde_json::from_str(&contents)
            .map_err(|e| SnapshotError::Deserialize(e.to_string()))?;

        Ok(snapshot)
    }

    /// Internal helper — reads the directory and returns sorted entries.
    fn list_paths(&self) -> Result<Vec<(String, PathBuf)>> {
        let read_dir = fs::read_dir(&self.dir)?;

        let mut entries: Vec<(String, PathBuf)> = Vec::new();
        for entry in read_dir {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let stem = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or_default()
                    .to_owned();
                entries.push((stem, path));
            }
        }

        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(entries)
    }
}

#[cfg(test)]
#[path = "store_test.rs"]
mod store_test;
