//! Known-bad hash blocklist for binary detection.
//!
//! Loads SHA-256 hashes from plain-text files (one per line, `#` comments).
//! Built-in hashes are embedded at compile time; user hashes are loaded
//! from `~/.macwarden/blocklists/hashes.txt`.

use std::collections::HashSet;
use std::path::Path;

use crate::error::InventoryError;

/// Embedded built-in blocklist (starts empty — populated as hashes are curated).
const BUILTIN_HASHES: &str = include_str!("../../../knowledge/blocklists/hashes.txt");

/// A set of known-bad SHA-256 hashes.
#[derive(Debug, Clone)]
pub struct HashBlocklist {
    hashes: HashSet<String>,
}

impl HashBlocklist {
    /// Load the built-in blocklist plus any user-provided file.
    ///
    /// The user file is at `~/.macwarden/blocklists/hashes.txt`.
    /// If it doesn't exist, only built-in hashes are loaded.
    pub fn load() -> Self {
        let mut bl = Self::from_str(BUILTIN_HASHES);

        if let Ok(home) = std::env::var("HOME") {
            let user_path = Path::new(&home).join(".macwarden/blocklists/hashes.txt");
            if user_path.is_file()
                && let Ok(contents) = std::fs::read_to_string(&user_path)
            {
                bl.merge_str(&contents);
            }
        }

        bl
    }

    /// Load from a specific file (for testing or custom paths).
    pub fn load_file(path: &Path) -> Result<Self, InventoryError> {
        let contents = std::fs::read_to_string(path).map_err(|e| InventoryError::Blocklist {
            path: path.to_path_buf(),
            source: e,
        })?;
        Ok(Self::from_str(&contents))
    }

    /// Check if a SHA-256 hash is in the blocklist.
    pub fn contains(&self, sha256: &str) -> bool {
        self.hashes.contains(sha256)
    }

    /// Number of hashes in the blocklist.
    pub fn len(&self) -> usize {
        self.hashes.len()
    }

    /// Whether the blocklist is empty.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// Parse hashes from a string (one per line, `#` comments, empty lines skipped).
    fn from_str(contents: &str) -> Self {
        Self {
            hashes: parse_hash_lines(contents),
        }
    }

    /// Merge additional hashes from a string.
    fn merge_str(&mut self, contents: &str) {
        self.hashes.extend(parse_hash_lines(contents));
    }
}

/// Parse lines into a set of lowercase hex SHA-256 hashes.
fn parse_hash_lines(contents: &str) -> HashSet<String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_lowercase)
        .collect()
}

#[cfg(test)]
#[path = "blocklist_test.rs"]
mod blocklist_test;
