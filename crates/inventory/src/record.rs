//! Binary inventory record — the core data type for a discovered binary.

use serde::{Deserialize, Serialize};

/// A single binary discovered during an inventory scan.
///
/// Keyed by canonical path in the etch store. Fields populated in stages:
/// - Scan phase: path, sha256, bundle metadata, code signing, blocklist status
/// - Lookup phase: openbinary analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryRecord {
    /// Canonical filesystem path to the binary executable.
    pub path: String,

    /// SHA-256 hash of the binary (lowercase hex).
    pub sha256: String,

    // -- App bundle metadata (None for naked executables) ----------------
    /// `CFBundleIdentifier` from `Info.plist`.
    pub bundle_id: Option<String>,

    /// Display name (`CFBundleDisplayName` or `CFBundleName`).
    pub name: Option<String>,

    /// Marketing version (`CFBundleShortVersionString`).
    pub version: Option<String>,

    // -- Code signing (populated on macOS) --------------------------------
    /// Code signing identifier (e.g. `com.apple.Safari`).
    pub code_id: Option<String>,

    /// Apple Developer Team ID (e.g. `ABCDEF1234`).
    pub team_id: Option<String>,

    /// Whether the binary is signed by Apple.
    pub is_apple_signed: bool,

    /// Whether the code signature is currently valid.
    pub is_valid_sig: bool,

    // -- Scan metadata ----------------------------------------------------
    /// Epoch milliseconds when this record was last scanned.
    pub scanned_at: i64,

    /// Whether the sha256 matched a known-bad hash in the blocklist.
    pub is_blocklisted: bool,

    // -- Openbinary analysis (populated by `inventory lookup`) -------------
    /// Raw openbinary analysis JSON, if available.
    pub openbinary: Option<serde_json::Value>,

    /// Epoch milliseconds when openbinary analysis was fetched.
    pub analyzed_at: Option<i64>,
}

impl BinaryRecord {
    /// Short display name: bundle name if available, otherwise filename.
    pub fn display_name(&self) -> &str {
        if let Some(ref name) = self.name {
            return name;
        }
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// Truncated hash for table display (first 12 hex chars).
    pub fn short_hash(&self) -> &str {
        if self.sha256.len() >= 12 {
            &self.sha256[..12]
        } else {
            &self.sha256
        }
    }
}

#[cfg(test)]
#[path = "record_test.rs"]
mod record_test;
