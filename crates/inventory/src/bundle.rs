//! macOS `.app` bundle `Info.plist` parser.
//!
//! Extracts display name, version, and bundle identifier from an
//! application bundle's `Contents/Info.plist`.

use std::path::Path;

use crate::error::InventoryError;

/// Metadata extracted from an `.app` bundle's `Info.plist`.
#[derive(Debug, Clone)]
pub struct BundleMetadata {
    /// `CFBundleIdentifier` (e.g. `com.apple.Safari`).
    pub bundle_id: Option<String>,
    /// Display name (`CFBundleDisplayName`, falling back to `CFBundleName`).
    pub name: Option<String>,
    /// Marketing version (`CFBundleShortVersionString`).
    pub version: Option<String>,
}

/// Read bundle metadata from a `.app` directory's `Info.plist`.
///
/// # Errors
///
/// Returns `InventoryError::Plist` if the plist cannot be read or parsed.
pub fn read_bundle_metadata(app_path: &Path) -> Result<BundleMetadata, InventoryError> {
    let plist_path = app_path.join("Contents/Info.plist");
    let value = plist::Value::from_file(&plist_path).map_err(|e| InventoryError::Plist {
        path: plist_path,
        source: e,
    })?;

    let dict = value.as_dictionary();

    let bundle_id = dict
        .and_then(|d| d.get("CFBundleIdentifier"))
        .and_then(plist::Value::as_string)
        .map(String::from);

    let name = dict
        .and_then(|d| {
            d.get("CFBundleDisplayName")
                .or_else(|| d.get("CFBundleName"))
        })
        .and_then(plist::Value::as_string)
        .map(String::from);

    let version = dict
        .and_then(|d| d.get("CFBundleShortVersionString"))
        .and_then(plist::Value::as_string)
        .map(String::from);

    Ok(BundleMetadata {
        bundle_id,
        name,
        version,
    })
}

#[cfg(test)]
#[path = "bundle_test.rs"]
mod bundle_test;
