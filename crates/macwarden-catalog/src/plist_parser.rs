//! Plist file parsing for launchd service discovery.
//!
//! Parses both XML and binary plist files, extracting the fields relevant to
//! service enumeration: Label, Program, `RunAtLoad`, `KeepAlive`, and Disabled.

use std::path::{Path, PathBuf};

use plist::Dictionary;

use crate::error::{CatalogError, Result};

// ---------------------------------------------------------------------------
// PlistInfo
// ---------------------------------------------------------------------------

/// Parsed information from a launchd plist file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlistInfo {
    /// The service label (from the `Label` key).
    pub label: String,
    /// The executable path (from `Program` or first element of `ProgramArguments`).
    pub program: Option<String>,
    /// Whether the service loads at boot/login.
    pub run_at_load: bool,
    /// Whether the service is kept alive (restarted on exit).
    pub keep_alive: bool,
    /// Whether the service is explicitly disabled in the plist.
    pub disabled: bool,
    /// Path to the plist file on disk.
    pub path: PathBuf,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a launchd plist file (binary or XML) and extract service metadata.
///
/// Returns an error if the file cannot be read, is not a valid plist, or is
/// missing the required `Label` key.
pub fn parse_plist(path: &Path) -> Result<PlistInfo> {
    let value = plist::Value::from_file(path).map_err(|e| CatalogError::PlistParse {
        path: path.to_path_buf(),
        message: e.to_string(),
    })?;

    let dict = value
        .as_dictionary()
        .ok_or_else(|| CatalogError::PlistParse {
            path: path.to_path_buf(),
            message: "plist root is not a dictionary".to_string(),
        })?;

    let label = extract_label(dict, path)?;
    let program = extract_program(dict);
    let run_at_load = extract_bool(dict, "RunAtLoad");
    let keep_alive = extract_keep_alive(dict);
    let disabled = extract_bool(dict, "Disabled");

    Ok(PlistInfo {
        label,
        program,
        run_at_load,
        keep_alive,
        disabled,
        path: path.to_path_buf(),
    })
}

/// Extract the `Label` key, which is required.
fn extract_label(dict: &Dictionary, path: &Path) -> Result<String> {
    dict.get("Label")
        .and_then(plist::Value::as_string)
        .map(String::from)
        .ok_or_else(|| CatalogError::PlistParse {
            path: path.to_path_buf(),
            message: "missing or non-string 'Label' key".to_string(),
        })
}

/// Extract the executable path from `Program` or `ProgramArguments[0]`.
fn extract_program(dict: &Dictionary) -> Option<String> {
    // Prefer the explicit `Program` key.
    if let Some(prog) = dict.get("Program").and_then(plist::Value::as_string) {
        return Some(prog.to_string());
    }

    // Fall back to the first element of `ProgramArguments`.
    dict.get("ProgramArguments")
        .and_then(plist::Value::as_array)
        .and_then(|arr| arr.first())
        .and_then(plist::Value::as_string)
        .map(String::from)
}

/// Extract a boolean value from the dictionary, defaulting to `false`.
fn extract_bool(dict: &Dictionary, key: &str) -> bool {
    dict.get(key)
        .and_then(plist::Value::as_boolean)
        .unwrap_or(false)
}

/// Extract the `KeepAlive` value.
///
/// `KeepAlive` can be a simple boolean or a dictionary of conditions.
/// If it is a dictionary, we treat it as `true` (conditionally kept alive).
fn extract_keep_alive(dict: &Dictionary) -> bool {
    match dict.get("KeepAlive") {
        Some(plist::Value::Boolean(b)) => *b,
        Some(plist::Value::Dictionary(_)) => true,
        _ => false,
    }
}

#[cfg(test)]
#[path = "plist_parser_test.rs"]
mod plist_parser_test;
