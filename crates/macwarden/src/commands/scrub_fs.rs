//! Filesystem helpers for `macwarden scrub` — size computation, path safety,
//! deletion operations, and process warnings.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;

// ---------------------------------------------------------------------------
// Allowed prefixes for path safety (R10)
// ---------------------------------------------------------------------------

/// Prefixes under which artifact path deletion is permitted.
pub fn allowed_prefixes() -> Vec<PathBuf> {
    let mut prefixes = vec![
        PathBuf::from("/private/var/"),
        PathBuf::from("/var/log/"),
        PathBuf::from("/System/Volumes/Data/.Spotlight-V100"),
        PathBuf::from("/tmp/"),
    ];
    if let Ok(home) = std::env::var("HOME") {
        prefixes.push(PathBuf::from(home).join("Library/"));
    }
    prefixes
}

/// Check whether a canonical path falls under any allowed prefix.
pub fn is_under_allowed_prefix(canonical: &Path, prefixes: &[PathBuf]) -> bool {
    prefixes.iter().any(|prefix| canonical.starts_with(prefix))
}

// ---------------------------------------------------------------------------
// Size formatting
// ---------------------------------------------------------------------------

/// Format a byte count as a human-readable string (1024-based, SI labels).
pub fn format_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// Compute total size of a path (recursive for directories).
pub fn compute_size(path: &Path) -> u64 {
    if path.is_file() {
        return path.metadata().map(|m| m.len()).unwrap_or(0);
    }
    if path.is_dir() {
        return dir_size_recursive(path);
    }
    0
}

/// Recursively sum file sizes in a directory.
fn dir_size_recursive(dir: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    entries.fold(0u64, |acc, entry| {
        let Ok(entry) = entry else { return acc };
        let path = entry.path();
        if path.is_dir() {
            acc + dir_size_recursive(&path)
        } else {
            acc + path.metadata().map(|m| m.len()).unwrap_or(0)
        }
    })
}

// ---------------------------------------------------------------------------
// Path safety (R10)
// ---------------------------------------------------------------------------

/// Verify a path is safe to delete via canonicalization + allowed prefixes.
pub fn verify_path_safety(expanded: &Path, raw_path: &str) -> bool {
    let canonical = match fs::canonicalize(expanded) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("  Warning: cannot canonicalize '{raw_path}': {e}");
            return false;
        }
    };

    let prefixes = allowed_prefixes();
    if !is_under_allowed_prefix(&canonical, &prefixes) {
        eprintln!(
            "  Refusing to delete {raw_path}: resolves to {} \
             which is outside allowed cleanup directories.",
            canonical.display()
        );
        return false;
    }
    true
}

/// Delete a file or directory, printing warnings on error.
pub fn delete_path(expanded: &Path, raw_path: &str, artifact_name: &str) {
    let result = if expanded.is_dir() {
        fs::remove_dir_all(expanded).context("remove_dir_all failed")
    } else {
        fs::remove_file(expanded).context("remove_file failed")
    };

    match result {
        Ok(()) => println!("  Deleted: {raw_path}"),
        Err(e) => eprintln!("  Warning: failed to delete '{artifact_name}' ({raw_path}): {e}"),
    }
}

// ---------------------------------------------------------------------------
// Process warnings (T3)
// ---------------------------------------------------------------------------

/// Applications to check before cleaning specific domains.
const WARNED_PROCESSES: &[(&str, &[&str])] = &[
    ("browser-traces", &["Google Chrome", "firefox", "Opera"]),
    ("app-caches", &["Spotify", "Telegram", "Deezer"]),
    ("safari", &["Safari"]),
    ("mail", &["Mail"]),
];

/// Warn if relevant applications are currently running.
pub fn warn_running_processes(domain_name: &str) {
    for (domain, names) in WARNED_PROCESSES {
        if !domain_name.eq_ignore_ascii_case(domain) {
            continue;
        }
        for name in *names {
            if is_process_running(name) {
                eprintln!(
                    "  Warning: {name} appears to be running. \
                     Cleaning while it's open may cause errors."
                );
            }
        }
    }
}

/// Check if a process with the given name is running via `pgrep`.
fn is_process_running(name: &str) -> bool {
    std::process::Command::new("pgrep")
        .args(["-xi", name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
