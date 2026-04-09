//! Binary discovery for macOS systems.
//!
//! Two scan modes:
//! - **Targeted** (default): scans known app and system binary directories.
//! - **Full** (`--all`): Spotlight (`mdfind`) + system dirs for fast,
//!   comprehensive discovery without recursive filesystem walks.

use std::path::{Path, PathBuf};

use tracing::debug;

use crate::error::InventoryError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Application directories (contain `.app` bundles).
pub const APP_DIRS: &[&str] = &["/Applications", "~/Applications"];

/// System binary directories (contain naked executables).
pub const SYSTEM_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/libexec",
    "/usr/local/bin",
    "/opt/homebrew/bin",
];

/// All targeted scan directories — applications and system binaries.
pub const ALL_DIRS: &[&str] = &[
    "/Applications",
    "~/Applications",
    "/usr/bin",
    "/usr/sbin",
    "/usr/libexec",
    "/usr/local/bin",
    "/opt/homebrew/bin",
];

/// Mach-O magic bytes for executable detection.
const MACHO_MAGIC_32: [u8; 4] = [0xfe, 0xed, 0xfa, 0xce]; // MH_MAGIC
const MACHO_MAGIC_64: [u8; 4] = [0xfe, 0xed, 0xfa, 0xcf]; // MH_MAGIC_64
const MACHO_FAT: [u8; 4] = [0xca, 0xfe, 0xba, 0xbe]; // FAT_MAGIC
const MACHO_FAT_64: [u8; 4] = [0xca, 0xfe, 0xba, 0xbf]; // FAT_MAGIC_64

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A binary discovered during a directory scan.
#[derive(Debug, Clone)]
pub struct DiscoveredBinary {
    /// Path to the executable file.
    pub executable: PathBuf,
    /// If this binary came from an `.app` bundle, the bundle root path.
    pub bundle_path: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Targeted scan (default)
// ---------------------------------------------------------------------------

/// Scan targeted directories for executables and `.app` bundles.
///
/// Uses `std::fs::read_dir` for flat directory listing (no recursion needed
/// for `/usr/bin`, `/Applications` etc.).
pub fn scan_directories(dirs: &[PathBuf]) -> Result<Vec<DiscoveredBinary>, InventoryError> {
    let mut results = Vec::new();

    for dir in dirs {
        if !dir.is_dir() {
            debug!(path = %dir.display(), "skipping non-existent directory");
            continue;
        }
        scan_one_dir(dir, &mut results)?;
    }

    results.sort_by(|a, b| a.executable.cmp(&b.executable));
    results.dedup_by(|a, b| a.executable == b.executable);
    Ok(results)
}

/// Scan a single directory. Detects `.app` bundles vs naked executables.
fn scan_one_dir(dir: &Path, out: &mut Vec<DiscoveredBinary>) -> Result<(), InventoryError> {
    let entries = std::fs::read_dir(dir).map_err(|e| InventoryError::ReadDir {
        path: dir.to_path_buf(),
        source: e,
    })?;

    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                debug!(dir = %dir.display(), error = %e, "skipping unreadable entry");
                continue;
            }
        };

        let path = entry.path();

        if is_app_bundle(&path) {
            if let Some(exec) = resolve_bundle_executable(&path) {
                out.push(DiscoveredBinary {
                    executable: exec,
                    bundle_path: Some(path),
                });
            }
        } else if is_executable_file(&path) {
            out.push(DiscoveredBinary {
                executable: path,
                bundle_path: None,
            });
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Full scan (--all) — hybrid: mdfind + targeted system dirs
// ---------------------------------------------------------------------------

/// Directories that Spotlight typically skips (sealed volume, homebrew, etc.).
/// Scanned with flat `read_dir` to supplement `mdfind` results.
const EXTRA_SYSTEM_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/usr/libexec",
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/bin",
    "/sbin",
];

/// Discover all binaries system-wide using Spotlight + targeted system dirs.
///
/// 1. `mdfind` for executables and `.app` bundles (instant, Spotlight-indexed).
/// 2. Flat scan of system dirs that Spotlight skips (sealed volume, homebrew).
/// 3. Merge and deduplicate.
pub fn scan_full(_home: &Path) -> Vec<DiscoveredBinary> {
    let mut results = Vec::new();

    // Phase 1: Spotlight discovery.
    let mdfind_paths = mdfind_executables();
    debug!(count = mdfind_paths.len(), "mdfind returned executables");

    for path in mdfind_paths {
        if path.is_dir() && is_app_bundle(&path) {
            if let Some(exec) = resolve_bundle_executable(&path) {
                results.push(DiscoveredBinary {
                    executable: exec,
                    bundle_path: Some(path),
                });
            }
        } else if path.is_file() {
            // Check for .app ancestor (mdfind sometimes returns inner execs).
            let bundle_path = find_app_bundle_ancestor(&path);
            results.push(DiscoveredBinary {
                executable: path,
                bundle_path,
            });
        }
    }

    // Phase 2: system dirs that Spotlight skips.
    for dir_str in EXTRA_SYSTEM_DIRS {
        let dir = PathBuf::from(dir_str);
        if dir.is_dir() {
            let _ = scan_one_dir(&dir, &mut results);
        }
    }

    results.sort_by(|a, b| a.executable.cmp(&b.executable));
    results.dedup_by(|a, b| a.executable == b.executable);
    results
}

/// Query Spotlight for executables and application bundles.
fn mdfind_executables() -> Vec<PathBuf> {
    let query = "(kMDItemContentType == 'public.unix-executable' || \
                  kMDItemContentType == 'com.apple.application-bundle')";

    let Ok(output) = std::process::Command::new("mdfind").arg(query).output() else {
        debug!("mdfind command failed");
        return Vec::new();
    };

    if !output.status.success() {
        debug!(
            status = %output.status,
            "mdfind exited with non-zero status"
        );
        return Vec::new();
    }

    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect()
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

/// Check if a path looks like a `.app` bundle.
fn is_app_bundle(path: &Path) -> bool {
    path.is_dir()
        && path.extension().is_some_and(|e| e == "app")
        && path.join("Contents/MacOS").is_dir()
}

/// Walk up from a path to find an `.app` bundle ancestor.
fn find_app_bundle_ancestor(path: &Path) -> Option<PathBuf> {
    let mut current = path.parent();
    while let Some(p) = current {
        if p.extension().is_some_and(|e| e == "app") && p.join("Contents/MacOS").is_dir() {
            return Some(p.to_path_buf());
        }
        current = p.parent();
    }
    None
}

/// Resolve the main executable inside a `.app` bundle.
fn resolve_bundle_executable(bundle: &Path) -> Option<PathBuf> {
    let macos_dir = bundle.join("Contents/MacOS");

    // Try CFBundleExecutable from Info.plist.
    let plist_path = bundle.join("Contents/Info.plist");
    if let Ok(plist) = plist::Value::from_file(&plist_path)
        && let Some(exec_name) = plist
            .as_dictionary()
            .and_then(|d| d.get("CFBundleExecutable"))
            .and_then(plist::Value::as_string)
    {
        let exec_path = macos_dir.join(exec_name);
        if exec_path.is_file() {
            return Some(exec_path);
        }
    }

    // Fallback: bundle stem.
    let stem = bundle.file_stem()?;
    let exec_path = macos_dir.join(stem);
    if exec_path.is_file() {
        return Some(exec_path);
    }

    // Last resort: first file in Contents/MacOS/.
    if let Ok(entries) = std::fs::read_dir(&macos_dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                return Some(p);
            }
        }
    }

    debug!(bundle = %bundle.display(), "no executable found in bundle");
    None
}

/// Check if a path is a regular executable file (Unix permission bits).
fn is_executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        path.metadata()
            .map(|m| m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Check if a file starts with Mach-O magic bytes.
///
/// Reads the first 4 bytes only — fast even for large files.
pub fn is_macho(path: &Path) -> bool {
    use std::io::Read;

    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };

    let mut magic = [0u8; 4];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }

    magic == MACHO_MAGIC_32
        || magic == MACHO_MAGIC_64
        || magic == MACHO_FAT
        || magic == MACHO_FAT_64
}

#[cfg(test)]
#[path = "scanner_test.rs"]
mod scanner_test;
