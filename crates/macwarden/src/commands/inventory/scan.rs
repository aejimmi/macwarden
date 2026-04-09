//! `macwarden inventory scan` — discover, hash, and store binaries.

use std::collections::HashMap;
use std::fmt::Write as _;
use std::io::{Write, stderr};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use inventory::scanner::{ALL_DIRS, SYSTEM_DIRS};
use inventory::{BinaryRecord, DiscoveredBinary, HashBlocklist, InventoryStore, bundle};
use rayon::prelude::*;

use crate::cli::OutputFormat;

/// Run the inventory scan command.
pub fn run(full: bool, format: OutputFormat) -> Result<()> {
    let blocklist = HashBlocklist::load();
    let now_ms = epoch_ms();

    let discovered = if full {
        eprint!("  Walking filesystem...");
        let _ = stderr().flush();
        let home = crate::cli::expand_home("~")?;
        let result = inventory::scanner::scan_full(&home);
        eprintln!(" found {} executables", result.len());
        result
    } else {
        eprint!("  Scanning...");
        let _ = stderr().flush();
        let dirs = resolve_all_dirs()?;
        let result =
            inventory::scanner::scan_directories(&dirs).context("failed to scan directories")?;
        eprintln!(" found {} binaries", result.len());
        result
    };

    eprint!("  Hashing and inspecting...");
    let _ = stderr().flush();

    let records: Vec<BinaryRecord> = discovered
        .par_iter()
        .filter_map(|d| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                build_record(d, &blocklist, now_ms)
            }))
            .unwrap_or_else(|_| {
                tracing::warn!(path = %d.executable.display(), "panic during record build");
                None
            })
        })
        .collect();

    let blocklisted_count = records.iter().filter(|r| r.is_blocklisted).count();
    eprintln!(" done");

    // Preserve existing openbinary analysis results from the store.
    let store = InventoryStore::open().context("failed to open inventory store")?;
    let existing: HashMap<String, BinaryRecord> = store
        .all()
        .into_iter()
        .map(|r| (r.path.clone(), r))
        .collect();

    let records: Vec<BinaryRecord> = records
        .into_iter()
        .map(|mut rec| {
            if let Some(prev) = existing.get(&rec.path) {
                rec.openbinary = prev.openbinary.clone();
                rec.analyzed_at = prev.analyzed_at;
            }
            rec
        })
        .collect();

    store
        .reconcile(&records)
        .context("failed to save inventory")?;

    match format {
        OutputFormat::Table => print_grouped(&records, blocklisted_count),
        OutputFormat::Json => print_json(&records)?,
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Record building
// ---------------------------------------------------------------------------

/// Paths on the sealed system volume — code signing is guaranteed by the OS.
const SEALED_PREFIXES: &[&str] = &["/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/System/"];

/// Returns true if a path is on the macOS sealed system volume.
fn is_sealed_path(path: &str) -> bool {
    SEALED_PREFIXES.iter().any(|pfx| path.starts_with(pfx))
}

/// Build a `BinaryRecord` from a discovered binary.
fn build_record(
    discovered: &DiscoveredBinary,
    blocklist: &HashBlocklist,
    now_ms: i64,
) -> Option<BinaryRecord> {
    let exec_path = &discovered.executable;

    // Streaming hash — reads in 64KB chunks, not the whole file.
    let sha256 = match inventory::hash::hash_file(exec_path) {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!(path = %exec_path.display(), error = %e, "skipping unhashable binary");
            return None;
        }
    };

    let (bundle_id, name, version) = match &discovered.bundle_path {
        Some(bp) => match bundle::read_bundle_metadata(bp) {
            Ok(meta) => (meta.bundle_id, meta.name, meta.version),
            Err(e) => {
                tracing::debug!(path = %bp.display(), error = %e, "failed to read bundle plist");
                (None, None, None)
            }
        },
        None => (None, None, None),
    };

    // Skip code signing for sealed system paths — the OS guarantees their integrity.
    let path_str = exec_path.to_string_lossy();
    let (code_id, team_id, is_apple_signed, is_valid_sig) = if is_sealed_path(&path_str) {
        (None, None, true, true)
    } else {
        get_code_signing(exec_path)
    };

    let is_blocklisted = blocklist.contains(&sha256);

    Some(BinaryRecord {
        path: exec_path.to_string_lossy().into_owned(),
        sha256,
        bundle_id,
        name,
        version,
        code_id,
        team_id,
        is_apple_signed,
        is_valid_sig,
        scanned_at: now_ms,
        is_blocklisted,
        openbinary: None,
        analyzed_at: None,
    })
}

#[cfg(target_os = "macos")]
fn get_code_signing(path: &std::path::Path) -> (Option<String>, Option<String>, bool, bool) {
    match procmon::code_signing::get_code_signing_info(0, path) {
        Ok(info) => (
            info.code_id,
            info.team_id,
            info.is_apple_signed,
            info.is_valid,
        ),
        Err(e) => {
            tracing::debug!(path = %path.display(), error = %e, "code signing check failed");
            (None, None, false, false)
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn get_code_signing(_path: &std::path::Path) -> (Option<String>, Option<String>, bool, bool) {
    (None, None, false, false)
}

// ---------------------------------------------------------------------------
// Directory resolution
// ---------------------------------------------------------------------------

/// Resolve all scan directories, expanding `~`.
fn resolve_all_dirs() -> Result<Vec<PathBuf>> {
    ALL_DIRS
        .iter()
        .map(|p| crate::cli::expand_home(p))
        .collect()
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

/// A record is "individual" if it came from an .app bundle (has bundle metadata).
fn is_app_record(rec: &BinaryRecord) -> bool {
    rec.bundle_id.is_some() || rec.name.is_some() || rec.version.is_some()
}

/// Determine the grouping directory for a non-app binary.
/// Returns the longest matching known prefix, or the parent dir.
fn group_dir_for(path: &str) -> String {
    // Check known system dirs first (longest match).
    if let Some(dir) = SYSTEM_DIRS
        .iter()
        .find(|dir| path.starts_with(**dir))
        .copied()
    {
        return dir.to_owned();
    }
    // Fall back to parent directory.
    if let Some(pos) = path.rfind('/') {
        return path[..pos].to_owned();
    }
    path.to_owned()
}

// ---------------------------------------------------------------------------
// ANSI (same palette as status.rs)
// ---------------------------------------------------------------------------

const BOLD: &str = "\x1b[1;37m";
const N: &str = "\x1b[37m";
const DIM: &str = "\x1b[90m";
const RED: &str = "\x1b[31m";
const GRN: &str = "\x1b[32m";
const RST: &str = "\x1b[0m";

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

/// Print grouped table: apps individually, non-app dirs as summaries.
/// Blocklisted or invalid-sig binaries are always promoted to individual rows.
fn print_grouped(records: &[BinaryRecord], blocklisted_count: usize) {
    let analyzed_total = records.iter().filter(|r| r.analyzed_at.is_some()).count();

    let mut apps: Vec<&BinaryRecord> = Vec::new();
    let mut promoted: Vec<&BinaryRecord> = Vec::new();
    let mut grouped: HashMap<String, Vec<&BinaryRecord>> = HashMap::new();

    for rec in records {
        if is_app_record(rec) {
            apps.push(rec);
        } else {
            if rec.is_blocklisted || (!rec.is_valid_sig && rec.code_id.is_some()) {
                promoted.push(rec);
            }
            let dir = group_dir_for(&rec.path);
            grouped.entry(dir).or_default().push(rec);
        }
    }

    println!();
    println!("  {BOLD}APPLICATIONS{RST}  {DIM}{} apps{RST}", apps.len());
    println!();

    for rec in &apps {
        print_record_row(rec);
    }

    if !promoted.is_empty() {
        println!();
        println!("  {BOLD}FLAGGED{RST}");
        println!();
        for rec in &promoted {
            print_record_row(rec);
        }
    }

    if !grouped.is_empty() {
        println!();
        println!("  {BOLD}SYSTEM BINARIES{RST}");

        let mut dirs: Vec<&String> = grouped.keys().collect();
        dirs.sort();

        for dir in dirs {
            let Some(entries) = grouped.get(dir) else {
                continue;
            };
            let count = entries.len();
            let an = entries.iter().filter(|r| r.analyzed_at.is_some()).count();
            let bl = entries.iter().filter(|r| r.is_blocklisted).count();

            let an_str = if an > 0 {
                format!("  {GRN}{an} analyzed{RST}")
            } else {
                String::new()
            };
            let bl_str = if bl > 0 {
                format!("  {RED}{bl} blocklisted{RST}")
            } else {
                String::new()
            };

            println!("  {N}{dir:<40}{RST} {DIM}{count:>5}{RST}{an_str}{bl_str}");
        }
    }

    println!();
    println!(
        "  {DIM}{} binaries, {} analyzed, {} blocklisted{RST}",
        records.len(),
        analyzed_total,
        blocklisted_count
    );
    println!();
}

/// Print a single record as a table row.
fn print_record_row(rec: &BinaryRecord) {
    let name = truncate(rec.display_name(), 30);
    let version = rec.version.as_deref().unwrap_or("");
    let team = rec.team_id.as_deref().unwrap_or("");
    let hash = rec.short_hash();

    let ob = if rec.analyzed_at.is_some() {
        format!("{GRN}\u{2713}{RST}")
    } else {
        String::new()
    };

    let mut flags = String::new();
    if rec.is_blocklisted {
        let _ = write!(flags, " {RED}BLOCKED{RST}");
    }
    if rec.is_apple_signed {
        let _ = write!(flags, " {DIM}Apple{RST}");
    }
    if !rec.is_valid_sig && rec.code_id.is_some() {
        let _ = write!(flags, " {RED}INVALID_SIG{RST}");
    }

    println!(
        "  {N}{:<30}{RST} {DIM}{:<12} {:<10} {}{RST} {ob}{flags}",
        name,
        truncate(version, 12),
        truncate(team, 10),
        hash,
    );
}

/// Print results as JSON (all records, flat).
fn print_json(records: &[BinaryRecord]) -> Result<()> {
    let json = serde_json::to_string_pretty(records).context("failed to serialize")?;
    println!("{json}");
    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_owned()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

fn epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
