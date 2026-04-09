//! `macwarden inventory lookup` — batch openbinary analysis of stored inventory.
//!
//! Reads unanalyzed records from the etch store and processes each through
//! the same openbinary API used by `macwarden lookup`.

use std::collections::HashSet;
use std::io::{Write, stderr};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use inventory::InventoryStore;

use crate::cli::OutputFormat;
use crate::openbinary::{self, JobStatus, UploadResult};

/// Delay between openbinary API calls (milliseconds).
const REQUEST_DELAY_MS: u64 = 100;

/// Run the inventory lookup command.
pub fn run(no_upload: bool, format: OutputFormat) -> Result<()> {
    let store = InventoryStore::open().context("failed to open inventory store")?;
    let unanalyzed = store.unanalyzed();

    if unanalyzed.is_empty() {
        println!("  All inventory binaries have been analyzed.");
        return Ok(());
    }

    // Dedup by sha256 — same binary at different paths only needs one lookup.
    let mut seen_hashes = HashSet::new();
    let unique: Vec<_> = unanalyzed
        .iter()
        .filter(|r| seen_hashes.insert(r.sha256.clone()))
        .collect();

    let base = openbinary::endpoint();
    let total = unique.len();
    let mut found = 0u64;
    let uploaded = 0u64;
    let mut not_found = 0u64;
    let mut errors = 0u64;

    eprintln!(
        "  Processing {} unique binaries ({} total unanalyzed)...",
        total,
        unanalyzed.len()
    );

    for (i, rec) in unique.iter().enumerate() {
        eprint!("\r  [{}/{}] {}...", i + 1, total, rec.display_name());
        let _ = stderr().flush();

        match process_one(&base, &rec.sha256, &rec.path, no_upload) {
            Ok(Some(analysis)) => {
                found += 1;
                let now = epoch_ms();
                // Update all records sharing this sha256.
                for r in &unanalyzed {
                    if r.sha256 == rec.sha256
                        && let Err(e) = store.save_analysis(&r.path, analysis.clone(), now)
                    {
                        tracing::warn!(path = %r.path, error = %e, "failed to save analysis");
                    }
                }
            }
            Ok(None) => {
                not_found += 1;
            }
            Err(e) => {
                tracing::debug!(sha256 = %rec.sha256, error = %e, "lookup failed");
                errors += 1;
            }
        }

        if i + 1 < total {
            std::thread::sleep(std::time::Duration::from_millis(REQUEST_DELAY_MS));
        }
    }

    // Clear the progress line.
    eprint!("\r{}\r", " ".repeat(80));
    let _ = stderr().flush();

    match format {
        OutputFormat::Table => print_summary(total as u64, found, uploaded, not_found, errors),
        OutputFormat::Json => print_summary_json(total as u64, found, uploaded, not_found, errors)?,
    }

    Ok(())
}

/// Process a single binary through openbinary.
///
/// Returns `Ok(Some(analysis))` if found or successfully uploaded and analyzed,
/// `Ok(None)` if not found and upload is disabled, or `Err` on API failure.
fn process_one(
    base: &str,
    sha256: &str,
    path: &str,
    no_upload: bool,
) -> Result<Option<serde_json::Value>> {
    // Check if openbinary already knows this hash.
    if let Some(analysis) = openbinary::get_binary(base, sha256)? {
        return Ok(Some(analysis));
    }

    if no_upload {
        return Ok(None);
    }

    // Upload for analysis (same flow as `macwarden lookup`).
    let file_path = std::path::Path::new(path);
    if !file_path.is_file() {
        return Ok(None);
    }

    let job_id = match openbinary::upload(base, file_path)? {
        UploadResult::AlreadyDone { sha256: ref s, .. } => {
            return openbinary::get_binary(base, s);
        }
        UploadResult::Pending { job_id } => job_id,
    };

    // Poll until done.
    let status = openbinary::poll_job(base, &job_id, &mut |_| {})?;
    if let JobStatus::Failed(e) = status {
        anyhow::bail!("analysis failed: {e}");
    }

    openbinary::get_binary(base, sha256)
}

/// Print a human-readable summary.
fn print_summary(total: u64, found: u64, _uploaded: u64, not_found: u64, errors: u64) {
    println!();
    println!("  Inventory lookup complete");
    println!("    Total:     {total}");
    println!("    Analyzed:  {found}");
    println!("    Unknown:   {not_found}");
    if errors > 0 {
        println!("    Errors:    {errors}");
    }
    println!();
    if not_found > 0 {
        println!("  Run `macwarden lookup <path>` on specific binaries to upload them.");
    }
}

/// Print summary as JSON.
fn print_summary_json(
    total: u64,
    found: u64,
    _uploaded: u64,
    not_found: u64,
    errors: u64,
) -> Result<()> {
    let json = serde_json::json!({
        "total": total,
        "analyzed": found,
        "unknown": not_found,
        "errors": errors,
    });
    let s = serde_json::to_string_pretty(&json).context("serialize")?;
    println!("{s}");
    Ok(())
}

/// Current time as epoch milliseconds.
fn epoch_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
