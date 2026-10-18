//! `macwarden inventory lookup` — batch openbinary analysis of stored inventory.
//!
//! Reads unanalyzed records from the etch store and processes each through
//! the same openbinary API used by `macwarden lookup`.

use std::collections::HashSet;
use std::io::{Write, stderr};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use inventory::InventoryStore;
use openbinary_agent_core::{JobStatus, OpenBinaryClient, UploadResult};

use crate::cli::OutputFormat;
use crate::openbinary;

/// Outcome of processing one binary through openbinary.
enum Outcome {
    /// Analysis is available. `uploaded` is true when this run uploaded the
    /// binary (it was not already in the openbinary database).
    Analyzed {
        analysis: serde_json::Value,
        uploaded: bool,
    },
    /// Unknown to openbinary and not uploaded (upload disabled or missing file).
    NotFound,
}

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

    let client = openbinary::client();
    let total = unique.len();
    let mut found = 0u64;
    let mut uploaded = 0u64;
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

        match process_one(&client, &rec.sha256, &rec.path, no_upload) {
            Ok(Outcome::Analyzed {
                analysis,
                uploaded: up,
            }) => {
                found += 1;
                if up {
                    uploaded += 1;
                }
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
            Ok(Outcome::NotFound) => {
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
        OutputFormat::Json => {
            print_summary_json(total as u64, found, uploaded, not_found, errors)?;
        }
    }

    Ok(())
}

/// Process a single binary through openbinary.
///
/// Returns [`Outcome::Analyzed`] if found or successfully uploaded and analyzed
/// (with `uploaded` reflecting whether this run uploaded it),
/// [`Outcome::NotFound`] if unknown and upload is disabled, or `Err` on API
/// failure.
fn process_one(
    client: &OpenBinaryClient,
    sha256: &str,
    path: &str,
    no_upload: bool,
) -> Result<Outcome> {
    // Check if openbinary already knows this hash.
    if let Some(analysis) = client.get_analysis(sha256)? {
        return Ok(Outcome::Analyzed {
            analysis: analysis.into_raw(),
            uploaded: false,
        });
    }

    if no_upload {
        return Ok(Outcome::NotFound);
    }

    // Upload for analysis (same flow as `macwarden lookup`).
    let file_path = std::path::Path::new(path);
    if !file_path.is_file() {
        return Ok(Outcome::NotFound);
    }

    let job_id = match client.upload(file_path)? {
        UploadResult::AlreadyDone { sha256: ref s, .. } => {
            return fetch_uploaded(client, s);
        }
        UploadResult::Pending { job_id } => job_id,
    };

    // Poll until done.
    let status = client.poll_job(&job_id, &mut |_| {})?;
    if let JobStatus::Failed(e) = status {
        anyhow::bail!("analysis failed: {e}");
    }

    fetch_uploaded(client, sha256)
}

/// Fetch the analysis for a binary that was just uploaded this run.
fn fetch_uploaded(client: &OpenBinaryClient, sha256: &str) -> Result<Outcome> {
    match client.get_analysis(sha256)? {
        Some(analysis) => Ok(Outcome::Analyzed {
            analysis: analysis.into_raw(),
            uploaded: true,
        }),
        None => Ok(Outcome::NotFound),
    }
}

/// Print a human-readable summary.
fn print_summary(total: u64, found: u64, uploaded: u64, not_found: u64, errors: u64) {
    println!();
    println!("  Inventory lookup complete");
    println!("    Total:     {total}");
    println!("    Analyzed:  {found}");
    if uploaded > 0 {
        println!("    Uploaded:  {uploaded}");
    }
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
    uploaded: u64,
    not_found: u64,
    errors: u64,
) -> Result<()> {
    let json = serde_json::json!({
        "total": total,
        "analyzed": found,
        "uploaded": uploaded,
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
