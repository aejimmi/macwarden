//! `macwarden lookup <path>` — look up a binary on openbinary.
//!
//! Flow: SHA256 → GET lookup → auto-upload if unknown → poll → display.

use std::io::{Write, stderr};

use anyhow::{Context, Result, bail};

use crate::cli::OutputFormat;
use crate::openbinary::{
    self, AnalysisJson, JobStatus, UploadResult, extract_capabilities, extract_string_list,
};

/// Run the lookup command.
pub fn run(path: &str, no_upload: bool, format: OutputFormat) -> Result<()> {
    let path = resolve_path(path)?;
    if !path.exists() {
        bail!("file not found: {}", path.display());
    }
    if !path.is_file() {
        bail!("not a file: {}", path.display());
    }

    let base = openbinary::endpoint();

    // 1. Hash locally.
    eprint!("  Hashing... ");
    let sha256 = openbinary::hash_file(&path)?;
    eprintln!("{}", &sha256[..16]);

    // 2. Lookup by hash.
    if let Some(analysis) = openbinary::get_binary(&base, &sha256)? {
        eprintln!("  \u{2713} Found on openbinary\n");
        display(&analysis, &sha256, format);
        return Ok(());
    }

    if no_upload {
        eprintln!("  \u{2717} Not in openbinary database.");
        return Ok(());
    }
    eprint!("  Not found. Uploading for analysis... ");

    // 3. Upload.
    let job_id = match openbinary::upload(&base, &path)? {
        UploadResult::AlreadyDone { sha256, name } => {
            eprintln!("already analyzed ({name}).");
            let analysis =
                openbinary::get_binary(&base, &sha256)?.context("binary vanished after upload")?;
            display(&analysis, &sha256, format);
            return Ok(());
        }
        UploadResult::Pending { job_id } => {
            eprintln!("done.");
            job_id
        }
    };

    // 4. Poll for completion.
    eprint!("  Analyzing... ");
    let status = openbinary::poll_job(&base, &job_id, &mut |s| match s {
        JobStatus::Pending => eprint_flush("waiting... "),
        JobStatus::Running => eprint_flush("running... "),
        JobStatus::Done => eprintln!("done."),
        JobStatus::Failed(e) => eprintln!("failed: {e}"),
    })?;

    if let JobStatus::Failed(e) = status {
        bail!("analysis failed: {e}");
    }

    // 5. Fetch results.
    eprintln!();
    let analysis =
        openbinary::get_binary(&base, &sha256)?.context("analysis missing after completion")?;
    display(&analysis, &sha256, format);

    Ok(())
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

fn display(analysis: &AnalysisJson, sha256: &str, format: OutputFormat) {
    match format {
        OutputFormat::Table => print_table(analysis, sha256),
        OutputFormat::Json => print_json(analysis),
    }
}

fn print_table(a: &AnalysisJson, sha256: &str) {
    let name = a
        .pointer("/fingerprint/name")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let capabilities = extract_capabilities(a);
    let frameworks = extract_string_list(a, &["dna", "sets", "frameworks"]);
    let entitlements = extract_string_list(a, &["dna", "sets", "entitlements"]);

    let endpoint = openbinary::endpoint();
    // Strip /api/v1 to get the base URL for the web link.
    let web_base = endpoint.strip_suffix("/api/v1").unwrap_or(&endpoint);

    println!("  {name}");
    println!(
        "    Capabilities:  {}",
        if capabilities.is_empty() {
            "none".to_owned()
        } else {
            capabilities.join(", ")
        }
    );
    println!(
        "    Frameworks:    {}",
        if frameworks.is_empty() {
            "none".to_owned()
        } else {
            summarize(&frameworks, 5)
        }
    );
    println!(
        "    Entitlements:  {}",
        if entitlements.is_empty() {
            "none".to_owned()
        } else {
            summarize(&entitlements, 5)
        }
    );
    println!();
    println!("    {web_base}/binary/{sha256}");
}

fn print_json(a: &AnalysisJson) {
    // serde_json::to_string_pretty won't fail on a valid Value.
    if let Ok(json) = serde_json::to_string_pretty(a) {
        println!("{json}");
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a path, expanding `~`.
fn resolve_path(raw: &str) -> Result<std::path::PathBuf> {
    crate::cli::expand_home(raw)
}

/// Show first `n` items, then "+ N more".
fn summarize(items: &[String], n: usize) -> String {
    if items.len() <= n {
        items.join(", ")
    } else {
        let shown: Vec<&str> = items.iter().take(n).map(String::as_str).collect();
        format!("{} (+{} more)", shown.join(", "), items.len() - n)
    }
}

fn eprint_flush(msg: &str) {
    let _ = write!(stderr(), "{msg}");
    let _ = stderr().flush();
}
