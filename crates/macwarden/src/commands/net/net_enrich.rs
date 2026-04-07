//! `macwarden net enrich` — download or manage GeoIP databases.
//!
//! Downloads MaxMind GeoLite2 databases to `~/.macwarden/geo/` for IP
//! enrichment in scan, network, and learn commands. Requires a free
//! MaxMind license key.

use std::fs;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result, bail};
use tracing::info;

/// MaxMind download URL template. Edition and key are interpolated.
const DOWNLOAD_URL: &str = "https://download.maxmind.com/app/geoip_download?edition_id={EDITION}&license_key={KEY}&suffix=tar.gz";

/// Database editions to download.
const EDITIONS: [&str; 2] = ["GeoLite2-Country", "GeoLite2-ASN"];

/// Run `macwarden net enrich`.
pub(super) fn run(key: Option<&str>, remove: bool, status: bool) -> Result<()> {
    if status {
        return run_status();
    }
    if remove {
        return run_remove();
    }
    run_download(key)
}

/// Show the current state of geo databases.
fn run_status() -> Result<()> {
    let dir = net::geo_dir().map_err(|e| anyhow::anyhow!("HOME not set: {e}"))?;

    println!("GeoIP Database Status");
    println!("  Directory: {}", dir.display());
    println!();

    if !dir.exists() {
        println!("  Not installed. Run `macwarden net enrich --key <KEY>` to download.");
        println!("  Get a free key at: https://www.maxmind.com/en/geolite2/signup");
        return Ok(());
    }

    for edition in &EDITIONS {
        let path = dir.join(format!("{edition}.mmdb"));
        if path.is_file() {
            let meta = fs::metadata(&path).context("failed to read file metadata")?;
            let size = meta.len();
            let modified = meta
                .modified()
                .ok()
                .and_then(|t| t.elapsed().ok())
                .map_or_else(
                    || "unknown".to_owned(),
                    |d| format!("{}d ago", d.as_secs() / 86400),
                );
            println!(
                "  {edition}.mmdb  {:.1} MB  modified {modified}",
                size as f64 / 1_048_576.0
            );
        } else {
            println!("  {edition}.mmdb  MISSING");
        }
    }

    if net::databases_available() {
        let age = db_age_days(&dir);
        if let Some(days) = age
            && days > 30
        {
            println!();
            println!(
                "  Databases are {days}d old. Run `macwarden net enrich --key <KEY>` to refresh."
            );
        }
    }

    Ok(())
}

/// Remove downloaded databases.
fn run_remove() -> Result<()> {
    let dir = net::geo_dir().map_err(|e| anyhow::anyhow!("HOME not set: {e}"))?;

    if !dir.exists() {
        println!("No GeoIP databases installed.");
        return Ok(());
    }

    let mut removed = 0u32;
    for edition in &EDITIONS {
        let path = dir.join(format!("{edition}.mmdb"));
        if path.is_file() {
            fs::remove_file(&path)
                .with_context(|| format!("failed to remove {}", path.display()))?;
            removed += 1;
        }
    }

    if removed > 0 {
        println!("Removed {removed} GeoIP database(s).");
    } else {
        println!("No GeoIP databases found to remove.");
    }

    // Remove the directory if empty.
    if dir.exists() && fs::read_dir(&dir).is_ok_and(|mut d| d.next().is_none()) {
        let _ = fs::remove_dir(&dir);
    }

    Ok(())
}

/// Download databases from MaxMind.
fn run_download(key: Option<&str>) -> Result<()> {
    let license_key = key
        .map(String::from)
        .or_else(|| std::env::var("MAXMIND_LICENSE_KEY").ok());

    let Some(license_key) = license_key else {
        bail!(
            "MaxMind license key required.\n\n\
             Provide via --key or MAXMIND_LICENSE_KEY env var.\n\
             Get a free key at: https://www.maxmind.com/en/geolite2/signup"
        );
    };

    let dir = net::geo_dir().map_err(|e| anyhow::anyhow!("HOME not set: {e}"))?;
    fs::create_dir_all(&dir).context("failed to create geo directory")?;

    println!("Downloading GeoIP databases to {}", dir.display());
    println!();

    for edition in &EDITIONS {
        print!("  {edition}...");
        match download_edition(edition, &license_key, &dir) {
            Ok(size) => {
                println!(" {:.1} MB", size as f64 / 1_048_576.0);
            }
            Err(e) => {
                println!(" FAILED");
                eprintln!("    Error: {e}");
                // Continue with other editions.
            }
        }
    }

    println!();
    if net::databases_available() {
        println!("GeoIP enrichment is now active.");
        println!("IP lookups in `net scan`, `network`, and `net learn` will show country and ASN.");
    } else {
        println!("Some databases failed to download. Run again or check your license key.");
    }

    Ok(())
}

/// Download a single edition, extract the .mmdb, and write it to `dir`.
fn download_edition(edition: &str, key: &str, dir: &Path) -> Result<u64> {
    let url = DOWNLOAD_URL
        .replace("{EDITION}", edition)
        .replace("{KEY}", key);

    info!(edition, "downloading GeoIP database");

    let response = ureq::get(&url)
        .call()
        .context("HTTP request failed — check your license key")?;

    let status = response.status();
    if status != 200 {
        bail!("MaxMind returned HTTP {status} — is your license key valid?");
    }

    // Response is a .tar.gz — extract the .mmdb file.
    let reader = response.into_body().into_reader();
    let decoder = flate2::read::GzDecoder::new(reader);
    let mut archive = tar::Archive::new(decoder);

    let mmdb_name = format!("{edition}.mmdb");
    let dest = dir.join(&mmdb_name);

    for entry_result in archive.entries().context("failed to read tar archive")? {
        let mut entry = entry_result.context("corrupted tar entry")?;
        let path = entry.path().context("invalid tar entry path")?;

        if path
            .file_name()
            .is_some_and(|n| n.to_string_lossy() == mmdb_name)
        {
            let mut buf = Vec::new();
            entry
                .read_to_end(&mut buf)
                .context("failed to read mmdb from archive")?;
            fs::write(&dest, &buf)
                .with_context(|| format!("failed to write {}", dest.display()))?;
            return Ok(buf.len() as u64);
        }
    }

    bail!("archive did not contain {mmdb_name}");
}

/// Return the age in days of the oldest database in the directory.
fn db_age_days(dir: &Path) -> Option<u64> {
    EDITIONS
        .iter()
        .filter_map(|edition| {
            let path = dir.join(format!("{edition}.mmdb"));
            let meta = fs::metadata(&path).ok()?;
            let modified = meta.modified().ok()?;
            let elapsed = modified.elapsed().ok()?;
            Some(elapsed.as_secs() / 86400)
        })
        .max()
}

#[cfg(test)]
#[path = "net_enrich_test.rs"]
mod net_enrich_test;
