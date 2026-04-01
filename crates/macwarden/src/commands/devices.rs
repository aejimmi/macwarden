//! `macwarden devices` — show what has access to your camera and microphone.
//!
//! Queries the macOS TCC (Transparency, Consent, and Control) database to find
//! which apps are authorized to use the camera and microphone, then
//! cross-references with running processes and macwarden's service catalog.
//!
//! Supports revoking access via `tccutil reset` for apps that should no longer
//! have camera/mic permissions (including ghost authorizations from uninstalled
//! apps that persist in TCC).
//!
//! Falls back to showing known media services from the catalog when the TCC
//! database is not readable (requires Full Disk Access or SIP disabled).

use std::collections::HashMap;
use std::fmt;
use std::process::Command;

use anyhow::{Context, Result};
use tabled::settings::Style;
use tabled::{Table, Tabled};

use catalog::load_builtin_groups;
use launchd::{MacOsPlatform, Platform};
use policy::{ServiceCategory, ServiceGroup, find_groups_for_service};

use crate::cli::OutputFormat;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which hardware device the authorization applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum Device {
    Camera,
    Microphone,
}

impl fmt::Display for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Camera => write!(f, "camera"),
            Self::Microphone => write!(f, "mic"),
        }
    }
}

/// TCC authorization status for an app.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum TccStatus {
    /// User granted access (auth_value = 2).
    Allowed,
    /// User denied access or toggled off (auth_value = 0).
    Denied,
    /// Limited access (auth_value = 3).
    Limited,
}

impl fmt::Display for TccStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::Denied => write!(f, "denied"),
            Self::Limited => write!(f, "limited"),
        }
    }
}

/// An app with a TCC entry for camera or microphone.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceEntry {
    /// Camera or microphone.
    pub device: Device,
    /// Bundle ID or path from the TCC `client` column.
    pub client: String,
    /// TCC authorization status.
    pub status: TccStatus,
    /// Whether the app is currently running.
    pub running: bool,
    /// Process ID if running.
    pub pid: Option<u32>,
    /// macwarden service group name, if the app maps to a known group.
    pub group: Option<String>,
}

/// Table row for the formatted output.
#[derive(Debug, Tabled)]
struct DeviceRow {
    #[tabled(rename = "Device")]
    device: String,
    #[tabled(rename = "App")]
    client: String,
    #[tabled(rename = "Access")]
    status: String,
    #[tabled(rename = "Running")]
    running: String,
    #[tabled(rename = "PID")]
    pid: String,
    #[tabled(rename = "Group")]
    group: String,
}

/// Fallback table row when TCC is unreadable.
#[derive(Debug, Tabled)]
struct MediaRow {
    #[tabled(rename = "Service")]
    label: String,
    #[tabled(rename = "State")]
    state: String,
    #[tabled(rename = "Category")]
    category: String,
    #[tabled(rename = "Safety")]
    safety: String,
}

// ---------------------------------------------------------------------------
// TCC constants
// ---------------------------------------------------------------------------

/// TCC service identifier for camera access.
const TCC_CAMERA: &str = "kTCCServiceCamera";

/// TCC service identifier for microphone access.
const TCC_MICROPHONE: &str = "kTCCServiceMicrophone";

/// TCC `auth_value` for user-granted access.
const AUTH_ALLOWED: i32 = 2;

/// TCC `auth_value` for user-denied access.
const AUTH_DENIED: i32 = 0;

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `devices` command.
#[allow(clippy::unnecessary_wraps)]
pub fn run(format: OutputFormat) -> Result<()> {
    let groups = load_builtin_groups();

    // Build PID -> service label map from launchctl.
    let platform = MacOsPlatform::new();
    let pid_to_label: HashMap<u32, String> = platform
        .enumerate()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|e| e.pid.map(|p| (p, e.label)))
        .collect();

    // Check hardware state via CoreAudio/CoreMediaIO.
    let mic_active = sensors::microphone::is_active().unwrap_or(false);
    let cam_active = sensors::camera::is_active().unwrap_or(false);

    println!(
        "Camera: {}  Microphone: {}\n",
        if cam_active { "ACTIVE" } else { "not active" },
        if mic_active { "ACTIVE" } else { "not active" },
    );

    // Try TCC database.
    match query_tcc(&pid_to_label, &groups) {
        Ok(entries) if !entries.is_empty() => {
            print_results(&entries, format);
        }
        Ok(_) => {
            println!("No camera or microphone entries found in TCC database.");
        }
        Err(e) => {
            tracing::debug!(error = %e, "TCC query failed");
            println!("TCC database not readable ({e}).");
            println!("Grant Full Disk Access to your terminal, or run with SIP disabled.\n");
            print_media_fallback(format)?;
        }
    }

    Ok(())
}

/// Revoke camera and microphone access for an app via `tccutil reset`.
pub fn revoke(bundle_id: &str) -> Result<()> {
    println!("Revoking camera and microphone access for {bundle_id}...\n");

    let services = [("Camera", TCC_CAMERA), ("Microphone", TCC_MICROPHONE)];

    for (label, _tcc_name) in &services {
        let output = Command::new("tccutil")
            .args(["reset", label, bundle_id])
            .output()
            .context("failed to run tccutil")?;

        if output.status.success() {
            println!("  {label}: revoked");
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let stderr = stderr.trim();
            if stderr.is_empty() {
                // tccutil often succeeds silently even if there was no entry.
                println!("  {label}: revoked (or no entry)");
            } else {
                println!("  {label}: failed ({stderr})");
            }
        }
    }

    println!(
        "\nThe app will need to request permission again next time it tries \
         to use the camera or microphone."
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// TCC query
// ---------------------------------------------------------------------------

/// A raw entry parsed from the TCC database.
#[derive(Debug, Clone)]
struct TccEntry {
    service: String,
    client: String,
    auth_value: i32,
}

/// Query both user-level and system-level TCC databases, merge, deduplicate,
/// and cross-reference with running processes.
fn query_tcc(
    pid_to_label: &HashMap<u32, String>,
    groups: &[ServiceGroup],
) -> Result<Vec<DeviceEntry>> {
    let user_db = expand_tcc_path("~/Library/Application Support/com.apple.TCC/TCC.db")?;

    let mut entries = read_tcc_db(&user_db)?;

    // System-level TCC (needs root — best-effort).
    let system_db = "/Library/Application Support/com.apple.TCC/TCC.db";
    if let Ok(system_entries) = read_tcc_db(system_db) {
        for entry in system_entries {
            let dup = entries
                .iter()
                .any(|e| e.service == entry.service && e.client == entry.client);
            if !dup {
                entries.push(entry);
            }
        }
    }

    // Collect running processes for cross-referencing.
    let procs = collect_running_processes()?;

    // Convert to DeviceEntry with status, running state, and group info.
    let mut result: Vec<DeviceEntry> = entries
        .into_iter()
        .map(|tcc| {
            let device = if tcc.service == TCC_CAMERA {
                Device::Camera
            } else {
                Device::Microphone
            };

            let status = match tcc.auth_value {
                AUTH_ALLOWED => TccStatus::Allowed,
                AUTH_DENIED => TccStatus::Denied,
                _ => TccStatus::Limited,
            };

            let (running, pid, group) = resolve_process(&tcc.client, pid_to_label, &procs, groups);

            DeviceEntry {
                device,
                client: tcc.client,
                status,
                running,
                pid,
                group,
            }
        })
        .collect();

    // Sort: camera before mic, allowed before denied, running before not, alpha.
    result.sort_by(|a, b| {
        let dev_rank = |d: Device| match d {
            Device::Camera => 0u8,
            Device::Microphone => 1,
        };
        let status_rank = |s: TccStatus| match s {
            TccStatus::Allowed => 0u8,
            TccStatus::Limited => 1,
            TccStatus::Denied => 2,
        };
        dev_rank(a.device)
            .cmp(&dev_rank(b.device))
            .then_with(|| status_rank(a.status).cmp(&status_rank(b.status)))
            .then_with(|| b.running.cmp(&a.running))
            .then_with(|| a.client.cmp(&b.client))
    });

    Ok(result)
}

/// Run `sqlite3` to read TCC entries from a database file.
fn read_tcc_db(path: &str) -> Result<Vec<TccEntry>> {
    let query = format!(
        "SELECT service, client, auth_value FROM access \
         WHERE service IN ('{TCC_CAMERA}', '{TCC_MICROPHONE}')"
    );

    let output = Command::new("sqlite3")
        .args(["-separator", "|", path, &query])
        .output()
        .context("failed to run sqlite3")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{}", stderr.trim());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_tcc_output(&stdout))
}

/// Parse pipe-delimited sqlite3 output into `TccEntry` values.
fn parse_tcc_output(output: &str) -> Vec<TccEntry> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.splitn(3, '|');
            let service = parts.next()?.trim();
            let client = parts.next()?.trim();
            let auth_str = parts.next()?.trim();

            if service.is_empty() || client.is_empty() {
                return None;
            }

            let auth_value = auth_str.parse::<i32>().unwrap_or(-1);

            Some(TccEntry {
                service: service.to_owned(),
                client: client.to_owned(),
                auth_value,
            })
        })
        .collect()
}

/// Expand a leading `~` to `$HOME`.
fn expand_tcc_path(path: &str) -> Result<String> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").context("HOME not set")?;
        Ok(format!("{home}/{rest}"))
    } else {
        Ok(path.to_owned())
    }
}

// ---------------------------------------------------------------------------
// Process resolution
// ---------------------------------------------------------------------------

/// Minimal info from `ps` for cross-referencing with TCC clients.
struct RunningProc {
    pid: u32,
    command: String,
}

/// Collect running processes via `ps -axo pid=,comm=`.
fn collect_running_processes() -> Result<Vec<RunningProc>> {
    let output = Command::new("ps")
        .args(["-axo", "pid=,comm="])
        .output()
        .context("failed to run ps")?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(parse_ps_output(&stdout))
}

/// Parse `ps -axo pid=,comm=` output.
fn parse_ps_output(output: &str) -> Vec<RunningProc> {
    output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (pid_str, cmd) = trimmed.split_once(char::is_whitespace)?;
            let pid = pid_str.trim().parse::<u32>().ok()?;
            Some(RunningProc {
                pid,
                command: cmd.trim().to_owned(),
            })
        })
        .collect()
}

/// Match a TCC client (bundle ID or path) against running processes and
/// launchctl services.
///
/// Returns `(is_running, pid, group_name)`.
fn resolve_process(
    client: &str,
    pid_to_label: &HashMap<u32, String>,
    procs: &[RunningProc],
    groups: &[ServiceGroup],
) -> (bool, Option<u32>, Option<String>) {
    // 1. Exact match on launchctl label.
    for (&pid, label) in pid_to_label {
        if label == client {
            let group = first_group(label, groups);
            return (true, Some(pid), group);
        }
    }

    // 2. Application-style label: "application.com.apple.Safari.12345".
    for (&pid, label) in pid_to_label {
        if label.starts_with("application.") && label.contains(client) {
            let group = first_group(label, groups);
            return (true, Some(pid), group);
        }
    }

    // 3. Match by process command basename.
    //    TCC clients are bundle IDs like "com.apple.Safari" — extract the
    //    short name ("Safari") and match against the executable basename.
    let short = client.rsplit('.').next().unwrap_or(client);

    for proc in procs {
        let basename = proc.command.rsplit('/').next().unwrap_or(&proc.command);

        if basename.eq_ignore_ascii_case(short) {
            let group = pid_to_label
                .get(&proc.pid)
                .and_then(|l| first_group(l, groups));
            return (true, Some(proc.pid), group);
        }
    }

    // 4. Broader substring match on the full command path.
    let client_lower = client.to_lowercase();
    for proc in procs {
        if proc.command.to_lowercase().contains(&client_lower) {
            let group = pid_to_label
                .get(&proc.pid)
                .and_then(|l| first_group(l, groups));
            return (true, Some(proc.pid), group);
        }
    }

    (false, None, None)
}

/// Return the first group name for a service label, if any.
fn first_group(label: &str, groups: &[ServiceGroup]) -> Option<String> {
    find_groups_for_service(label, groups)
        .first()
        .map(|g| g.name.clone())
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

/// Print TCC-based results as a table or JSON.
fn print_results(entries: &[DeviceEntry], format: OutputFormat) {
    let cam_allowed = entries
        .iter()
        .filter(|e| e.device == Device::Camera && e.status == TccStatus::Allowed)
        .count();
    let mic_allowed = entries
        .iter()
        .filter(|e| e.device == Device::Microphone && e.status == TccStatus::Allowed)
        .count();
    let cam_denied = entries
        .iter()
        .filter(|e| e.device == Device::Camera && e.status == TccStatus::Denied)
        .count();
    let mic_denied = entries
        .iter()
        .filter(|e| e.device == Device::Microphone && e.status == TccStatus::Denied)
        .count();
    let running = entries
        .iter()
        .filter(|e| e.running && e.status == TccStatus::Allowed)
        .count();
    let grouped = entries.iter().filter(|e| e.group.is_some()).count();

    match format {
        OutputFormat::Table => {
            let rows: Vec<DeviceRow> = entries
                .iter()
                .map(|e| DeviceRow {
                    device: e.device.to_string(),
                    client: truncate(&e.client, 40),
                    status: e.status.to_string(),
                    running: if e.running {
                        "yes".to_owned()
                    } else {
                        "no".to_owned()
                    },
                    pid: e
                        .pid
                        .map_or_else(|| "\u{2014}".to_owned(), |p| p.to_string()),
                    group: e.group.clone().unwrap_or_else(|| "\u{2014}".to_owned()),
                })
                .collect();

            let table = Table::new(&rows).with(Style::rounded()).to_string();
            println!("{table}");
            println!(
                "\nCamera: {cam_allowed} allowed, {cam_denied} denied. \
                 Microphone: {mic_allowed} allowed, {mic_denied} denied.",
            );
            if running > 0 || grouped > 0 {
                println!("{running} authorized apps running, {grouped} in known groups.",);
            }

        }
        OutputFormat::Json => {
            let json =
                serde_json::to_string_pretty(entries).expect("serialization should not fail");
            println!("{json}");
        }
    }
}

/// Fallback: show known media services from the catalog.
fn print_media_fallback(format: OutputFormat) -> Result<()> {
    let services = super::scan::discover_services()?;
    let media: Vec<_> = services
        .iter()
        .filter(|s| s.category == ServiceCategory::Media)
        .collect();

    if media.is_empty() {
        println!("No known media services found in catalog.");
        return Ok(());
    }

    println!("Known camera/microphone services from catalog:\n");

    match format {
        OutputFormat::Table => {
            let rows: Vec<MediaRow> = media
                .iter()
                .map(|s| MediaRow {
                    label: s.label.clone(),
                    state: s.state.to_string(),
                    category: s.category.to_string(),
                    safety: s.safety.to_string(),
                })
                .collect();

            let table = Table::new(&rows).with(Style::rounded()).to_string();
            println!("{table}");
            println!(
                "\n{} media services ({} running)",
                media.len(),
                media
                    .iter()
                    .filter(|s| s.state == policy::ServiceState::Running)
                    .count(),
            );
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&media).expect("serialization should not fail");
            println!("{json}");
        }
    }

    Ok(())
}

/// Truncate a string to `max` characters, appending ellipsis if needed.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() > max {
        let truncated: String = s.chars().take(max - 1).collect();
        return format!("{truncated}\u{2026}");
    }
    s.to_owned()
}

#[cfg(test)]
#[path = "devices_test.rs"]
mod devices_test;
