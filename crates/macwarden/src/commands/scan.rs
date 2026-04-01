//! `macwarden scan` — discover and list all launchd services.

use anyhow::{Context, Result};
use tabled::settings::Style;
use tabled::{Table, Tabled};

use catalog::{AnnotationDb, annotate_services, discover_plists};
use launchd::{MacOsPlatform, Platform};
use policy::{ServiceCategory, ServiceInfo, ServiceState};

use crate::cli::{self, OutputFormat};

// ---------------------------------------------------------------------------
// Table row
// ---------------------------------------------------------------------------

/// A single row in the scan output table.
#[derive(Debug, Tabled, serde::Serialize)]
struct ServiceRow {
    #[tabled(rename = "Label")]
    label: String,
    #[tabled(rename = "State")]
    state: String,
    #[tabled(rename = "Category")]
    category: String,
    #[tabled(rename = "Safety")]
    safety: String,
    #[tabled(rename = "Description")]
    description: String,
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `scan` command.
///
/// Discovers all plist files, annotates them, and prints the result as a table
/// or JSON. Optionally filters by category or unknown-only.
pub fn run(category: Option<&str>, unknown_only: bool, format: OutputFormat) -> Result<()> {
    let services = discover_services()?;

    let filtered = filter_services(&services, category, unknown_only);

    let running = filtered
        .iter()
        .filter(|s| s.state == policy::ServiceState::Running)
        .count();
    let disabled = filtered
        .iter()
        .filter(|s| s.state == policy::ServiceState::Disabled)
        .count();

    match format {
        OutputFormat::Table => print_table(&filtered, running, disabled),
        OutputFormat::Json => print_json(&filtered)?,
    }

    Ok(())
}

/// Discover services from plist directories, annotate them, and enrich with
/// runtime state from `launchctl list`.
pub fn discover_services() -> Result<Vec<ServiceInfo>> {
    let dirs = cli::plist_dirs().context("failed to expand plist directories")?;
    let db = AnnotationDb::load_builtin();
    let plists = discover_plists(&dirs);
    let mut services = annotate_services(&plists, &db);

    // Merge runtime state from launchctl list.
    let platform = MacOsPlatform::new();
    match platform.enumerate() {
        Ok(entries) => {
            for svc in &mut services {
                if let Some(entry) = entries.iter().find(|e| e.label == svc.label) {
                    if let Some(pid) = entry.pid {
                        svc.state = ServiceState::Running;
                        svc.pid = Some(pid);
                    } else {
                        // launchctl knows about it but no PID — it's loaded but stopped.
                        if svc.state == ServiceState::Unknown {
                            svc.state = ServiceState::Stopped;
                        }
                    }
                }
            }
            // Also add services from launchctl that have no plist (runtime-only).
            for entry in &entries {
                if !services.iter().any(|s| s.label == entry.label) {
                    let annotation = db.lookup(&entry.label);
                    let state = if entry.pid.is_some() {
                        ServiceState::Running
                    } else {
                        ServiceState::Stopped
                    };
                    services.push(ServiceInfo {
                        label: entry.label.clone(),
                        domain: policy::Domain::System,
                        plist_path: None,
                        state,
                        category: annotation.map_or(ServiceCategory::Unknown, |a| a.category),
                        safety: annotation.map_or(policy::SafetyLevel::Optional, |a| a.safety),
                        description: annotation.map(|a| a.description.clone()),
                        pid: entry.pid,
                    });
                }
            }
        }
        Err(e) => {
            tracing::warn!(error = %e, "could not query launchctl — state will be incomplete");
        }
    }

    Ok(services)
}

/// Apply category and unknown-only filters.
fn filter_services<'a>(
    services: &'a [ServiceInfo],
    category: Option<&str>,
    unknown_only: bool,
) -> Vec<&'a ServiceInfo> {
    services
        .iter()
        .filter(|s| {
            if unknown_only {
                return s.category == ServiceCategory::Unknown;
            }
            if let Some(cat) = category {
                return s.category.to_string() == cat;
            }
            true
        })
        .collect()
}

/// Format a service as a table row.
fn to_row(svc: &ServiceInfo) -> ServiceRow {
    let desc = svc
        .description
        .as_deref()
        .unwrap_or("")
        .chars()
        .take(40)
        .collect::<String>();

    ServiceRow {
        label: svc.label.clone(),
        state: svc.state.to_string(),
        category: svc.category.to_string(),
        safety: svc.safety.to_string(),
        description: desc,
    }
}

/// Print the service list as a formatted table.
fn print_table(services: &[&ServiceInfo], running: usize, disabled: usize) {
    let rows: Vec<ServiceRow> = services.iter().map(|s| to_row(s)).collect();
    let table = Table::new(&rows).with(Style::rounded()).to_string();

    println!("{table}");
    println!(
        "\nFound {} services ({} running, {} disabled)",
        services.len(),
        running,
        disabled,
    );
}

/// Print the service list as JSON.
fn print_json(services: &[&ServiceInfo]) -> Result<()> {
    let json = serde_json::to_string_pretty(&services).context("failed to serialize to JSON")?;
    println!("{json}");
    Ok(())
}
