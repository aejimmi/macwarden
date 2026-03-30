//! `macwarden groups` -- list all service groups with service counts.

use anyhow::Result;
use tabled::settings::Style;
use tabled::{Table, Tabled};

use macwarden_catalog::load_builtin_groups;
use macwarden_core::{Safety, ServiceState, resolve_group_services};

use crate::cli::{GroupSort, SafetyFilter};
use crate::commands::scan::discover_services;

// ---------------------------------------------------------------------------
// Table row
// ---------------------------------------------------------------------------

/// A single row in the groups output table.
#[derive(Debug, Tabled)]
struct GroupRow {
    #[tabled(rename = "Group")]
    name: String,
    #[tabled(rename = "Safety")]
    safety: String,
    #[tabled(rename = "Services")]
    total: usize,
    #[tabled(rename = "Running")]
    running: usize,
    #[tabled(rename = "Description")]
    description: String,
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `groups` command.
///
/// Lists all built-in service groups, showing how many services match each
/// group and how many of those are currently running.
pub fn run(sort: GroupSort, filter: Option<SafetyFilter>) -> Result<()> {
    let services = discover_services()?;
    let groups = load_builtin_groups();

    let filter_safety = filter.map(|f| match f {
        SafetyFilter::Recommended => Safety::Recommended,
        SafetyFilter::Optional => Safety::Optional,
        SafetyFilter::Keep => Safety::Keep,
    });

    let mut rows: Vec<GroupRow> = groups
        .iter()
        .filter(|group| filter_safety.is_none_or(|s| group.safety == s))
        .map(|group| {
            let matched = resolve_group_services(group, &services);
            let running = matched
                .iter()
                .filter(|s| s.state == ServiceState::Running)
                .count();
            GroupRow {
                name: group.name.clone(),
                safety: group.safety.to_string(),
                total: matched.len(),
                running,
                description: group.description.clone(),
            }
        })
        .collect();

    match sort {
        GroupSort::Name => rows.sort_by(|a, b| a.name.cmp(&b.name)),
        GroupSort::Services => rows.sort_by(|a, b| b.total.cmp(&a.total)),
        GroupSort::Running => rows.sort_by(|a, b| b.running.cmp(&a.running)),
        GroupSort::Safety => {
            rows.sort_by(|a, b| a.safety.cmp(&b.safety).then_with(|| a.name.cmp(&b.name)));
        }
    }

    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("{table}");
    println!("\n{} groups shown", rows.len());

    Ok(())
}
