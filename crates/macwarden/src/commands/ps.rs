//! `macwarden ps` -- list all running processes grouped by service groups.

use std::collections::HashMap;

use anyhow::{Context, Result};
use tabled::settings::Style;
use tabled::{Table, Tabled};

use macwarden_catalog::load_builtin_groups;
use macwarden_core::{ServiceGroup, find_groups_for_service};
use macwarden_launchd::{MacOsPlatform, Platform};

use crate::cli::OutputFormat;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A running process with optional service/group annotation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProcessEntry {
    /// Process ID.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// User who owns the process.
    pub user: String,
    /// CPU usage percentage.
    pub cpu: f32,
    /// Memory usage percentage.
    pub mem_pct: f32,
    /// Resident set size in kilobytes.
    pub rss_kb: u64,
    /// Command path/name.
    pub command: String,
    /// Service group name if the process maps to a known group.
    pub group: Option<String>,
    /// Launchd label if the process is a managed service.
    pub service: Option<String>,
}

/// Table row for the tabled output.
#[derive(Debug, Tabled)]
struct PsRow {
    #[tabled(rename = "Group")]
    group: String,
    #[tabled(rename = "PID")]
    pid: u32,
    #[tabled(rename = "CPU%")]
    cpu: String,
    #[tabled(rename = "Mem(MB)")]
    mem_mb: String,
    #[tabled(rename = "User")]
    user: String,
    #[tabled(rename = "Command")]
    command: String,
}

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `ps` command.
///
/// Lists all running processes, annotated with launchd service labels and
/// group membership.
pub fn run(format: OutputFormat, tree: bool) -> Result<()> {
    let groups = load_builtin_groups();
    let entries = collect_processes(&groups)?;

    if tree {
        print_tree(&entries);
        return Ok(());
    }

    match format {
        OutputFormat::Table => print_table(&entries, groups.len()),
        OutputFormat::Json => print_json(&entries)?,
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Data collection
// ---------------------------------------------------------------------------

/// Collect all running processes, annotate with service labels and groups.
fn collect_processes(groups: &[ServiceGroup]) -> Result<Vec<ProcessEntry>> {
    let ps_output = run_ps().context("failed to run ps")?;
    let mut entries = parse_ps_output(&ps_output);

    // Build pid -> label map from launchctl.
    let platform = MacOsPlatform::new();
    let pid_labels: HashMap<u32, String> = match platform.enumerate() {
        Ok(lc_entries) => lc_entries
            .into_iter()
            .filter_map(|e| e.pid.map(|pid| (pid, e.label)))
            .collect(),
        Err(e) => {
            eprintln!("warning: could not query launchctl: {e}");
            HashMap::new()
        }
    };

    // Annotate each process with service label and group.
    for entry in &mut entries {
        if let Some(label) = pid_labels.get(&entry.pid) {
            entry.service = Some(label.clone());

            let matched_groups = find_groups_for_service(label, groups);
            if let Some(first_group) = matched_groups.first() {
                entry.group = Some(first_group.name.clone());
            }
        }
    }

    // Sort: grouped first (by group name), then ungrouped services, then others.
    // Within each section, sort by CPU descending.
    entries.sort_by(|a, b| {
        let rank_a = sort_rank(a);
        let rank_b = sort_rank(b);
        rank_a
            .cmp(&rank_b)
            .then_with(|| {
                // Within same rank, sort by group name.
                a.group.as_deref().cmp(&b.group.as_deref())
            })
            .then_with(|| {
                // Then by CPU descending.
                b.cpu
                    .partial_cmp(&a.cpu)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });

    Ok(entries)
}

/// Assign a sorting rank: 0 = has group, 1 = has service but no group, 2 = other.
fn sort_rank(entry: &ProcessEntry) -> u8 {
    if entry.group.is_some() {
        0
    } else if entry.service.is_some() {
        1
    } else {
        2
    }
}

/// Run `ps` and return its stdout.
fn run_ps() -> Result<String> {
    let output = std::process::Command::new("ps")
        .args(["-axo", "pid=,ppid=,user=,pcpu=,pmem=,rss=,comm="])
        .output()
        .context("failed to execute ps")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("ps failed: {stderr}");
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Parse the output of `ps -axo pid=,ppid=,user=,pcpu=,pmem=,rss=,comm=`.
///
/// Each line has 6 whitespace-delimited fields followed by the command which
/// may contain spaces. We use `split_whitespace` for the first 6 fields and
/// extract the remainder as the command string.
pub fn parse_ps_output(output: &str) -> Vec<ProcessEntry> {
    output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                return None;
            }

            let mut iter = trimmed.split_whitespace();
            let pid = iter.next()?.parse::<u32>().ok()?;
            let ppid = iter.next()?.parse::<u32>().ok()?;
            let user = iter.next()?.to_owned();
            let cpu = iter.next()?.parse::<f32>().ok()?;
            let mem_pct = iter.next()?.parse::<f32>().ok()?;
            let rss_kb = iter.next()?.parse::<u64>().ok()?;

            // The command is everything after the 6th field. Find it by
            // skipping past the first 6 whitespace-delimited tokens.
            let command = extract_command_field(trimmed, 6)?;

            Some(ProcessEntry {
                pid,
                ppid,
                user,
                cpu,
                mem_pct,
                rss_kb,
                command,
                group: None,
                service: None,
            })
        })
        .collect()
}

/// Skip past `n` whitespace-delimited fields and return the remainder.
fn extract_command_field(line: &str, skip: usize) -> Option<String> {
    let mut pos = 0;
    let bytes = line.as_bytes();
    let len = bytes.len();

    for _ in 0..skip {
        // Skip leading whitespace.
        while pos < len && bytes.get(pos).copied() == Some(b' ') {
            pos += 1;
        }
        // Skip non-whitespace (the field).
        while pos < len && bytes.get(pos).copied() != Some(b' ') {
            pos += 1;
        }
    }

    // Skip whitespace before command.
    while pos < len && bytes.get(pos).copied() == Some(b' ') {
        pos += 1;
    }

    if pos >= len {
        return None;
    }

    Some(line.get(pos..)?.to_owned())
}

// ---------------------------------------------------------------------------
// Table view
// ---------------------------------------------------------------------------

/// Print processes as a formatted table.
fn print_table(entries: &[ProcessEntry], group_count: usize) {
    let mut last_group: Option<&str> = None;
    let rows: Vec<PsRow> = entries
        .iter()
        .map(|e| {
            let group_display = if let Some(g) = &e.group {
                let g_str = g.as_str();
                if last_group == Some(g_str) {
                    // Blank for subsequent entries in same group.
                    String::new()
                } else {
                    last_group = Some(g_str);
                    g.clone()
                }
            } else {
                last_group = None;
                if e.service.is_some() {
                    // Ungrouped service.
                    "\u{00b7}".to_owned()
                } else {
                    // Not a service.
                    "\u{2014}".to_owned()
                }
            };

            let cmd_truncated: String = e.command.chars().take(40).collect();
            let mem_mb = format!("{:.1}", e.rss_kb as f64 / 1024.0);

            PsRow {
                group: group_display,
                pid: e.pid,
                cpu: format!("{:.1}", e.cpu),
                mem_mb,
                user: e.user.clone(),
                command: cmd_truncated,
            }
        })
        .collect();

    let total = entries.len();
    let grouped = entries.iter().filter(|e| e.group.is_some()).count();
    let services = entries.iter().filter(|e| e.service.is_some()).count();

    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("{table}");
    println!("\n{total} processes ({services} services, {grouped} in {group_count} groups)",);
}

// ---------------------------------------------------------------------------
// Tree view
// ---------------------------------------------------------------------------

/// Maximum depth for tree rendering.
const MAX_TREE_DEPTH: usize = 4;

/// Print processes as a tree rooted at PID 1.
fn print_tree(entries: &[ProcessEntry]) {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut by_pid: HashMap<u32, &ProcessEntry> = HashMap::new();

    for entry in entries {
        by_pid.insert(entry.pid, entry);
        children.entry(entry.ppid).or_default().push(entry.pid);
    }

    // Sort children of each parent by CPU descending.
    for kids in children.values_mut() {
        kids.sort_by(|a, b| {
            let cpu_a = by_pid.get(a).map_or(0.0, |e| e.cpu);
            let cpu_b = by_pid.get(b).map_or(0.0, |e| e.cpu);
            cpu_b
                .partial_cmp(&cpu_a)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
    }

    // Start from root processes (those whose parent is not in the list).
    let mut roots: Vec<u32> = entries
        .iter()
        .filter(|e| !by_pid.contains_key(&e.ppid) || e.ppid == 0)
        .map(|e| e.pid)
        .collect();
    roots.sort_unstable();

    for root in roots {
        print_tree_node(root, &children, &by_pid, "", true, 0);
    }
}

/// Recursively print a tree node with box-drawing characters.
fn print_tree_node(
    pid: u32,
    children: &HashMap<u32, Vec<u32>>,
    by_pid: &HashMap<u32, &ProcessEntry>,
    prefix: &str,
    is_last: bool,
    depth: usize,
) {
    if depth > MAX_TREE_DEPTH {
        return;
    }

    let connector = if depth == 0 {
        ""
    } else if is_last {
        "\u{2514}\u{2500}\u{2500} "
    } else {
        "\u{251c}\u{2500}\u{2500} "
    };

    let Some(entry) = by_pid.get(&pid) else {
        return;
    };

    let annotation = match &entry.group {
        Some(g) => format!(" [{g}]"),
        None => String::new(),
    };

    let cmd_short: String = entry.command.chars().take(30).collect();
    println!(
        "{prefix}{connector}{pid} {user} {cpu:.1}% {cmd}{ann}",
        user = entry.user,
        cpu = entry.cpu,
        cmd = cmd_short,
        ann = annotation,
    );

    let Some(kids) = children.get(&pid) else {
        return;
    };

    let child_prefix = if depth == 0 {
        String::new()
    } else if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}\u{2502}   ")
    };

    let count = kids.len();
    for (i, &child_pid) in kids.iter().enumerate() {
        let child_is_last = i == count - 1;
        print_tree_node(
            child_pid,
            children,
            by_pid,
            &child_prefix,
            child_is_last,
            depth + 1,
        );
    }
}

// ---------------------------------------------------------------------------
// JSON view
// ---------------------------------------------------------------------------

/// Print processes as JSON.
fn print_json(entries: &[ProcessEntry]) -> Result<()> {
    let json = serde_json::to_string_pretty(entries).context("failed to serialize processes")?;
    println!("{json}");
    Ok(())
}

#[cfg(test)]
#[path = "ps_test.rs"]
mod ps_test;
