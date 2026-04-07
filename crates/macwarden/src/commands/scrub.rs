//! `macwarden scrub` — delete data artifacts left by disabled services.
//!
//! Resolves targets across service groups and artifact domains. Supports
//! `--list` to show available targets and `--dry-run` to preview deletions.

use super::enforce;
use super::scrub_fs::{
    compute_size, delete_path, format_size, verify_path_safety, warn_running_processes,
};
use crate::cli;
use anyhow::Result;
use catalog::{load_builtin_artifacts, load_builtin_groups};
use policy::group::ServiceGroup;
use policy::{ArtifactAction, ArtifactDomain, find_artifact, find_artifact_domain, find_group};
use std::io::{self, Write};

// ---------------------------------------------------------------------------
// Dry-run result types
// ---------------------------------------------------------------------------

/// Result of cleaning a single artifact in dry-run mode.
struct CleanResult {
    size: u64,
    existed: bool,
}

/// Accumulated stats for a domain's dry-run.
struct DomainStats {
    total_size: u64,
    found: u32,
    clean: u32,
}

// ---------------------------------------------------------------------------
// Confirmation prompt
// ---------------------------------------------------------------------------

/// Ask the user to confirm before proceeding. Returns `true` if confirmed.
fn confirm(prompt: &str) -> bool {
    eprint!("{prompt} [y/N] ");
    io::stderr().flush().ok();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return false;
    }
    matches!(input.trim(), "y" | "Y" | "yes" | "YES")
}

// ---------------------------------------------------------------------------
// Pre-scan sizes (for confirmation prompt)
// ---------------------------------------------------------------------------

/// Scan total size across all artifact domains without deleting anything.
fn scan_all_sizes(domains: &[ArtifactDomain]) -> DomainStats {
    let mut stats = DomainStats {
        total_size: 0,
        found: 0,
        clean: 0,
    };
    for domain in domains {
        let ds = scan_domain_sizes(domain);
        stats.total_size += ds.total_size;
        stats.found += ds.found;
        stats.clean += ds.clean;
    }
    stats
}

/// Scan sizes for a specific target (group + artifact domain + individual artifact).
fn scan_target_sizes(
    target: &str,
    _groups: &[ServiceGroup],
    domains: &[ArtifactDomain],
) -> DomainStats {
    if let Some(domain) = find_artifact_domain(target, domains) {
        return scan_domain_sizes(domain);
    }
    if let Some((_, artifact)) = find_artifact(target, domains) {
        return scan_artifact_size(artifact);
    }
    DomainStats {
        total_size: 0,
        found: 0,
        clean: 0,
    }
}

/// Scan sizes for all artifacts in a domain.
fn scan_domain_sizes(domain: &ArtifactDomain) -> DomainStats {
    let mut stats = DomainStats {
        total_size: 0,
        found: 0,
        clean: 0,
    };
    for artifact in &domain.artifacts {
        let s = scan_artifact_size(artifact);
        stats.total_size += s.total_size;
        stats.found += s.found;
        stats.clean += s.clean;
    }
    stats
}

/// Compute the size of a single artifact.
fn scan_artifact_size(artifact: &policy::Artifact) -> DomainStats {
    match &artifact.action {
        ArtifactAction::Path(raw_path) => {
            let Ok(expanded) = cli::expand_home(raw_path) else {
                return DomainStats {
                    total_size: 0,
                    found: 0,
                    clean: 1,
                };
            };
            if expanded.exists() {
                let size = compute_size(&expanded);
                DomainStats {
                    total_size: size,
                    found: 1,
                    clean: 0,
                }
            } else {
                DomainStats {
                    total_size: 0,
                    found: 0,
                    clean: 1,
                }
            }
        }
        ArtifactAction::Command(_) => DomainStats {
            total_size: 0,
            found: 1,
            clean: 0,
        },
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Run the `scrub` command.
///
/// Dispatches based on `--list`, target resolution, or bare invocation.
/// Returns `Ok(())` on success; calls `process::exit(2)` for usage errors
/// to satisfy the spec's required exit code.
#[allow(clippy::unnecessary_wraps)]
pub fn run(target: Option<&str>, dry_run: bool, list: bool) -> Result<()> {
    if list {
        run_list(target);
        return Ok(());
    }

    let Some(target) = target else {
        eprintln!(
            "Error: specify a target (e.g., 'macwarden scrub safari') or use 'all'. \
             Run 'macwarden scrub --list' to see available targets."
        );
        std::process::exit(2);
    };

    let groups = load_builtin_groups();
    let domains = load_builtin_artifacts();

    if target.eq_ignore_ascii_case("all") {
        if !dry_run {
            let stats = scan_all_sizes(&domains);
            if !confirm(&format!(
                "This will delete ~{} across {} artifacts. Proceed?",
                format_size(stats.total_size),
                stats.found
            )) {
                println!("Aborted.");
                return Ok(());
            }
        }
        run_all(&groups, &domains, dry_run);
        return Ok(());
    }

    if !dry_run {
        let stats = scan_target_sizes(target, &groups, &domains);
        if !confirm(&format!(
            "Scrub '{target}'? Will delete ~{}. Proceed?",
            format_size(stats.total_size)
        )) {
            println!("Aborted.");
            return Ok(());
        }
    }

    run_target(target, &groups, &domains, dry_run);
    Ok(())
}

// ---------------------------------------------------------------------------
// List mode (R8)
// ---------------------------------------------------------------------------

/// Print available scrub targets, or detail for a specific target.
fn run_list(target: Option<&str>) {
    match target {
        Some(name) => run_list_detail(name),
        None => run_list_summary(),
    }
}

/// Print summary tables of all scrub targets.
fn run_list_summary() {
    let groups = load_builtin_groups();
    let domains = load_builtin_artifacts();

    println!("Service Groups (cleanup available):");
    println!("  {:<20} {:<14} COMMANDS", "NAME", "SAFETY");

    let mut cleanup_groups: Vec<&ServiceGroup> = groups
        .iter()
        .filter(|g| !g.cleanup_commands.is_empty())
        .collect();
    cleanup_groups.sort_by_key(|g| &g.name);

    for g in &cleanup_groups {
        println!(
            "  {:<20} {:<14} {} commands",
            g.name,
            g.safety,
            g.cleanup_commands.len()
        );
    }

    println!("\nArtifact Domains:");
    println!("  {:<20} {:<14} ARTIFACTS", "NAME", "SAFETY");

    let mut sorted_domains: Vec<&ArtifactDomain> = domains.iter().collect();
    sorted_domains.sort_by_key(|d| &d.name);

    let mut total_artifacts: usize = 0;
    for d in &sorted_domains {
        let has_group = find_group(&d.name, &groups).is_some();
        let suffix = if has_group { " [+services]" } else { "" };
        println!(
            "  {:<20} {:<14} {} artifacts{}",
            d.name,
            d.safety,
            d.artifacts.len(),
            suffix
        );
        total_artifacts += d.artifacts.len();
    }

    println!(
        "\n{} domains, {} artifacts total",
        sorted_domains.len(),
        total_artifacts
    );
}

/// Print detailed info for a specific target.
fn run_list_detail(name: &str) {
    let groups = load_builtin_groups();
    let domains = load_builtin_artifacts();

    let group = find_group(name, &groups);
    let domain = find_artifact_domain(name, &domains);

    if group.is_none() && domain.is_none() {
        eprintln!("Error: target '{name}' not found.");
        std::process::exit(2);
    }

    // Print header from whichever source has a description
    if let Some(d) = &domain {
        println!("{} — {} ({})", d.name, d.description, d.safety);
    } else if let Some(g) = &group {
        println!("{} — {} ({})", g.name, g.description, g.safety);
    }

    // Print artifacts if domain exists
    if let Some(d) = &domain {
        println!("\n  Artifacts:");
        for a in &d.artifacts {
            let path_or_cmd = match &a.action {
                ArtifactAction::Path(p) => p.as_str(),
                ArtifactAction::Command(c) => c.as_str(),
            };
            println!("    {:<28} {}", a.name, path_or_cmd);
            println!("    {:<28} {}", "", a.description);
        }
    }

    // Print service patterns if group exists
    if let Some(g) = &group {
        if !g.patterns.is_empty() {
            println!("\n  Services: {} patterns", g.patterns.len());
            for p in &g.patterns {
                println!("    {p}");
            }
        }
        if !g.cleanup_commands.is_empty() {
            println!("\n  Cleanup commands: {}", g.cleanup_commands.len());
            for c in &g.cleanup_commands {
                println!("    {c}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Target resolution (R6)
// ---------------------------------------------------------------------------

/// Resolve and execute a named target across groups and artifact domains.
fn run_target(target: &str, groups: &[ServiceGroup], domains: &[ArtifactDomain], dry_run: bool) {
    let mut found = false;

    // Step 1: group cleanup_commands
    if let Some(group) = find_group(target, groups) {
        found = true;
        if !group.cleanup_commands.is_empty() {
            run_group_cleanup(group, dry_run);
        }
    }

    // Step 2: artifact domain
    if let Some(domain) = find_artifact_domain(target, domains) {
        found = true;
        run_artifact_domain(domain, dry_run);
    }

    // Step 3: individual artifact (only if steps 1+2 missed)
    if !found && let Some((domain, artifact)) = find_artifact(target, domains) {
        found = true;
        println!(
            "Cleaning artifact '{}' from domain '{}':",
            artifact.name, domain.name
        );
        clean_artifact(artifact, dry_run);
    }

    if !found {
        eprintln!(
            "Error: target '{target}' not found.\n\
             Run 'macwarden scrub --list' to see available targets."
        );
        std::process::exit(2);
    }

    if !dry_run {
        println!("\nDone.");
    }
}

/// Run all group cleanup_commands and all artifact domains.
fn run_all(groups: &[ServiceGroup], domains: &[ArtifactDomain], dry_run: bool) {
    for group in groups {
        if !group.cleanup_commands.is_empty() {
            run_group_cleanup(group, dry_run);
        }
    }

    let mut grand_size: u64 = 0;
    let mut grand_found: u32 = 0;
    let mut grand_clean: u32 = 0;

    for domain in domains {
        let stats = run_artifact_domain(domain, dry_run);
        grand_size += stats.total_size;
        grand_found += stats.found;
        grand_clean += stats.clean;
    }

    if dry_run && (grand_found > 0 || grand_clean > 0) {
        println!(
            "\nGrand total: {} across {} artifacts ({} already clean)",
            format_size(grand_size),
            grand_found,
            grand_clean
        );
    }

    if !dry_run {
        println!("\nDone. All targets scrubbed.");
    }
}

// ---------------------------------------------------------------------------
// Execution helpers
// ---------------------------------------------------------------------------

/// Run a group's cleanup_commands.
fn run_group_cleanup(group: &ServiceGroup, dry_run: bool) {
    println!(
        "{}Scrubbing group '{}':",
        if dry_run { "[DRY RUN] " } else { "" },
        group.name,
    );
    enforce::run_shell_commands(&group.cleanup_commands, dry_run);
}

/// Clean all artifacts in a domain, returning dry-run stats.
fn run_artifact_domain(domain: &ArtifactDomain, dry_run: bool) -> DomainStats {
    println!(
        "\n{}Scrubbing artifact domain '{}' ({}):",
        if dry_run { "[DRY RUN] " } else { "" },
        domain.name,
        domain.description,
    );
    warn_running_processes(&domain.name);

    let mut stats = DomainStats {
        total_size: 0,
        found: 0,
        clean: 0,
    };

    for artifact in &domain.artifacts {
        let result = clean_artifact(artifact, dry_run);
        if dry_run {
            if result.existed {
                stats.found += 1;
                stats.total_size += result.size;
            } else {
                stats.clean += 1;
            }
        }
    }

    if dry_run && (stats.found > 0 || stats.clean > 0) {
        println!(
            "  Total: {} across {} artifacts ({} already clean)",
            format_size(stats.total_size),
            stats.found,
            stats.clean
        );
    }

    stats
}

/// Clean a single artifact (path or command), respecting dry_run.
fn clean_artifact(artifact: &policy::Artifact, dry_run: bool) -> CleanResult {
    match &artifact.action {
        ArtifactAction::Path(raw_path) => clean_path_artifact(artifact, raw_path, dry_run),
        ArtifactAction::Command(cmd) => clean_command_artifact(artifact, cmd, dry_run),
    }
}

/// Handle a path-based artifact.
fn clean_path_artifact(artifact: &policy::Artifact, raw_path: &str, dry_run: bool) -> CleanResult {
    let expanded = match cli::expand_home(raw_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("  Warning: cannot expand path '{raw_path}': {e}");
            return CleanResult {
                size: 0,
                existed: false,
            };
        }
    };

    if !expanded.exists() {
        return CleanResult {
            size: 0,
            existed: false,
        };
    }

    if dry_run {
        let size = compute_size(&expanded);
        println!(
            "  [DRY RUN] Would delete: {raw_path} ({})",
            format_size(size)
        );
        return CleanResult {
            size,
            existed: true,
        };
    }

    if !verify_path_safety(&expanded, raw_path) {
        return CleanResult {
            size: 0,
            existed: true,
        };
    }

    delete_path(&expanded, raw_path, &artifact.name);
    CleanResult {
        size: 0,
        existed: true,
    }
}

/// Handle a command-based artifact.
fn clean_command_artifact(artifact: &policy::Artifact, cmd: &str, dry_run: bool) -> CleanResult {
    if dry_run {
        println!("  [DRY RUN] Would run: {cmd}");
        return CleanResult {
            size: 0,
            existed: true,
        };
    }

    println!("  Running: {cmd}");
    let result = std::process::Command::new("sh").args(["-c", cmd]).status();
    match result {
        Ok(status) if status.success() => {}
        Ok(status) => {
            eprintln!(
                "  Warning: command for '{}' exited with {status}",
                artifact.name
            );
        }
        Err(e) => {
            eprintln!(
                "  Warning: failed to run command for '{}': {e}",
                artifact.name
            );
        }
    }

    CleanResult {
        size: 0,
        existed: true,
    }
}
