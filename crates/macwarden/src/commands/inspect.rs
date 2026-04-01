//! `macwarden info` — show detailed information about a service, group, or profile.
//!
//! Smart resolution: tries profile name → group name → service label.
//! Folds in policy decisions (explain) and binary analysis (catalog).

use anyhow::{Context, Result};

use catalog::{load_builtin_groups, load_builtin_profiles};
use launchd::{MacOsPlatform, Platform, ServiceDetail, binary_frameworks, binary_telemetry_scan};
use policy::{
    ServiceInfo, decide, diff, find_group, find_groups_for_service, resolve_extends,
    resolve_group_services,
};

use crate::cli::{self, OutputFormat};
use crate::commands::scan::discover_services;

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

/// Run the `info` command.
///
/// Smart resolution order: profile → group → service label.
pub fn run(target: &str, format: OutputFormat) -> Result<()> {
    // 1. Try as a profile name.
    let builtins = load_builtin_profiles();
    if let Some(profile) = builtins.iter().find(|p| p.profile.name == target) {
        return inspect_profile(profile, &builtins, format);
    }

    // 2. Try as a group name.
    let groups = load_builtin_groups();
    if let Some(group) = find_group(target, &groups) {
        return inspect_group(group, format);
    }

    // 3. Try as a service label.
    inspect_service(target, format, &groups)
}

// ---------------------------------------------------------------------------
// Group inspection
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Profile inspection
// ---------------------------------------------------------------------------

/// Display profile information: rules, what it would do, dry-run preview.
fn inspect_profile(
    profile: &policy::Profile,
    all_profiles: &[policy::Profile],
    format: OutputFormat,
) -> Result<()> {
    let resolved = resolve_extends(profile, all_profiles).context(format!(
        "failed to resolve profile '{}'",
        profile.profile.name
    ))?;

    let services = discover_services()?;
    let actions = diff(&services, &resolved);

    match format {
        OutputFormat::Table => print_profile_table(profile, &resolved, &services, &actions),
        OutputFormat::Json => print_profile_json(profile, &actions)?,
    }
    Ok(())
}

/// Print profile details as a human-readable summary.
fn print_profile_table(
    profile: &policy::Profile,
    resolved: &policy::Profile,
    services: &[ServiceInfo],
    actions: &[(ServiceInfo, policy::Action)],
) {
    let active = cli::read_active_profile().unwrap_or_default();
    let is_active = active == profile.profile.name;

    println!("Profile: {}", profile.profile.name);
    if !profile.profile.description.is_empty() {
        println!("  {}", profile.profile.description);
    }
    if !profile.profile.extends.is_empty() {
        println!("  Extends: {}", profile.profile.extends.join(" → "));
    }
    if is_active {
        println!("  Status: ACTIVE");
    }

    if !resolved.rules.deny.is_empty() {
        println!("\nDeny rules:");
        for rule in &resolved.rules.deny {
            println!("  {rule}");
        }
    }
    if !resolved.rules.allow.is_empty() {
        println!("\nAllow rules:");
        for rule in &resolved.rules.allow {
            println!("  {rule}");
        }
    }
    if !resolved.rules.categories.is_empty() {
        println!("\nCategory rules:");
        for (cat, action) in &resolved.rules.categories {
            println!("  {cat} = {action}");
        }
    }

    if actions.is_empty() {
        println!("\nWould change: nothing (system already in compliance)");
    } else {
        let disable_count = actions
            .iter()
            .filter(|(_, a)| matches!(a, policy::Action::Disable { .. }))
            .count();
        println!(
            "\nWould block {} of {} services:",
            disable_count,
            services.len()
        );
        let mut seen = std::collections::HashSet::new();
        for (svc, action) in actions {
            if matches!(action, policy::Action::Disable { .. }) && seen.insert(&svc.label) {
                println!(
                    "  {} [{}] (category: {}, safety: {})",
                    svc.label, svc.state, svc.category, svc.safety,
                );
            }
        }
    }
}

/// Print profile details as JSON.
fn print_profile_json(
    profile: &policy::Profile,
    actions: &[(ServiceInfo, policy::Action)],
) -> Result<()> {
    #[derive(serde::Serialize)]
    struct ProfileReport<'a> {
        name: &'a str,
        description: &'a str,
        extends: &'a [String],
        deny_rules: &'a [String],
        allow_rules: &'a [String],
        would_block: Vec<&'a str>,
    }

    let would_block: Vec<&str> = actions
        .iter()
        .filter(|(_, a)| matches!(a, policy::Action::Disable { .. }))
        .map(|(svc, _)| svc.label.as_str())
        .collect();

    let report = ProfileReport {
        name: &profile.profile.name,
        description: &profile.profile.description,
        extends: &profile.profile.extends,
        deny_rules: &profile.rules.deny,
        allow_rules: &profile.rules.allow,
        would_block,
    };

    let json = serde_json::to_string_pretty(&report).context("failed to serialize")?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Group inspection
// ---------------------------------------------------------------------------

/// Display group information: description, patterns, matching services.
fn inspect_group(group: &policy::ServiceGroup, format: OutputFormat) -> Result<()> {
    let services = discover_services()?;
    let matched = resolve_group_services(group, &services);

    match format {
        OutputFormat::Table => print_group_table(group, &matched),
        OutputFormat::Json => print_group_json(group, &matched)?,
    }
    Ok(())
}

/// Print group details as a human-readable table.
fn print_group_table(group: &policy::ServiceGroup, services: &[&ServiceInfo]) {
    println!("Group: {}", group.name);
    println!("  {}\n", group.description);

    println!("  Safety:   {}", group.safety);
    println!("  Respawn:  {}", group.respawn_behavior);

    println!("\nPatterns:");
    for pat in &group.patterns {
        println!("  {pat}");
    }

    if !group.disable_commands.is_empty() {
        println!("\nDisable commands:");
        for cmd in &group.disable_commands {
            println!("  {cmd}");
        }
    }
    if !group.enable_commands.is_empty() {
        println!("\nEnable commands:");
        for cmd in &group.enable_commands {
            println!("  {cmd}");
        }
    }
    if !group.cleanup_commands.is_empty() {
        println!("\nCleanup commands (reclaim disk space after disabling):");
        for cmd in &group.cleanup_commands {
            println!("  {cmd}");
        }
    }

    if group.respawn_behavior == policy::RespawnBehavior::RespawnsAggressive {
        println!(
            "\nNote: This group respawns aggressively. Use `macwarden watch` to keep it disabled."
        );
    }

    println!("\nMatching services ({}):", services.len());
    for svc in services {
        let pid_str = svc.pid.map_or(String::new(), |p| format!(" (pid {p})"));
        println!("  {} [{}]{}", svc.label, svc.state, pid_str);
    }
}

/// Print group details as JSON.
fn print_group_json(group: &policy::ServiceGroup, services: &[&ServiceInfo]) -> Result<()> {
    #[derive(serde::Serialize)]
    struct GroupReport<'a> {
        name: &'a str,
        description: &'a str,
        respawn_behavior: String,
        patterns: &'a [String],
        disable_commands: &'a [String],
        enable_commands: &'a [String],
        cleanup_commands: &'a [String],
        matching_services: Vec<&'a ServiceInfo>,
    }

    let report = GroupReport {
        name: &group.name,
        description: &group.description,
        respawn_behavior: group.respawn_behavior.to_string(),
        patterns: &group.patterns,
        disable_commands: &group.disable_commands,
        enable_commands: &group.enable_commands,
        cleanup_commands: &group.cleanup_commands,
        matching_services: services.to_vec(),
    };

    let json = serde_json::to_string_pretty(&report).context("failed to serialize")?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Service inspection
// ---------------------------------------------------------------------------

/// Display detailed information about a single service.
fn inspect_service(
    label: &str,
    format: OutputFormat,
    all_groups: &[policy::ServiceGroup],
) -> Result<()> {
    let services = discover_services()?;
    let svc = services.iter().find(|s| s.label == label);

    let Some(svc) = svc else {
        suggest_similar(label, &services);
        anyhow::bail!("service '{label}' not found");
    };

    let platform = MacOsPlatform::new();
    let domain_str = domain_string(svc);
    let detail = platform.inspect(&domain_str, label).ok();

    let process = svc.pid.and_then(|pid| platform.process_detail(pid).ok());

    let groups = find_groups_for_service(label, all_groups);

    match format {
        OutputFormat::Table => print_service_table(svc, detail.as_ref(), process.as_ref(), &groups),
        OutputFormat::Json => print_service_json(svc, detail.as_ref(), process.as_ref(), &groups)?,
    }
    Ok(())
}

/// Print service details as a human-readable summary.
fn print_service_table(
    svc: &ServiceInfo,
    detail: Option<&ServiceDetail>,
    process: Option<&launchd::ProcessDetail>,
    groups: &[&policy::ServiceGroup],
) {
    println!("Service: {}", svc.label);
    println!("  Domain:    {}", svc.domain);
    println!("  State:     {}", svc.state);
    println!("  Category:  {}", svc.category);
    println!("  Safety:    {}", svc.safety);

    if let Some(desc) = &svc.description {
        println!("  Desc:      {desc}");
    }
    if let Some(pid) = svc.pid {
        println!("  PID:       {pid}");
    }

    if let Some(d) = detail {
        if let Some(prog) = &d.program {
            println!("  Program:   {prog}");
        }
        if let Some(ka) = &d.keep_alive {
            println!("  KeepAlive: {ka}");
            println!("  (killing this service will cause launchd to restart it)");
        }
        if !d.mach_services.is_empty() {
            println!("  XPC endpoints (trigger on-demand launch):");
            for ms in &d.mach_services {
                println!("    {ms}");
            }
        }
        if let Some(runs) = d.runs {
            println!("  Runs:      {runs}");
        }
        if let Some(timeout) = d.exit_timeout {
            println!("  Exit timeout: {timeout}s");
        }
    }

    // Binary analysis — framework linkage and telemetry string scan.
    if let Some(d) = detail
        && let Some(prog) = &d.program
    {
        let frameworks = binary_frameworks(prog);
        if !frameworks.is_empty() {
            println!("  Frameworks: {}", frameworks.join(", "));
        }
        let scan = binary_telemetry_scan(prog);
        if scan.has_analytics {
            println!(
                "  Telemetry strings: YES ({})",
                scan.keywords_found.join(", ")
            );
        } else {
            println!("  Telemetry strings: none detected");
        }
    }

    if let Some(p) = process {
        println!("\n  Process info:");
        println!("    CPU:    {:.1}%", p.cpu_percent);
        println!("    Memory: {:.1}% ({} KB)", p.mem_percent, p.rss_kb);
        println!("    User:   {}", p.user);
        if !p.open_files.is_empty() {
            println!("    Open files ({}):", p.open_files.len());
            for f in &p.open_files {
                println!("      {f}");
            }
        }
    }

    if !groups.is_empty() {
        println!("\n  Member of groups:");
        for g in groups {
            println!("    {} — {}", g.name, g.description);
        }
    }

    // Policy decision (explain) — show why this service is allowed/denied.
    let builtins = load_builtin_profiles();
    let active_name = cli::read_active_profile().unwrap_or_default();
    if let Some(profile) = builtins.iter().find(|p| p.profile.name == active_name)
        && let Ok(resolved) = resolve_extends(profile, &builtins)
    {
        let decision = decide(svc, &resolved);
        println!("\n  Policy (profile: {active_name}): {decision}");
    }
}

/// Print service details as JSON.
fn print_service_json(
    svc: &ServiceInfo,
    detail: Option<&ServiceDetail>,
    process: Option<&launchd::ProcessDetail>,
    groups: &[&policy::ServiceGroup],
) -> Result<()> {
    #[derive(serde::Serialize)]
    struct ServiceReport<'a> {
        service: &'a ServiceInfo,
        detail: Option<&'a ServiceDetail>,
        process: Option<&'a launchd::ProcessDetail>,
        groups: Vec<&'a str>,
    }

    let report = ServiceReport {
        service: svc,
        detail,
        process,
        groups: groups.iter().map(|g| g.name.as_str()).collect(),
    };

    let json = serde_json::to_string_pretty(&report).context("failed to serialize")?;
    println!("{json}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a core `Domain` to the launchctl domain string.
fn domain_string(svc: &ServiceInfo) -> String {
    match svc.domain {
        policy::Domain::System => "system".to_owned(),
        policy::Domain::User | policy::Domain::Global => {
            // Best-effort: use uid from env if available
            let uid = std::env::var("UID")
                .or_else(|_| std::env::var("EUID"))
                .unwrap_or_else(|_| "501".to_owned());
            format!("gui/{uid}")
        }
    }
}

/// Suggest similar labels when a service is not found.
fn suggest_similar(target: &str, services: &[ServiceInfo]) {
    let lower = target.to_lowercase();
    let similar: Vec<&str> = services
        .iter()
        .filter(|s| s.label.to_lowercase().contains(&lower))
        .take(5)
        .map(|s| s.label.as_str())
        .collect();

    if !similar.is_empty() {
        eprintln!("Did you mean one of these?");
        for label in similar {
            eprintln!("  {label}");
        }
    }
}
