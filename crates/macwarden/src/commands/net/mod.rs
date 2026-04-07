//! `macwarden net` -- network firewall CLI commands.
//!
//! Thin display wrappers around the `net` crate's rule engine.
//! Subcommands that require more logic live in `net_scan` and `net_shield`.

mod net_enrich;
mod net_explain;
mod net_learn;
mod net_lsof;
mod net_rdns;
pub(crate) mod net_scan;
pub(crate) mod net_shield;

use anyhow::{Context, Result};
use tabled::settings::Style;
use tabled::{Table, Tabled};

use net::{
    AppDb, BlocklistConfig, BlocklistFormat, BlocklistSettings, GroupSettings, NetworkAction,
    NetworkGroups, NetworkProfile, RuleSet, TrackerCategory, TrackerDatabase, TrackerSettings,
};

use crate::cli::NetCommand;

/// Run the `net` subcommand tree.
pub fn run(command: NetCommand) -> Result<()> {
    match command {
        NetCommand::Scan {
            process,
            denied,
            trackers,
            json,
        } => net_scan::run(process.as_deref(), denied, trackers, json),
        NetCommand::Shield { off, only } => net_shield::run(off, &only),
        NetCommand::Rules {
            process,
            group,
            json,
        } => run_rules(process.as_deref(), group.as_deref(), json),
        NetCommand::Groups {
            enable,
            disable,
            json,
        } => run_groups(enable.as_deref(), disable.as_deref(), json),
        NetCommand::Trackers { stats, json } => run_trackers(stats, json),
        NetCommand::Apps { category, json } => run_apps(category.as_deref(), json),
        NetCommand::Explain { process, host } => net_explain::run(&process, host.as_deref()),
        NetCommand::Learn {
            duration,
            apply,
            json,
        } => net_learn::run(duration.as_deref(), apply, json),
        NetCommand::Log => run_log(),
        NetCommand::Blocklists { add, list } => run_blocklists(add.as_deref(), list),
        NetCommand::Enrich {
            key,
            remove,
            status,
        } => net_enrich::run(key.as_deref(), remove, status),
    }
}

/// Load the default base profile, applying shield overrides if active.
///
/// When the tracker shield is enabled, categories configured as `"deny"`
/// in the shield config upgrade the corresponding `TrackerSettings` field
/// from `Log` to `Deny`.
pub(super) fn base_profile() -> NetworkProfile {
    let shield = net_shield::load_shield_config();
    let trackers = if shield.enabled {
        TrackerSettings {
            advertising: shield.category_action("advertising"),
            analytics: shield.category_action("analytics"),
            fingerprinting: shield.category_action("fingerprinting"),
            social: shield.category_action("social"),
            ..TrackerSettings::default()
        }
    } else {
        TrackerSettings::default()
    };

    NetworkProfile {
        default: NetworkAction::Log,
        trackers,
        groups: GroupSettings::default(),
        blocklists: BlocklistSettings::default(),
        rules: Vec::new(),
    }
}

/// Build a resolved `RuleSet` from builtins and the base profile.
pub(super) fn build_base_ruleset() -> Result<RuleSet> {
    let tracker_db = TrackerDatabase::load_builtin().context("failed to load tracker database")?;
    let groups = NetworkGroups::load_builtin().context("failed to load network groups")?;
    let category_db = AppDb::load_builtin().context("failed to load app categories")?;
    let profile = base_profile();

    profile
        .resolve(&groups, &tracker_db, &category_db, &[])
        .context("failed to resolve base network profile")
}

/// Count total domains across all rules in a group.
fn group_domain_count(group: &net::NetworkGroup) -> usize {
    group.rules.iter().map(|r| r.dest_hosts.len()).sum()
}

#[derive(Debug, Tabled, serde::Serialize)]
struct RuleRow {
    #[tabled(rename = "Name")]
    name: String,
    #[tabled(rename = "Process")]
    process: String,
    #[tabled(rename = "Destination")]
    destination: String,
    #[tabled(rename = "Action")]
    action: String,
    #[tabled(rename = "Source")]
    source: String,
}

/// `macwarden net rules` -- list all active rules from the base profile.
fn run_rules(process_filter: Option<&str>, group_filter: Option<&str>, json: bool) -> Result<()> {
    let rs = build_base_ruleset()?;
    let mut rows = collect_rule_rows(&rs);

    if let Some(pf) = process_filter {
        let pf_lower = pf.to_ascii_lowercase();
        rows.retain(|r| r.process.to_ascii_lowercase().contains(&pf_lower));
    }
    if let Some(gf) = group_filter {
        let gf_lower = gf.to_ascii_lowercase();
        rows.retain(|r| r.source.to_ascii_lowercase().contains(&gf_lower));
    }
    if json {
        let out =
            serde_json::to_string_pretty(&rows).context("failed to serialize rules as JSON")?;
        println!("{out}");
        return Ok(());
    }
    if rows.is_empty() {
        println!("No rules match the given filters.");
        return Ok(());
    }
    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("Network Rules\n{table}");
    println!(
        "\n{} rules (profile default action: {})",
        rows.len(),
        rs.default_action
    );
    Ok(())
}

/// Flatten a `RuleSet` into displayable `RuleRow` values.
fn collect_rule_rows(rs: &RuleSet) -> Vec<RuleRow> {
    let mut rows = Vec::new();
    for rule in &rs.user_rules {
        rows.push(RuleRow {
            name: rule.name.clone(),
            process: rule.process.pattern().to_owned(),
            destination: format_dest(&rule.destination),
            action: rule.action.to_string(),
            source: "user".to_owned(),
        });
    }
    for gr in &rs.group_rules {
        rows.push(RuleRow {
            name: gr.rule.name.clone(),
            process: gr.rule.process.pattern().to_owned(),
            destination: format_dest(&gr.rule.destination),
            action: gr.rule.action.to_string(),
            source: format!("group/{}", gr.group_name),
        });
    }
    for tr in &rs.tracker_rules {
        rows.push(RuleRow {
            name: tr.description.clone(),
            process: "*".to_owned(),
            destination: tr.pattern.to_string(),
            action: "deny".to_owned(),
            source: format!("tracker/{}", tr.category),
        });
    }
    for bl in &rs.blocklist_domains {
        rows.push(RuleRow {
            name: bl.domain.clone(),
            process: "*".to_owned(),
            destination: bl.domain.clone(),
            action: "deny".to_owned(),
            source: format!("blocklist/{}", bl.list_name),
        });
    }
    rows
}

/// Format a `DestMatcher` for table display.
fn format_dest(d: &net::DestMatcher) -> String {
    if d.is_any() {
        return "*".to_owned();
    }
    let mut p = Vec::new();
    if let Some(ref h) = d.host {
        p.push(h.to_string());
    }
    if let Some(ref ip) = d.ip {
        p.push(ip.to_string());
    }
    if let Some(ref port) = d.port {
        p.push(format!(":{port}"));
    }
    if let Some(ref proto) = d.protocol {
        p.push(proto.to_string());
    }
    p.join(" ")
}

#[derive(Debug, Tabled, serde::Serialize)]
struct GroupRow {
    #[tabled(rename = "Group")]
    name: String,
    #[tabled(rename = "Domains")]
    domains: usize,
    #[tabled(rename = "Priority")]
    priority: u32,
    #[tabled(rename = "Enabled")]
    enabled: String,
}

/// `macwarden net groups` -- list all network rule groups.
fn run_groups(enable: Option<&str>, disable: Option<&str>, json: bool) -> Result<()> {
    let groups = NetworkGroups::load_builtin().context("failed to load network groups")?;
    if let Some((name, verb)) = enable
        .map(|n| (n, "enabled"))
        .or_else(|| disable.map(|n| (n, "disabled")))
    {
        if groups.get(name).is_some() {
            println!("Group `{name}` would be {verb}.");
            println!("(Profile editing is not yet implemented.)");
        } else {
            println!("Unknown group: `{name}`");
            for g in groups.all() {
                println!("  {}", g.name);
            }
        }
        return Ok(());
    }
    let rows: Vec<GroupRow> = groups
        .all()
        .iter()
        .map(|g| GroupRow {
            name: g.name.clone(),
            domains: group_domain_count(g),
            priority: g.priority,
            enabled: if g.default_enabled { "yes" } else { "no" }.to_owned(),
        })
        .collect();
    if json {
        let out =
            serde_json::to_string_pretty(&rows).context("failed to serialize groups as JSON")?;
        println!("{out}");
        return Ok(());
    }
    let enabled_count = groups.all().iter().filter(|g| g.default_enabled).count();
    let total = groups.all().len();
    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("Network Rule Groups");
    println!("{table}");
    println!("\n{total} groups defined ({enabled_count} enabled)");
    Ok(())
}

#[derive(Debug, Tabled, serde::Serialize)]
struct TrackerRow {
    #[tabled(rename = "Category")]
    category: String,
    #[tabled(rename = "Domains")]
    domains: usize,
    #[tabled(rename = "Status")]
    status: String,
}

/// `macwarden net trackers` -- show tracker shield categories.
fn run_trackers(stats: bool, json: bool) -> Result<()> {
    let tracker_db = TrackerDatabase::load_builtin().context("failed to load tracker database")?;
    let shield = net_shield::load_shield_config();
    let domain_stats = tracker_db.stats();
    let cats = [
        (TrackerCategory::Advertising, "Advertising"),
        (TrackerCategory::Analytics, "Analytics"),
        (TrackerCategory::Fingerprinting, "Fingerprinting"),
        (TrackerCategory::Social, "Social"),
    ];
    let rows: Vec<TrackerRow> = cats
        .iter()
        .map(|&(cat, name)| {
            let status = if shield.enabled && shield.is_category_denied(&cat.to_string()) {
                "deny"
            } else {
                "log"
            };
            TrackerRow {
                category: name.to_owned(),
                domains: domain_stats.get(&cat).copied().unwrap_or(0),
                status: status.to_owned(),
            }
        })
        .collect();
    if json {
        let out =
            serde_json::to_string_pretty(&rows).context("failed to serialize trackers as JSON")?;
        println!("{out}");
        return Ok(());
    }
    let total: usize = rows.iter().map(|r| r.domains).sum();
    if stats {
        println!("Tracker Shield -- Category Breakdown\n");
        for row in &rows {
            let pct = if total > 0 {
                (row.domains as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            println!(
                "  {:<20} {:>4} domains ({:.0}%)",
                row.category, row.domains, pct
            );
        }
        println!("\n{total} tracker domains loaded");
        return Ok(());
    }
    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("Tracker Shield");
    println!("{table}");
    println!("\n{total} tracker domains loaded");
    Ok(())
}

#[derive(Debug, Tabled, serde::Serialize)]
struct AppRow {
    #[tabled(rename = "App")]
    name: String,
    #[tabled(rename = "Code ID")]
    code_id: String,
    #[tabled(rename = "Category")]
    category: String,
}

/// `macwarden net apps` -- list app categories.
fn run_apps(category_filter: Option<&str>, json: bool) -> Result<()> {
    let category_db = AppDb::load_builtin().context("failed to load app categories")?;

    let mut rows: Vec<AppRow> = category_db
        .entries()
        .iter()
        .filter_map(|e| {
            let cat = e.category?;
            Some(AppRow {
                name: e.name.clone(),
                code_id: e.code_id.clone(),
                category: cat.to_string(),
            })
        })
        .collect();

    if let Some(cf) = category_filter {
        let cf_lower = cf.to_ascii_lowercase();
        rows.retain(|r| r.category.to_ascii_lowercase().contains(&cf_lower));
    }

    if json {
        let out =
            serde_json::to_string_pretty(&rows).context("failed to serialize apps as JSON")?;
        println!("{out}");
        return Ok(());
    }

    if rows.is_empty() {
        println!("No apps match the given category filter.");
        return Ok(());
    }

    let table = Table::new(&rows).with(Style::rounded()).to_string();
    println!("App Categories");
    println!("{table}");
    println!("\n{} apps registered", rows.len());
    Ok(())
}

/// `macwarden net log` -- show live network decision log status.
fn run_log() -> Result<()> {
    let tdb = TrackerDatabase::load_builtin().context("failed to load tracker database")?;
    let groups = NetworkGroups::load_builtin().context("failed to load network groups")?;
    let td: usize = tdb.stats().values().sum();
    let eg = groups.all().iter().filter(|g| g.default_enabled).count();
    println!("Network Firewall -- Log\n");
    println!("  Live logging requires the Endpoint Security daemon.");
    println!("  Run `macwarden watch` with ES enabled to stream network decisions.\n");
    println!("Current Policy Summary");
    println!("  Default action:   log (monitor mode)");
    println!("  Tracker domains:  {td}");
    println!(
        "  Rule groups:      {} ({eg} enabled by default)",
        groups.all().len()
    );
    println!(
        "  Safe-list:        {} essential domains",
        net::safelist::count()
    );
    println!(
        "  Graylist:         {} abusable Apple binaries",
        net::graylist::count()
    );
    Ok(())
}

/// `macwarden net blocklists` -- manage external blocklist subscriptions.
fn run_blocklists(add: Option<&str>, _list: bool) -> Result<()> {
    let Some(path) = add else {
        println!("Blocklists\n\n  No blocklists are configured yet.\n");
        println!("Add a local hosts-format blocklist:");
        println!("  macwarden net blocklists --add /path/to/hosts.txt\n");
        println!("Supported formats:");
        println!("  - hosts: Standard hosts file (0.0.0.0 domain.com)");
        println!("  - domain-list: One domain per line, # comments");
        return Ok(());
    };
    let config = BlocklistConfig {
        name: path.to_owned(),
        source: path.to_owned(),
        format: BlocklistFormat::Hosts,
        action: NetworkAction::Deny,
        update_interval: None,
        enabled: true,
    };
    let bl = net::blocklist::load_from_file(&config).context("failed to load blocklist file")?;
    println!("Loaded blocklist from {path}");
    println!("  Format:  hosts\n  Domains: {}\n", bl.len());
    println!("To activate, add this blocklist to your network profile.");
    Ok(())
}

#[cfg(test)]
#[path = "net_test.rs"]
mod net_test;
