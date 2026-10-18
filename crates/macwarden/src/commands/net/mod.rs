//! `macwarden net` -- network firewall CLI commands.
//!
//! Thin display wrappers around the `net` crate's rule engine.
//! Subcommands that require more logic live in `net_scan` and `net_shield`.

mod net_apps;
mod net_block;
mod net_enrich;
mod net_explain;
mod net_import;
mod net_learn;
pub(crate) mod net_lsof;
pub(crate) mod net_rdns;
pub(crate) mod net_scan;
pub(crate) mod net_shield;

use std::path::PathBuf;

use anyhow::{Context, Result};
use tabled::settings::Style;
use tabled::{Table, Tabled};

use net::{
    AppDb, BlocklistConfig, BlocklistFormat, GroupSettings, NetworkAction, NetworkGroups,
    PolicyConfig, RuleSet, TrackerCategory, TrackerDatabase,
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
        NetCommand::Apps {
            category,
            live,
            expand,
            json,
        } => {
            if live {
                net_apps::run_live(json)
            } else if let Some(ref app) = expand {
                net_apps::run_expand(app, json)
            } else {
                run_apps(category.as_deref(), json)
            }
        }
        NetCommand::Explain { process, host } => net_explain::run(&process, host.as_deref()),
        NetCommand::Learn {
            duration,
            apply,
            json,
        } => net_learn::run(duration.as_deref(), apply, json),
        NetCommand::Log => run_log(),
        NetCommand::Block { app, host } => net_block::run_block(app.as_deref(), host.as_deref()),
        NetCommand::Unblock { app, host } => {
            net_block::run_unblock(app.as_deref(), host.as_deref())
        }
        NetCommand::Blocklists { add, list } => run_blocklists(add.as_deref(), list),
        NetCommand::Import {
            source,
            path,
            apply,
            json,
        } => net_import::run(&source, path.as_deref(), apply, json),
        NetCommand::Enrich {
            key,
            remove,
            status,
        } => net_enrich::run(key.as_deref(), remove, status),
    }
}

/// Path to the persisted policy config (`~/.macwarden/net-profile.toml`).
pub(crate) fn policy_config_path() -> Result<PathBuf> {
    crate::cli::expand_home("~/.macwarden/net-profile.toml")
}

/// Load the persisted [`PolicyConfig`], failing open to the Allow-All default.
///
/// A missing or malformed file resolves to the default config (see
/// [`net::PolicyConfig::load`]); an unresolvable path likewise yields the
/// default so a broken `HOME` can never brick the network.
#[must_use]
pub(crate) fn load_policy_config() -> PolicyConfig {
    match policy_config_path() {
        Ok(path) => PolicyConfig::load(&path),
        Err(e) => {
            tracing::warn!(error = %e, "cannot resolve policy config path; using Allow-All default");
            PolicyConfig::default()
        }
    }
}

/// Whether "Allow Apple Programs" is currently enabled (for the decide-time
/// shim). Reads the persisted config so it always reflects the latest mutation.
#[must_use]
pub(crate) fn policy_apple_allow() -> bool {
    load_policy_config().allow_apple_programs
}

/// Resolve the `~/.macwarden/` base directory, failing open to a
/// non-existent path (so the loader yields safe defaults) if `HOME` is unset.
pub(crate) fn macwarden_base_dir() -> PathBuf {
    crate::cli::expand_home("~/.macwarden")
        .unwrap_or_else(|_| PathBuf::from("/nonexistent/.macwarden"))
}

/// Build a resolved `RuleSet` from builtins, the base profile, and the
/// persisted policy's synthetic allow-list + DNS Allow rules.
///
/// Delegates to [`net::build_base_ruleset`] so the CLI, the daemon, and the
/// NetworkExtension decision core compose one identical base rule set. The CLI
/// is a one-shot process with no in-memory banwatch engine, so it reads the
/// active-ban IP set from the on-disk store here and passes it in as an explicit
/// input (the loader itself never reopens the store).
pub(crate) fn build_base_ruleset() -> Result<RuleSet> {
    let base_dir = macwarden_base_dir();
    let banned_ips = banwatch::active_ban_ips(&base_dir);
    net::build_base_ruleset(&base_dir, &banned_ips).context("failed to build base network rule set")
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
    if let Some((name, want_enabled)) = enable
        .map(|n| (n, true))
        .or_else(|| disable.map(|n| (n, false)))
    {
        return toggle_group(&groups, name, want_enabled);
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

/// Durably enable or disable a group by mutating the persisted policy config.
fn toggle_group(groups: &NetworkGroups, name: &str, enabled: bool) -> Result<()> {
    if groups.get(name).is_none() {
        println!("Unknown group: `{name}`");
        for g in groups.all() {
            println!("  {}", g.name);
        }
        return Ok(());
    }
    let path = policy_config_path()?;
    let mut config = PolicyConfig::load(&path);
    set_group_override(&mut config.groups, name, enabled);
    config
        .save(&path)
        .context("failed to persist group override")?;
    let verb = if enabled { "enabled" } else { "disabled" };
    println!("Group `{name}` {verb} (saved to {}).", path.display());
    println!("A running daemon picks this up on its next reload.");
    Ok(())
}

/// Apply a durable enable/disable override to a [`GroupSettings`], keeping the
/// two override lists mutually exclusive for the named group.
pub(crate) fn set_group_override(groups: &mut GroupSettings, name: &str, enabled: bool) {
    groups.enable.retain(|g| g != name);
    groups.disable.retain(|g| g != name);
    if enabled {
        groups.enable.push(name.to_owned());
    } else {
        groups.disable.push(name.to_owned());
    }
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
    let shield = net_shield::load_shield_config(&macwarden_base_dir());
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
