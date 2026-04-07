//! `macwarden net explain` -- explain why a connection would be allowed or denied.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use anyhow::Result;

use net::{AddressFamily, Destination, MatchTier, NetworkAction, ProcessIdentity};

/// Run `macwarden net explain`.
pub(super) fn run(process_arg: &str, host: Option<&str>) -> Result<()> {
    let rule_set = super::build_base_ruleset()?;
    let process = build_process_identity(process_arg);
    let destination = build_destination(host);
    let decision = rule_set.decide_for(&process, &destination);
    let action_str = action_label(decision.action);
    let path_lossy = process.path.to_string_lossy();
    let display_proc = process.code_id.as_deref().unwrap_or(&path_lossy);
    println!("Network Decision");
    println!("  Process:  {display_proc}");
    println!("  Host:     {}", host.unwrap_or("(any)"));
    println!("  Action:   {action_str}");
    print_tier_info(&decision);
    let ps = process.path.to_string_lossy();
    if net::graylist::is_graylisted(&ps) {
        println!("  Graylist: YES -- {ps} is an abusable Apple binary");
    }
    if let Some(h) = host
        && net::safelist::is_essential_domain(h)
    {
        println!("  Safelist: YES -- {h} is an essential domain (never blocked)");
    }
    Ok(())
}

/// Human-readable label for a network action.
fn action_label(a: NetworkAction) -> &'static str {
    match a {
        NetworkAction::Allow => "ALLOW",
        NetworkAction::Deny => "DENY",
        NetworkAction::Log => "LOG",
    }
}

/// Print tier and rule information from a network decision.
fn print_tier_info(d: &net::NetworkDecision) {
    let (tier, rule) = match d.matched_rule {
        Some(ref m) => {
            let t = match &m.tier {
                MatchTier::SafeList => "Safe-list (essential domain)".to_owned(),
                MatchTier::UserRule => "User rule".to_owned(),
                MatchTier::RuleGroup { group_name } => format!("Rule group ({group_name})"),
                MatchTier::Tracker { category } => format!("Tracker ({category})"),
                MatchTier::Blocklist { list_name } => format!("Blocklist ({list_name})"),
                MatchTier::ProfileDefault => "Profile default".to_owned(),
            };
            (t, m.rule_name.clone())
        }
        None => (
            "Profile default".to_owned(),
            "(none -- using default action)".to_owned(),
        ),
    };
    println!("  Tier:     {tier}\n  Rule:     {rule}");
}

/// Build a synthetic `ProcessIdentity` from user input.
///
/// If the input starts with `/`, treat as file path; otherwise code signing ID.
pub(super) fn build_process_identity(input: &str) -> ProcessIdentity {
    let (path, code_id) = if input.starts_with('/') {
        (PathBuf::from(input), None)
    } else {
        (PathBuf::from("/unknown"), Some(input.to_owned()))
    };
    ProcessIdentity {
        pid: 0,
        uid: 0,
        path,
        code_id,
        team_id: None,
        is_valid_signature: None,
    }
}

/// Build a synthetic `Destination` from an optional hostname.
pub(super) fn build_destination(host: Option<&str>) -> Destination {
    Destination {
        host: host.map(ToOwned::to_owned),
        ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: None,
        protocol: None,
        address_family: AddressFamily::Inet,
    }
}
