//! Import rules from external firewall applications.
//!
//! Currently supports importing from [LuLu](https://objective-see.org/products/lulu.html),
//! the open-source macOS firewall by Objective-See.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use crate::error::NetError;
use crate::user_rule::UserRuleFile;

// ---------------------------------------------------------------------------
// LuLu rule format
// ---------------------------------------------------------------------------

/// LuLu rules.json is a dict of UUID -> rule object.
type LuLuRulesFile = HashMap<String, LuLuRule>;

/// A single rule from LuLu's `rules.json`.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LuLuRule {
    /// Executable path.
    #[serde(default)]
    pub path: String,
    /// Process display name.
    #[serde(default)]
    pub name: String,
    /// Destination address (IP, hostname, or empty for "any").
    #[serde(default)]
    pub endpoint_addr: String,
    /// Destination port (as string, or empty).
    #[serde(default)]
    pub endpoint_port: String,
    /// Whether endpoint_addr is a regex ("0" or "1").
    #[serde(default)]
    pub is_endpoint_addr_regex: String,
    /// Rule type.
    #[serde(default, rename = "type")]
    pub rule_type: String,
    /// Scope: "process" or empty.
    #[serde(default)]
    pub scope: String,
    /// Action: RULE_STATE_ALLOW (3) or RULE_STATE_BLOCK (4).
    #[serde(default)]
    pub action: LuLuAction,
    /// Code signing info.
    #[serde(default)]
    pub cs_info: Option<LuLuCodeSignInfo>,
}

/// LuLu code signing information.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct LuLuCodeSignInfo {
    /// Code signing identity (e.g., "com.apple.Safari").
    #[serde(default, rename = "signingID")]
    pub signing_id: Option<String>,
    /// Team identifier (e.g., "EQHXZ8M8AV").
    #[serde(default, rename = "teamID")]
    pub team_id: Option<String>,
}

/// LuLu rule action values.
///
/// LuLu uses numeric action codes. We accept both numeric and string forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LuLuAction {
    /// RULE_STATE_ALLOW = 3.
    Allow,
    /// RULE_STATE_BLOCK = 4.
    Block,
    /// Unknown action value.
    #[default]
    Unknown,
}

impl<'de> Deserialize<'de> for LuLuAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum ActionRaw {
            Num(i64),
            Str(String),
        }

        let raw = ActionRaw::deserialize(deserializer)?;
        Ok(match raw {
            ActionRaw::Num(3) => Self::Allow,
            ActionRaw::Num(4) => Self::Block,
            ActionRaw::Str(s) if s == "3" || s.eq_ignore_ascii_case("allow") => Self::Allow,
            ActionRaw::Str(s) if s == "4" || s.eq_ignore_ascii_case("block") => Self::Block,
            _ => Self::Unknown,
        })
    }
}

// ---------------------------------------------------------------------------
// Conversion result
// ---------------------------------------------------------------------------

/// Result of converting a LuLu rule to a macwarden rule.
#[derive(Debug, Clone)]
pub struct ImportedRule {
    /// The converted macwarden user rule.
    pub rule: UserRuleFile,
    /// Original LuLu process path.
    pub source_path: String,
    /// Original LuLu endpoint.
    pub source_endpoint: String,
}

/// Summary of an import operation.
#[derive(Debug, Clone)]
pub struct ImportSummary {
    /// Successfully converted rules.
    pub imported: Vec<ImportedRule>,
    /// Rules that were skipped with reason.
    pub skipped: Vec<(String, String)>,
}

// ---------------------------------------------------------------------------
// Import logic
// ---------------------------------------------------------------------------

/// Default LuLu rules location.
pub const LULU_RULES_PATH: &str =
    "~/Library/Group Containers/group.com.objective-see.lulu/rules.json";

/// Expand `~` to the user's home directory.
fn expand_tilde(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    path.to_owned()
}

/// Parse a LuLu rules.json file and convert to macwarden user rules.
///
/// # Errors
///
/// Returns an error if the file cannot be read or parsed as JSON.
pub fn import_lulu(path: &Path) -> Result<ImportSummary, NetError> {
    let content = std::fs::read_to_string(path).map_err(|e| NetError::RuleParse {
        path: path.display().to_string(),
        message: format!("cannot read LuLu rules file: {e}"),
    })?;

    let rules: LuLuRulesFile = serde_json::from_str(&content).map_err(|e| NetError::RuleParse {
        path: path.display().to_string(),
        message: format!("cannot parse LuLu rules JSON: {e}"),
    })?;

    let mut imported = Vec::new();
    let mut skipped = Vec::new();

    for (uuid, rule) in &rules {
        match convert_lulu_rule(rule) {
            Ok(user_rule) => {
                imported.push(ImportedRule {
                    rule: user_rule,
                    source_path: rule.path.clone(),
                    source_endpoint: rule.endpoint_addr.clone(),
                });
            }
            Err(reason) => {
                let desc = format!(
                    "{} -> {} ({})",
                    if rule.name.is_empty() {
                        &rule.path
                    } else {
                        &rule.name
                    },
                    if rule.endpoint_addr.is_empty() {
                        "*"
                    } else {
                        &rule.endpoint_addr
                    },
                    uuid,
                );
                skipped.push((desc, reason));
            }
        }
    }

    // Sort by name for deterministic output.
    imported.sort_by(|a, b| a.rule.name.cmp(&b.rule.name));

    Ok(ImportSummary { imported, skipped })
}

/// Resolve the default LuLu rules.json path.
pub fn default_lulu_path() -> std::path::PathBuf {
    std::path::PathBuf::from(expand_tilde(LULU_RULES_PATH))
}

/// Convert a single LuLu rule to a macwarden `UserRuleFile`.
fn convert_lulu_rule(rule: &LuLuRule) -> Result<UserRuleFile, String> {
    // Skip rules with unknown action.
    let action = match rule.action {
        LuLuAction::Allow => crate::rule::NetworkAction::Allow,
        LuLuAction::Block => crate::rule::NetworkAction::Deny,
        LuLuAction::Unknown => return Err("unknown action value".to_owned()),
    };

    // Skip regex endpoint rules — macwarden uses glob patterns, not regex.
    if rule.is_endpoint_addr_regex == "1" {
        return Err("regex endpoint patterns not supported".to_owned());
    }

    // Determine process identifier: prefer team_id > signing_id > path.
    let process = determine_process(rule)?;

    // Determine destination.
    let dest = determine_destination(rule);

    // Parse port if present.
    let dest_port: Option<u16> = if rule.endpoint_port.is_empty() {
        None
    } else {
        rule.endpoint_port.parse().ok().filter(|&p: &u16| p > 0)
    };

    // Build human-readable name.
    let name = build_rule_name(rule, &process, &dest);

    Ok(UserRuleFile {
        name,
        process,
        dest,
        dest_port,
        action,
        enabled: true,
        note: Some(format!("Imported from LuLu ({})", rule.name)),
    })
}

/// Determine the process pattern from a LuLu rule.
///
/// Priority: team_id > signing_id > path.
fn determine_process(rule: &LuLuRule) -> Result<String, String> {
    if let Some(ref cs) = rule.cs_info {
        // Prefer team_id (most stable identifier).
        if let Some(ref tid) = cs.team_id
            && !tid.is_empty()
            && tid != "not signed"
        {
            return Ok(format!("team:{tid}"));
        }
        // Fall back to signing identity (code_id).
        if let Some(ref sid) = cs.signing_id
            && !sid.is_empty()
            && sid != "not signed"
        {
            return Ok(sid.clone());
        }
    }
    // Fall back to executable path.
    if rule.path.is_empty() {
        return Err("rule has no process identifier".to_owned());
    }
    Ok(rule.path.clone())
}

/// Determine the destination pattern from a LuLu rule.
fn determine_destination(rule: &LuLuRule) -> String {
    if rule.endpoint_addr.is_empty() {
        return "*".to_owned();
    }
    rule.endpoint_addr.clone()
}

/// Build a human-readable rule name.
fn build_rule_name(rule: &LuLuRule, process: &str, dest: &str) -> String {
    let action_word = match rule.action {
        LuLuAction::Allow => "allow",
        LuLuAction::Block => "block",
        LuLuAction::Unknown => "rule",
    };

    // Use the short process name if available.
    let proc_short = if rule.name.is_empty() {
        // Extract filename from path.
        process.rsplit('/').next().unwrap_or(process).to_owned()
    } else {
        rule.name.clone()
    };

    let dest_short = if dest == "*" {
        "any".to_owned()
    } else {
        dest.to_owned()
    };

    format!("lulu-{action_word}-{proc_short}-{dest_short}")
}

/// Serialize a `UserRuleFile` to TOML for writing to disk.
///
/// # Errors
///
/// Returns an error if serialization fails.
pub fn rule_to_toml(rule: &UserRuleFile) -> Result<String, NetError> {
    toml::to_string_pretty(rule).map_err(|e| NetError::RuleParse {
        path: "<serialize>".to_owned(),
        message: format!("cannot serialize rule to TOML: {e}"),
    })
}

#[cfg(test)]
#[path = "import_test.rs"]
mod import_test;
