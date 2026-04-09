//! `macwarden net import` -- import rules from external firewall applications.

use std::path::PathBuf;

use anyhow::{Context, Result, bail};

/// Run `macwarden net import <source>`.
pub(super) fn run(source: &str, path: Option<&str>, apply: bool, json: bool) -> Result<()> {
    match source.to_ascii_lowercase().as_str() {
        "lulu" => run_lulu(path, apply, json),
        other => bail!("unknown import source: `{other}`. Supported: lulu"),
    }
}

/// Import rules from LuLu.
fn run_lulu(path: Option<&str>, apply: bool, json: bool) -> Result<()> {
    let rules_path = path.map_or_else(net::import::default_lulu_path, PathBuf::from);

    if !rules_path.is_file() {
        bail!(
            "LuLu rules not found at: {}\n\n\
             If LuLu is installed, its rules are typically at:\n  {}\n\n\
             You can specify a custom path with --path.",
            rules_path.display(),
            net::import::LULU_RULES_PATH,
        );
    }

    let summary = net::import::import_lulu(&rules_path).context("failed to import LuLu rules")?;

    if json {
        print_json(&summary)?;
        return Ok(());
    }

    // Print imported rules.
    if summary.imported.is_empty() {
        println!("No rules imported from LuLu.");
    } else {
        println!(
            "LuLu Import — {} rules converted{}",
            summary.imported.len(),
            if apply { "" } else { " (dry-run)" },
        );
        println!();
        for item in &summary.imported {
            let action = match item.rule.action {
                net::NetworkAction::Allow => "ALLOW",
                net::NetworkAction::Deny => "DENY",
                net::NetworkAction::Log => "LOG",
            };
            println!(
                "  {:<6}  {:<40}  {}",
                action, item.rule.process, item.rule.dest,
            );
        }
    }

    // Print skipped rules.
    if !summary.skipped.is_empty() {
        println!("\nSkipped {} rules:", summary.skipped.len());
        for (desc, reason) in &summary.skipped {
            println!("  {desc}: {reason}");
        }
    }

    // Write to disk if --apply.
    if apply {
        let written = write_rules(&summary)?;
        println!("\nWrote {written} rule files to ~/.macwarden/net-rules/");
    } else if !summary.imported.is_empty() {
        println!("\nDry-run mode. Use --apply to write rule files.");
    }

    Ok(())
}

/// Write imported rules as TOML files to ~/.macwarden/net-rules/.
fn write_rules(summary: &net::import::ImportSummary) -> Result<usize> {
    let home = std::env::var("HOME").context("HOME not set")?;
    let rules_dir = PathBuf::from(home).join(".macwarden").join("net-rules");
    std::fs::create_dir_all(&rules_dir)
        .with_context(|| format!("failed to create {}", rules_dir.display()))?;

    let mut written = 0;
    for item in &summary.imported {
        let toml = net::import::rule_to_toml(&item.rule).context("failed to serialize rule")?;

        // Sanitize the name for use as a filename.
        let safe_name: String = item
            .rule
            .name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        let filename = format!("{safe_name}.toml");
        let file_path = rules_dir.join(&filename);

        std::fs::write(&file_path, &toml)
            .with_context(|| format!("failed to write {}", file_path.display()))?;
        written += 1;
    }

    Ok(written)
}

/// Print import summary as JSON.
fn print_json(summary: &net::import::ImportSummary) -> Result<()> {
    #[derive(serde::Serialize)]
    struct JsonOutput {
        imported: Vec<JsonRule>,
        skipped: Vec<JsonSkipped>,
    }

    #[derive(serde::Serialize)]
    struct JsonRule {
        name: String,
        process: String,
        dest: String,
        dest_port: Option<u16>,
        action: String,
        source_path: String,
    }

    #[derive(serde::Serialize)]
    struct JsonSkipped {
        description: String,
        reason: String,
    }

    let output = JsonOutput {
        imported: summary
            .imported
            .iter()
            .map(|r| JsonRule {
                name: r.rule.name.clone(),
                process: r.rule.process.clone(),
                dest: r.rule.dest.clone(),
                dest_port: r.rule.dest_port,
                action: r.rule.action.to_string(),
                source_path: r.source_path.clone(),
            })
            .collect(),
        skipped: summary
            .skipped
            .iter()
            .map(|(d, r)| JsonSkipped {
                description: d.clone(),
                reason: r.clone(),
            })
            .collect(),
    };

    let json =
        serde_json::to_string_pretty(&output).context("failed to serialize import summary")?;
    println!("{json}");
    Ok(())
}
