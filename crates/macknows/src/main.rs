//! macknows CLI — decode Apple analyticsd telemetry databases.

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use macknows::category::Category;
use macknows::output;
use std::path::{Path, PathBuf};

/// The default location of analyticsd databases on macOS.
const DEFAULT_DIR: &str = "/private/var/db/analyticsd";

/// macknows — see what Apple knows about you.
///
/// Decodes the analyticsd SQLite databases to show exactly what telemetry
/// Apple collects, even when all analytics toggles are OFF.
#[derive(Parser)]
#[command(name = "macknows", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Available subcommands.
#[derive(Subcommand)]
enum Commands {
    /// Decode and display all collected telemetry.
    Decode {
        /// Directory containing config.sqlite + state.sqlite.
        #[arg(default_value = DEFAULT_DIR)]
        path: PathBuf,
        /// Filter by category.
        #[arg(long, value_parser = parse_category)]
        category: Option<Category>,
        /// Filter by event name (substring match).
        #[arg(long)]
        event: Option<String>,
        /// Show only data from OptOut configs (collected regardless of settings).
        #[arg(long)]
        opt_out_only: bool,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
        /// Limit output records.
        #[arg(long)]
        limit: Option<usize>,
    },
    /// Show high-level overview of collected telemetry.
    Summary {
        /// Directory containing config.sqlite + state.sqlite.
        #[arg(default_value = DEFAULT_DIR)]
        path: PathBuf,
    },
    /// List all event types from config with categories and transform counts.
    Events {
        /// Directory containing config.sqlite + state.sqlite.
        #[arg(default_value = DEFAULT_DIR)]
        path: PathBuf,
        /// Filter by category.
        #[arg(long, value_parser = parse_category)]
        category: Option<Category>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Decode {
            path,
            category,
            event,
            opt_out_only,
            json,
            limit,
        } => cmd_decode(&path, category, event.as_deref(), opt_out_only, json, limit),
        Commands::Summary { path } => cmd_summary(&path),
        Commands::Events {
            path,
            category,
            json,
        } => cmd_events(&path, category, json),
    }
}

/// Execute the `decode` subcommand.
fn cmd_decode(
    dir: &Path,
    category: Option<Category>,
    event: Option<&str>,
    opt_out_only: bool,
    json: bool,
    limit: Option<usize>,
) -> Result<()> {
    let (config, state) = resolve_paths(dir)?;
    let mut records =
        macknows::decode_databases(&config, &state).context("failed to decode databases")?;

    // Apply filters (AND logic)
    if let Some(cat) = category {
        records.retain(|r| r.category == cat);
    }
    if let Some(substr) = event {
        records.retain(|r| r.event_names.iter().any(|n| n.contains(substr)));
    }
    if opt_out_only {
        records.retain(|r| r.config_type == "OptOut");
    }
    if let Some(n) = limit {
        records.truncate(n);
    }

    if json {
        let out =
            output::format_decode_json(&records).context("failed to serialize records as JSON")?;
        println!("{out}");
    } else {
        println!("{}", output::format_decode_table(&records));
    }

    Ok(())
}

/// Execute the `summary` subcommand.
fn cmd_summary(dir: &Path) -> Result<()> {
    let (config, state) = resolve_paths(dir)?;
    let summary = macknows::summary(&config, &state).context("failed to generate summary")?;
    println!("{}", output::format_summary(&summary));
    Ok(())
}

/// Execute the `events` subcommand.
fn cmd_events(dir: &Path, category: Option<Category>, json: bool) -> Result<()> {
    let (config, _state) = resolve_paths(dir)?;
    let mut events = macknows::list_events(&config).context("failed to list events")?;

    if let Some(cat) = category {
        events.retain(|e| e.category == cat);
    }

    if json {
        let out =
            output::format_events_json(&events).context("failed to serialize events as JSON")?;
        println!("{out}");
    } else {
        println!("{}", output::format_events_table(&events));
    }

    Ok(())
}

/// Resolve a directory to the two database file paths, with helpful error messages.
fn resolve_paths(dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let config = dir.join("config.sqlite");
    let state = dir.join("state.sqlite");

    if !dir.exists() {
        bail!(
            "directory not found: {}\n\n\
             Hint: copy the databases from /private/var/db/analyticsd/ to a local directory,\n\
             or run with sudo: sudo macknows decode",
            dir.display()
        );
    }

    if !config.exists() {
        bail!(
            "config.sqlite not found in {}\n\n\
             Expected: {}\n\
             Hint: the directory should contain both config.sqlite and state.sqlite",
            dir.display(),
            config.display()
        );
    }

    if !state.exists() {
        bail!(
            "state.sqlite not found in {}\n\n\
             Expected: {}\n\
             Hint: the directory should contain both config.sqlite and state.sqlite",
            dir.display(),
            state.display()
        );
    }

    Ok((config, state))
}

/// Parse a category string from CLI arguments.
fn parse_category(s: &str) -> std::result::Result<Category, String> {
    s.parse()
}
