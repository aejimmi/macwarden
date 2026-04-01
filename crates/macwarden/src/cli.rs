//! CLI argument parsing, tracing setup, and command dispatch.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

use crate::commands;

// ---------------------------------------------------------------------------
// Clap types
// ---------------------------------------------------------------------------

/// A profile-based daemon firewall for macOS.
///
/// Run with no arguments to see what's on your machine.
#[derive(Debug, Parser)]
#[command(name = "macwarden", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    // Flags for the default (scan) mode — when no subcommand is given.
    /// Filter by service category (e.g. telemetry, networking).
    #[arg(short, long)]
    category: Option<String>,

    /// Show only uncategorized / unknown services.
    #[arg(short = 'u', long)]
    unknown: bool,

    /// Show service groups instead of individual services.
    #[arg(short, long)]
    groups: bool,

    /// Sort order for groups view.
    #[arg(long, default_value = "name")]
    sort: GroupSort,

    /// Show only groups with this safety tier (with --groups).
    #[arg(long)]
    filter: Option<SafetyFilter>,

    /// Output format.
    #[arg(short, long, default_value = "table")]
    format: OutputFormat,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
enum Commands {
    /// Scan and list all discovered launchd services.
    ///
    /// This is also the default when no subcommand is given.
    Scan {
        /// Filter by service category (e.g. telemetry, networking).
        #[arg(short, long)]
        category: Option<String>,
        /// Show only uncategorized / unknown services.
        #[arg(short = 'u', long)]
        unknown: bool,
        /// Show service groups instead of individual services.
        #[arg(short, long)]
        groups: bool,
        /// Sort order for groups view.
        #[arg(long, default_value = "name")]
        sort: GroupSort,
        /// Show only groups with this safety tier (with --groups).
        #[arg(long)]
        filter: Option<SafetyFilter>,
        /// Output format.
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Show detailed information about a service, group, or profile.
    ///
    /// Automatically detects whether the target is a service label,
    /// group name, or profile name.
    Info {
        /// Service label, group name, or profile name.
        target: String,
        /// Output format.
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Enforce a profile. Run with no argument to see current status.
    Use {
        /// Profile name to enforce (omit to show current status).
        profile: Option<String>,
        /// Print actions without executing.
        #[arg(short = 'n', long)]
        dry_run: bool,
    },

    /// Block a service or group from running.
    Block {
        /// Service label or group name to block.
        target: String,
        /// Print actions without executing.
        #[arg(short = 'n', long)]
        dry_run: bool,
        /// Service labels to exclude (can be repeated).
        #[arg(long = "except", num_args = 1)]
        except: Vec<String>,
    },

    /// Allow a previously blocked service or group to run again.
    Allow {
        /// Service label or group name to allow.
        target: String,
        /// Print actions without executing.
        #[arg(short = 'n', long)]
        dry_run: bool,
    },

    /// Watch for drift and continuously enforce the active profile.
    ///
    /// Runs in the foreground by default. Use --install to run as a
    /// background launchd service that persists across reboots.
    Watch {
        /// Override the active profile without changing the saved setting.
        #[arg(short, long)]
        profile: Option<String>,
        /// Install macwarden as a persistent launchd service.
        #[arg(long)]
        install: bool,
        /// Remove the persistent launchd service.
        #[arg(long)]
        uninstall: bool,
    },

    /// Delete data artifacts left by disabled services.
    ///
    /// Removes Spotlight indexes, behavioral databases, ML caches,
    /// diagnostic logs, and other traces a group's services wrote to disk.
    Scrub {
        /// Group name to scrub data for.
        target: String,
        /// Print actions without executing.
        #[arg(short = 'n', long)]
        dry_run: bool,
    },

    /// Revert the last enforcement action.
    Undo {
        /// Snapshot name (reverts latest if omitted).
        name: Option<String>,
        /// Print actions without executing.
        #[arg(short = 'n', long)]
        dry_run: bool,
    },

    /// Show active network connections by service and group.
    Network {
        /// Output format.
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
        /// Show all connections including LISTEN and local UDP.
        #[arg(short, long)]
        all: bool,
    },

    /// Show what has access to your camera and microphone.
    ///
    /// Reads the macOS TCC database to find authorized apps, then
    /// cross-references with running processes and macwarden groups.
    /// Use --revoke to remove a stale or unwanted authorization.
    Devices {
        /// Output format.
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
        /// Revoke camera and microphone access for an app (bundle ID).
        #[arg(long)]
        revoke: Option<String>,
    },
}

/// Profiles sub-subcommands (used by profiles module internally).
#[derive(Debug, Subcommand)]
pub enum ProfilesSubcmd {
    /// Display the rules of a specific profile.
    Show {
        /// Profile name to display.
        name: String,
    },
}

/// Sort order for the `groups` view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum GroupSort {
    /// Alphabetical by group name.
    Name,
    /// By total service count (descending).
    Services,
    /// By running service count (descending).
    Running,
    /// By safety tier: recommended first, then optional, then keep.
    Safety,
}

/// Safety tier filter for the `groups` view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SafetyFilter {
    /// Show only groups safe to disable.
    Recommended,
    /// Show only groups that trade a feature for privacy.
    Optional,
    /// Show only groups that should be kept.
    Keep,
}

/// Output format selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Human-readable table.
    Table,
    /// Machine-readable JSON.
    Json,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Expand leading `~` in a path to the user's home directory.
pub fn expand_home(path: &str) -> Result<PathBuf> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = std::env::var("HOME").context("HOME environment variable not set")?;
        Ok(PathBuf::from(home).join(rest))
    } else {
        Ok(PathBuf::from(path))
    }
}

/// Build the list of plist directories with `~` expanded.
pub fn plist_dirs() -> Result<Vec<PathBuf>> {
    catalog::DEFAULT_PLIST_DIRS
        .iter()
        .map(|p| expand_home(p))
        .collect()
}

/// Return the path to the active-profile marker file.
pub fn active_profile_path() -> Result<PathBuf> {
    expand_home("~/.config/macwarden/active-profile")
}

/// Read the active profile name, defaulting to `"base"`.
pub fn read_active_profile() -> Result<String> {
    let path = active_profile_path()?;
    match std::fs::read_to_string(&path) {
        Ok(content) => Ok(content.trim().to_owned()),
        Err(_) => Ok("base".to_owned()),
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Initialise tracing, parse arguments, and dispatch to the correct command.
pub fn run() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();

    match cli.command {
        // No subcommand → default scan.
        None => {
            if cli.groups {
                commands::groups::run(cli.sort, cli.filter)
            } else {
                commands::scan::run(cli.category.as_deref(), cli.unknown, cli.format)
            }
        }

        Some(Commands::Scan {
            category,
            unknown,
            groups,
            sort,
            filter,
            format,
        }) => {
            if groups {
                commands::groups::run(sort, filter)
            } else {
                commands::scan::run(category.as_deref(), unknown, format)
            }
        }

        Some(Commands::Info { target, format }) => {
            // Smart resolve: try profile → group → service.
            commands::inspect::run(&target, format)
        }

        Some(Commands::Use { profile, dry_run }) => match profile {
            Some(name) => commands::apply::run(&name, dry_run),
            None => commands::status::run(cli.format),
        },

        Some(Commands::Block {
            target,
            dry_run,
            except,
        }) => commands::disable::run(&target, dry_run, &except),

        Some(Commands::Allow { target, dry_run }) => commands::enable::run(&target, dry_run),

        Some(Commands::Scrub { target, dry_run }) => commands::scrub::run(&target, dry_run),

        Some(Commands::Watch {
            profile,
            install,
            uninstall,
        }) => {
            if install {
                commands::daemon::install()
            } else if uninstall {
                commands::daemon::uninstall()
            } else {
                commands::monitor::run(profile.as_deref())
            }
        }

        Some(Commands::Undo { name, dry_run }) => commands::rollback::run(name.as_deref(), dry_run),

        Some(Commands::Network { format, all }) => commands::network::run(format, all),

        Some(Commands::Devices { format, revoke }) => match revoke {
            Some(bundle_id) => commands::devices::revoke(&bundle_id),
            None => commands::devices::run(format),
        },
    }
}

/// Initialise `tracing-subscriber` with `RUST_LOG` env filter.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}
