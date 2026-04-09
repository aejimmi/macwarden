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
    /// Run with --list to see all available targets.
    Scrub {
        /// Group name, artifact domain, or individual artifact to scrub.
        /// Use 'all' to clean everything.
        target: Option<String>,
        /// Print actions without executing.
        #[arg(short = 'n', long)]
        dry_run: bool,
        /// List all available scrub targets.
        #[arg(short, long)]
        list: bool,
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

    /// Show privacy posture and score.
    Status {
        /// Output format.
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Look up a binary on openbinary for behavioral analysis.
    ///
    /// With no arguments, shows the configured endpoint and tests
    /// connectivity. With a path, hashes the file, checks the openbinary
    /// database, and auto-uploads for analysis if not found.
    Lookup {
        /// Path to the binary to look up. Omit to test endpoint connectivity.
        path: Option<String>,
        /// Do not upload if the binary is unknown — just report.
        #[arg(long)]
        no_upload: bool,
        /// Output format.
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Binary inventory — scan installed apps and system binaries.
    ///
    /// Discover executables, hash them, verify code signing, and check
    /// against the known-bad hash blocklist. Use `inventory lookup` to
    /// batch-process the inventory through openbinary.
    Inventory {
        #[command(subcommand)]
        command: commands::inventory::InventoryCommand,
    },

    /// Network firewall — rules, groups, trackers, apps, explain.
    Net {
        #[command(subcommand)]
        command: NetCommand,
    },
}

/// Subcommands for the `net` firewall system.
#[derive(Debug, Subcommand)]
pub enum NetCommand {
    /// Show active network connections with firewall rule evaluation.
    Scan {
        /// Filter by process name or code_id.
        #[arg(long)]
        process: Option<String>,
        /// Show only denied / would-be-denied connections.
        #[arg(long)]
        denied: bool,
        /// Show only tracker connections.
        #[arg(long)]
        trackers: bool,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Enable or disable the tracker shield (one-command protection).
    Shield {
        /// Disable the tracker shield.
        #[arg(long)]
        off: bool,
        /// Block specific categories only (advertising, analytics, fingerprinting, social).
        #[arg(long)]
        only: Vec<String>,
    },
    /// List network rules (user + groups + trackers).
    Rules {
        /// Filter by process code_id pattern.
        #[arg(long)]
        process: Option<String>,
        /// Filter by group name.
        #[arg(long)]
        group: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// List network rule groups with enable/disable status.
    Groups {
        /// Enable a group.
        #[arg(long)]
        enable: Option<String>,
        /// Disable a group.
        #[arg(long)]
        disable: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Tracker shield — categories and stats.
    Trackers {
        /// Show blocking stats.
        #[arg(long)]
        stats: bool,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show app categories, live connections grouped by app, or per-app details.
    Apps {
        /// Filter by category (default mode).
        #[arg(long)]
        category: Option<String>,
        /// Show live connections grouped by application.
        #[arg(long)]
        live: bool,
        /// Expand a specific app to show per-destination details.
        #[arg(long)]
        expand: Option<String>,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Explain why a connection would be allowed or denied.
    Explain {
        /// Process code_id or path.
        process: String,
        /// Destination hostname (optional).
        host: Option<String>,
    },
    /// Show live network decision log (requires ES daemon).
    Log,
    /// Watch connections and suggest firewall rules.
    Learn {
        /// Duration to learn (e.g. "30s", "5m", "1h"). Default: until Ctrl+C.
        #[arg(long, short)]
        duration: Option<String>,
        /// Generate rule files from observed traffic.
        #[arg(long)]
        apply: bool,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Manage external blocklist subscriptions.
    Blocklists {
        /// Add a local blocklist file (hosts format).
        #[arg(long)]
        add: Option<String>,
        /// List configured blocklists.
        #[arg(long)]
        list: bool,
    },
    /// Block an app or destination in the network firewall.
    ///
    /// Creates a deny rule in ~/.macwarden/net-rules/. Use --app to
    /// target a specific application, --host for a domain, or both
    /// for a scoped app+destination rule.
    Block {
        /// App name or code signing identity to block.
        #[arg(long)]
        app: Option<String>,
        /// Destination hostname to block.
        #[arg(long)]
        host: Option<String>,
    },
    /// Unblock a previously blocked app or destination.
    ///
    /// Removes the matching deny rule from ~/.macwarden/net-rules/.
    Unblock {
        /// App name or code signing identity to unblock.
        #[arg(long)]
        app: Option<String>,
        /// Destination hostname to unblock.
        #[arg(long)]
        host: Option<String>,
    },
    /// Import rules from an external firewall application.
    ///
    /// Reads rules from LuLu's rules.json and converts them to macwarden
    /// user rules in ~/.macwarden/net-rules/.
    Import {
        /// Source firewall to import from (currently: "lulu").
        source: String,
        /// Path to the rules file (auto-detected if omitted).
        #[arg(long)]
        path: Option<String>,
        /// Write converted rules to disk (default: dry-run preview).
        #[arg(long)]
        apply: bool,
        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Download or update GeoIP databases for IP enrichment.
    ///
    /// Downloads MaxMind GeoLite2-Country and GeoLite2-ASN databases
    /// to ~/.macwarden/geo/. Requires a free MaxMind license key.
    /// Get one at: https://www.maxmind.com/en/geolite2/signup
    Enrich {
        /// MaxMind license key (or set MAXMIND_LICENSE_KEY env var).
        #[arg(long)]
        key: Option<String>,
        /// Remove downloaded GeoIP databases.
        #[arg(long)]
        remove: bool,
        /// Show current GeoIP database status.
        #[arg(long)]
        status: bool,
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
    expand_home("~/.macwarden/active-profile")
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

        Some(Commands::Scrub {
            target,
            dry_run,
            list,
        }) => commands::scrub::run(target.as_deref(), dry_run, list),

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

        Some(Commands::Status { format }) => commands::status::run(format),

        Some(Commands::Devices { format, revoke }) => match revoke {
            Some(bundle_id) => commands::devices::revoke(&bundle_id),
            None => commands::devices::run(format),
        },

        Some(Commands::Lookup {
            path: Some(path),
            no_upload,
            format,
        }) => commands::lookup::run(&path, no_upload, format),

        Some(Commands::Lookup { path: None, .. }) => commands::lookup::ping(),

        Some(Commands::Inventory { ref command }) => commands::inventory::run(command),

        Some(Commands::Net { command }) => commands::net::run(command),
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
