//! `macwarden inventory` — binary inventory scanner and openbinary batch lookup.
//!
//! Subcommands:
//! - `scan`   — discover binaries, hash, sign-check, store to etch
//! - `lookup` — batch-process stored inventory through openbinary

mod lookup;
mod scan;

use anyhow::Result;
use clap::Subcommand;

use crate::cli::OutputFormat;

/// Subcommands for the `inventory` system.
#[derive(Debug, Subcommand)]
pub enum InventoryCommand {
    /// Scan installed applications and system binaries.
    ///
    /// By default scans /Applications, ~/Applications, /usr/bin,
    /// /usr/sbin, /usr/libexec, /usr/local/bin, and /opt/homebrew/bin.
    ///
    /// Pass --all to recursively walk the entire filesystem and find
    /// every executable (Mach-O detection + permission bits).
    ///
    /// Pass --lookup to also process unanalyzed binaries through openbinary.
    Scan {
        /// Recursively walk the full filesystem for all executables.
        #[arg(long)]
        all: bool,
        /// After scanning, look up unanalyzed binaries on openbinary.
        #[arg(long)]
        lookup: bool,
        /// Output format.
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },

    /// Look up stored inventory binaries on openbinary.
    ///
    /// Processes all binaries that haven't been analyzed yet through the
    /// openbinary API. Uses the same logic as `macwarden lookup`.
    /// Pass --no-upload to only check without uploading unknown binaries.
    Lookup {
        /// Do not upload unknown binaries — just check what's known.
        #[arg(long)]
        no_upload: bool,
        /// Output format.
        #[arg(short, long, default_value = "table")]
        format: OutputFormat,
    },
}

/// Dispatch an inventory subcommand.
pub fn run(command: &InventoryCommand) -> Result<()> {
    match *command {
        InventoryCommand::Scan {
            all,
            lookup: do_lookup,
            format,
        } => {
            scan::run(all, format)?;
            if do_lookup {
                lookup::run(false, format)?;
            }
            Ok(())
        }
        InventoryCommand::Lookup { no_upload, format } => lookup::run(no_upload, format),
    }
}
