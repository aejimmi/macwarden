//! `macwarden` — a profile-based daemon firewall for macOS.
//!
//! Thin entry point that delegates to [`cli::run`].

use anyhow::Result;

mod cli;
mod commands;
mod openbinary;

fn main() -> Result<()> {
    cli::run()
}
