//! `macwarden daemon` — install or uninstall macwarden as a launchd service.
//!
//! Generates a launchd plist that runs `macwarden monitor` and loads it via
//! `launchctl`. Installs as a user agent in `~/Library/LaunchAgents/`.
//!
//! For system-wide monitoring (LaunchDaemons), run the install with `sudo`.
//! The plist is placed in `/Library/LaunchDaemons/` in that case.

use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::cli;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Service label for the macwarden launch agent.
const AGENT_LABEL: &str = "com.macwarden.monitor";

/// Plist filename.
const PLIST_NAME: &str = "com.macwarden.monitor.plist";

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

/// Install macwarden as a launchd service.
///
/// Generates the plist, writes it, and loads it via `launchctl bootstrap`.
pub fn install() -> Result<()> {
    let exe = std::env::current_exe().context("failed to locate macwarden binary")?;
    let exe_str = exe.to_string_lossy();

    let (plist_dir, domain) = plist_location()?;
    let plist_path = plist_dir.join(PLIST_NAME);
    let log_path = log_path()?;

    if plist_path.exists() {
        anyhow::bail!(
            "already installed at {}. Run `macwarden daemon uninstall` first.",
            plist_path.display(),
        );
    }

    let plist_content = generate_plist(&exe_str, &log_path.to_string_lossy());

    // Ensure parent directory exists.
    if let Some(parent) = plist_path.parent() {
        std::fs::create_dir_all(parent)
            .context(format!("failed to create {}", parent.display()))?;
    }

    std::fs::write(&plist_path, &plist_content)
        .context(format!("failed to write {}", plist_path.display()))?;

    println!("Wrote {}", plist_path.display());

    // Load the service.
    let status = std::process::Command::new("launchctl")
        .args(["bootstrap", &domain, &plist_path.to_string_lossy()])
        .status()
        .context("failed to run launchctl bootstrap")?;

    if !status.success() {
        // Fallback to legacy `load` for older macOS.
        let fallback = std::process::Command::new("launchctl")
            .args(["load", &plist_path.to_string_lossy()])
            .status()
            .context("failed to run launchctl load")?;
        if !fallback.success() {
            eprintln!("warning: launchctl load exited with {fallback}");
            eprintln!("The plist was written. You can load it manually:");
            eprintln!("  launchctl load {}", plist_path.display());
        }
    }

    println!("Installed. macwarden monitor is now running.");
    println!("  Logs: {}", log_path.display());
    println!("  Uninstall: macwarden daemon uninstall");

    Ok(())
}

/// Uninstall macwarden launchd service.
///
/// Unloads via `launchctl bootout` and removes the plist file.
pub fn uninstall() -> Result<()> {
    let (plist_dir, domain) = plist_location()?;
    let plist_path = plist_dir.join(PLIST_NAME);

    if !plist_path.exists() {
        anyhow::bail!("not installed (no plist at {}).", plist_path.display());
    }

    // Unload the service.
    let target = format!("{domain}/{AGENT_LABEL}");
    let status = std::process::Command::new("launchctl")
        .args(["bootout", &target])
        .status()
        .context("failed to run launchctl bootout")?;

    if !status.success() {
        // Fallback to legacy `unload`.
        let _ = std::process::Command::new("launchctl")
            .args(["unload", &plist_path.to_string_lossy()])
            .status();
    }

    std::fs::remove_file(&plist_path)
        .context(format!("failed to remove {}", plist_path.display()))?;

    println!("Uninstalled. Removed {}.", plist_path.display());

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Determine plist directory and launchctl domain based on effective UID.
///
/// Root → `/Library/LaunchDaemons/` + `system`.
/// User → `~/Library/LaunchAgents/` + `gui/{uid}`.
fn plist_location() -> Result<(PathBuf, String)> {
    // SAFETY: geteuid() is a pure read with no preconditions.
    #[allow(unsafe_code)]
    let is_root = unsafe { libc::geteuid() } == 0;
    if is_root {
        Ok((PathBuf::from("/Library/LaunchDaemons"), "system".to_owned()))
    } else {
        let dir = cli::expand_home("~/Library/LaunchAgents")?;
        // SAFETY: getuid() is a pure read with no preconditions.
        #[allow(unsafe_code)]
        let uid = unsafe { libc::getuid() };
        Ok((dir, format!("gui/{uid}")))
    }
}

/// Path for stdout/stderr log output.
fn log_path() -> Result<PathBuf> {
    cli::expand_home("~/.macwarden/monitor.log")
}

/// Generate a launchd plist for `macwarden monitor`.
fn generate_plist(exe_path: &str, log_path: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{AGENT_LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe_path}</string>
        <string>monitor</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{log_path}</string>
    <key>StandardErrorPath</key>
    <string>{log_path}</string>
    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
    <key>ProcessType</key>
    <string>Background</string>
    <key>LowPriorityIO</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>10</integer>
</dict>
</plist>
"#
    )
}

#[cfg(test)]
#[path = "daemon_test.rs"]
mod daemon_test;
