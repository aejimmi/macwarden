//! The impure `nettop` sampler: spawn the subprocess, parse its output.
//!
//! Gated to macOS since `nettop` is macOS-only; other targets return an empty
//! set so the crate still builds and links on Linux CI.

use crate::ProcNet;

/// Sample the machine's live per-process network telemetry via `nettop`.
///
/// Runs `nettop -x -J bytes_in,bytes_out -l 1`, parses the single sample, and
/// returns the per-process rows with their remote connections. A non-zero exit
/// yields an empty set rather than an error — nettop is best-effort telemetry.
#[cfg(target_os = "macos")]
pub fn sample() -> std::io::Result<Vec<ProcNet>> {
    use std::process::Command;

    let output = Command::new("/usr/bin/nettop")
        .args(["-x", "-J", "bytes_in,bytes_out", "-l", "1"])
        .output()?;
    if !output.status.success() {
        return Ok(Vec::new());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Ok(crate::parse(&text))
}

/// Non-macOS stub: `nettop` does not exist, so there is nothing to sample.
#[cfg(not(target_os = "macos"))]
pub fn sample() -> std::io::Result<Vec<ProcNet>> {
    Ok(Vec::new())
}
