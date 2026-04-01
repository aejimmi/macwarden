//! Real macOS platform implementation.
//!
//! Wraps `launchctl`, `kill`, and `csrutil` commands to interact with the
//! macOS service management layer.

use std::process::Command;

use tracing::debug;

use crate::error::LaunchdError;
use crate::platform::{LaunchctlEntry, Platform, ProcessDetail, ServiceDetail, SipState};

/// Platform implementation that talks to real macOS system commands.
#[derive(Debug, Clone, Default)]
pub struct MacOsPlatform;

impl MacOsPlatform {
    /// Creates a new platform instance.
    pub fn new() -> Self {
        Self
    }
}

impl Platform for MacOsPlatform {
    fn enumerate(&self) -> Result<Vec<LaunchctlEntry>, LaunchdError> {
        let output = Command::new("launchctl")
            .arg("list")
            .output()
            .map_err(LaunchdError::Io)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(LaunchdError::CommandFailed {
                cmd: "launchctl list".to_owned(),
                stderr,
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_launchctl_output(&stdout))
    }

    fn disable(&self, domain: &str, label: &str) -> Result<(), LaunchdError> {
        let target = format!("{domain}/{label}");
        debug!(target = %target, "disabling service");

        run_launchctl(&["disable", &target])
    }

    fn enable(&self, domain: &str, label: &str) -> Result<(), LaunchdError> {
        let target = format!("{domain}/{label}");
        debug!(target = %target, "enabling service");

        run_launchctl(&["enable", &target])
    }

    fn kill_process(&self, pid: u32) -> Result<(), LaunchdError> {
        debug!(pid, "killing process (SIGTERM first, SIGKILL fallback)");

        // Step 1: try SIGTERM for a graceful shutdown.
        let term_output = Command::new("kill")
            .args(["-15", &pid.to_string()])
            .output()
            .map_err(LaunchdError::Io)?;

        if term_output.status.success() {
            // Wait up to 2 seconds for the process to exit.
            for _ in 0..4 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if !is_pid_alive(pid) {
                    debug!(pid, "process exited after SIGTERM");
                    return Ok(());
                }
            }
            debug!(pid, "process survived SIGTERM, escalating to SIGKILL");
        } else {
            // Process may already be gone — that's fine.
            let stderr = String::from_utf8_lossy(&term_output.stderr);
            if stderr.contains("No such process") {
                return Ok(());
            }
            // Fall through to SIGKILL.
        }

        // Step 2: SIGKILL as fallback.
        let kill_output = Command::new("kill")
            .args(["-9", &pid.to_string()])
            .output()
            .map_err(LaunchdError::Io)?;

        if !kill_output.status.success() {
            let stderr = String::from_utf8_lossy(&kill_output.stderr).to_string();
            if !stderr.contains("No such process") {
                return Err(LaunchdError::CommandFailed {
                    cmd: format!("kill -9 {pid}"),
                    stderr,
                });
            }
        }

        Ok(())
    }

    fn is_running(&self, label: &str) -> Result<bool, LaunchdError> {
        let entries = self.enumerate()?;
        let running = entries.iter().any(|e| e.label == label && e.pid.is_some());
        Ok(running)
    }

    fn sip_status(&self) -> Result<SipState, LaunchdError> {
        let output = Command::new("csrutil")
            .arg("status")
            .output()
            .map_err(LaunchdError::Io)?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_sip_output(&stdout))
    }

    fn inspect(&self, domain: &str, label: &str) -> Result<ServiceDetail, LaunchdError> {
        let target = format!("{domain}/{label}");
        debug!(target = %target, "inspecting service");

        let output = Command::new("launchctl")
            .args(["print", &target])
            .output()
            .map_err(LaunchdError::Io)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(LaunchdError::CommandFailed {
                cmd: format!("launchctl print {target}"),
                stderr,
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut detail = parse_launchctl_print(&stdout);
        label.clone_into(&mut detail.label);
        domain.clone_into(&mut detail.domain);
        Ok(detail)
    }

    fn process_detail(&self, pid: u32) -> Result<ProcessDetail, LaunchdError> {
        debug!(pid, "querying process detail");
        let ps_detail = parse_ps_output(pid)?;
        let open_files = parse_lsof_output(pid);
        Ok(ProcessDetail {
            open_files,
            ..ps_detail
        })
    }

    fn bootout(&self, domain: &str, label: &str) -> Result<(), LaunchdError> {
        let target = format!("{domain}/{label}");
        debug!(target = %target, "booting out service");
        run_launchctl(&["bootout", &target])
    }
}

/// Runs a `launchctl` subcommand and checks for success.
fn run_launchctl(args: &[&str]) -> Result<(), LaunchdError> {
    let output = Command::new("launchctl")
        .args(args)
        .output()
        .map_err(LaunchdError::Io)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let cmd = format!("launchctl {}", args.join(" "));
        return Err(LaunchdError::CommandFailed { cmd, stderr });
    }

    Ok(())
}

/// Parses the tab-separated output of `launchctl list`.
///
/// Expected format:
/// ```text
/// PID\tStatus\tLabel
/// -\t0\tcom.apple.example
/// 123\t0\tcom.apple.running
/// ```
///
/// The first line is a header and is skipped. A PID of `-` is treated as
/// `None`. Non-numeric PID values are also treated as `None`.
pub fn parse_launchctl_output(output: &str) -> Vec<LaunchctlEntry> {
    output
        .lines()
        .skip(1) // Skip header line
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }

            let parts: Vec<&str> = line.splitn(3, '\t').collect();
            if parts.len() < 3 {
                return None;
            }

            let pid = parts.first().and_then(|s| s.parse::<u32>().ok());

            let last_exit_status = parts.get(1).and_then(|s| s.parse::<i32>().ok());

            let label = parts.get(2).unwrap_or(&"").to_string();
            if label.is_empty() {
                return None;
            }

            Some(LaunchctlEntry {
                label,
                pid,
                last_exit_status,
            })
        })
        .collect()
}

/// Parses the output of `launchctl print {domain}/{label}`.
///
/// Extracts structured fields from the freeform text output. Unknown fields
/// are silently ignored.
pub fn parse_launchctl_print(output: &str) -> ServiceDetail {
    let mut detail = ServiceDetail::default();

    let mut arguments_depth: u32 = 0;
    let mut endpoints_depth: u32 = 0;

    for line in output.lines() {
        let trimmed = line.trim();

        // Track brace depth for block sections.
        let opens = trimmed.matches('{').count() as u32;
        let closes = trimmed.matches('}').count() as u32;

        if arguments_depth > 0 {
            arguments_depth = arguments_depth.saturating_add(opens).saturating_sub(closes);
            // Collect argument values (skip braces-only lines).
            if !trimmed.is_empty() && trimmed != "{" && trimmed != "}" {
                detail.arguments.push(trimmed.to_owned());
            }
            continue;
        }

        if endpoints_depth > 0 {
            endpoints_depth = endpoints_depth.saturating_add(opens).saturating_sub(closes);
            // Extract top-level endpoint names: "com.apple.foo" = {
            if let Some(name) = extract_endpoint_name(trimmed) {
                detail.mach_services.push(name);
            }
            continue;
        }

        if let Some(value) = extract_field(trimmed, "state = ") {
            value.clone_into(&mut detail.state);
        } else if let Some(value) = extract_field(trimmed, "pid = ") {
            detail.pid = value.parse().ok();
        } else if let Some(value) = extract_field(trimmed, "program = ") {
            detail.program = Some(value.to_owned());
        } else if let Some(value) = extract_field(trimmed, "exit timeout = ") {
            detail.exit_timeout = value.parse().ok();
        } else if let Some(value) = extract_field(trimmed, "runs = ") {
            detail.runs = value.parse().ok();
        } else if let Some(value) = extract_field(trimmed, "keep alive = ")
            .or_else(|| extract_field(trimmed, "keepalive = "))
        {
            detail.keep_alive = Some(value.to_owned());
        } else if trimmed.starts_with("arguments = ") || trimmed == "arguments = {" {
            arguments_depth = opens.saturating_sub(closes);
        } else if trimmed.starts_with("endpoints = ")
            || trimmed == "endpoints = {"
            || trimmed.starts_with("machservices = ")
            || trimmed == "machservices = {"
        {
            endpoints_depth = opens.saturating_sub(closes);
        }
    }

    detail
}

/// Extract a simple `key = value` field from a trimmed line.
fn extract_field<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    line.strip_prefix(prefix).map(str::trim)
}

/// Extract an endpoint/mach service name from a line like `"com.apple.foo" = {`.
///
/// Only matches lines where a quoted name is followed by ` = {`, which is the
/// format used by `launchctl print` for endpoint entries.
fn extract_endpoint_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    // Endpoint lines start with a quoted name: "com.apple.foo" = {
    if !trimmed.starts_with('"') {
        return None;
    }
    // Extract the name between quotes.
    let after_quote = &trimmed[1..];
    let end = after_quote.find('"')?;
    let name = &after_quote[..end];
    if name.is_empty() {
        return None;
    }
    // Verify it's followed by ` = {`
    let rest = after_quote.get(end + 1..)?.trim();
    if rest.starts_with("= {") || rest.starts_with("= 0x") {
        Some(name.to_owned())
    } else {
        None
    }
}

/// Parse `ps` output for a single PID.
fn parse_ps_output(pid: u32) -> Result<ProcessDetail, LaunchdError> {
    let output = Command::new("ps")
        .args([
            "-p",
            &pid.to_string(),
            "-o",
            "pid=,ppid=,user=,%cpu=,%mem=,rss=,command=",
        ])
        .output()
        .map_err(LaunchdError::Io)?;

    if !output.status.success() {
        return Err(LaunchdError::CommandFailed {
            cmd: format!("ps -p {pid}"),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.trim();
    if line.is_empty() {
        return Err(LaunchdError::ParseError(format!(
            "no ps output for pid {pid}"
        )));
    }

    parse_ps_line(line, pid)
}

/// Parse a single line of `ps -o pid=,ppid=,user=,%cpu=,%mem=,rss=,command=`.
fn parse_ps_line(line: &str, pid: u32) -> Result<ProcessDetail, LaunchdError> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 7 {
        return Err(LaunchdError::ParseError(format!(
            "unexpected ps output: {line}"
        )));
    }

    let parsed_pid = parts
        .first()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(pid);
    let ppid = parts
        .get(1)
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let user = parts.get(2).unwrap_or(&"").to_string();
    let cpu_percent = parts
        .get(3)
        .and_then(|s| s.parse::<f32>().ok())
        .unwrap_or(0.0);
    let mem_percent = parts
        .get(4)
        .and_then(|s| s.parse::<f32>().ok())
        .unwrap_or(0.0);
    let rss_kb = parts
        .get(5)
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    let command = parts.get(6..).map(|s| s.join(" ")).unwrap_or_default();

    Ok(ProcessDetail {
        pid: parsed_pid,
        ppid,
        user,
        cpu_percent,
        mem_percent,
        rss_kb,
        command,
        open_files: vec![],
    })
}

/// Parse `lsof -p {pid} -Fn` output to extract open file paths.
///
/// Returns at most 20 file paths. Errors are silently ignored since `lsof`
/// may not be available or may fail for permission reasons.
fn parse_lsof_output(pid: u32) -> Vec<String> {
    let output = Command::new("lsof")
        .args(["-p", &pid.to_string(), "-Fn"])
        .stderr(std::process::Stdio::null())
        .output();

    let Ok(output) = output else {
        return vec![];
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter_map(|line| line.strip_prefix('n'))
        .filter(|path| !path.is_empty())
        .take(20)
        .map(ToOwned::to_owned)
        .collect()
}

/// Check whether a PID is still alive via `kill -0`.
fn is_pid_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

/// Parses `csrutil status` output to determine SIP state.
fn parse_sip_output(output: &str) -> SipState {
    let lower = output.to_lowercase();
    if lower.contains("enabled") {
        SipState::Enabled
    } else if lower.contains("disabled") {
        SipState::Disabled
    } else {
        SipState::Unknown
    }
}

// ---------------------------------------------------------------------------
// Binary analysis (for catalog generation)
// ---------------------------------------------------------------------------

/// Result of scanning a binary for telemetry indicators.
#[derive(Debug, Clone, Default)]
pub struct TelemetryScan {
    /// Whether analytics/telemetry strings were found.
    pub has_analytics: bool,
    /// Which telemetry keywords matched.
    pub keywords_found: Vec<String>,
}

/// Extract linked framework names from a binary via `otool -L`.
pub fn binary_frameworks(binary_path: &str) -> Vec<String> {
    let Ok(output) = Command::new("otool").args(["-L", binary_path]).output() else {
        return vec![];
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .filter_map(|line| {
            // Lines look like: /System/Library/.../Foo.framework/Foo (compat ...)
            let trimmed = line.trim();
            if let Some(idx) = trimmed.find(".framework") {
                let before = &trimmed[..idx];
                let name = before.rsplit('/').next().unwrap_or("");
                if !name.is_empty() {
                    return Some(name.to_owned());
                }
            }
            None
        })
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// Scan a binary's strings for telemetry/analytics indicators.
pub fn binary_telemetry_scan(binary_path: &str) -> TelemetryScan {
    let Ok(output) = Command::new("strings").arg(binary_path).output() else {
        return TelemetryScan::default();
    };
    let stdout = String::from_utf8_lossy(&output.stdout).to_lowercase();

    let keywords = [
        "coreanalytics",
        "analyticssubmission",
        "diagnosticsubmission",
        "reporttelemetry",
        "telemetrydata",
        "xp.apple.com",
        "mesu.apple.com",
        "daw.apple.com",
    ];

    let found: Vec<String> = keywords
        .iter()
        .filter(|k| stdout.contains(**k))
        .map(|k| (*k).to_owned())
        .collect();

    TelemetryScan {
        has_analytics: !found.is_empty(),
        keywords_found: found,
    }
}

#[cfg(test)]
#[path = "macos_test.rs"]
mod macos_test;
