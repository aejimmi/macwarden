//! openbinary API client for binary intelligence lookups.
//!
//! Provides [`hash_file`], [`get_binary`], [`upload`], and [`poll_job`] for
//! the `lookup` command. Uses `ureq` (synchronous HTTP) — no Tokio required.

use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use ureq::unversioned::multipart::{Form, Part};

/// Default public API endpoint.
const DEFAULT_ENDPOINT: &str = "https://openbinary.org/api/v1";

/// Config file location.
const CONFIG_PATH: &str = "~/.macwarden/openbinary.toml";

/// Read the openbinary API endpoint from config, falling back to the default.
pub fn endpoint() -> String {
    let path = resolve_config_path();
    if let Ok(contents) = fs::read_to_string(path)
        && let Ok(table) = contents.parse::<toml::Table>()
        && let Some(ep) = table.get("endpoint").and_then(|v| v.as_str())
    {
        return ep.trim_end_matches('/').to_owned();
    }
    DEFAULT_ENDPOINT.to_owned()
}

/// SHA256 hash a file on disk. Returns lowercase hex.
pub fn hash_file(path: &Path) -> Result<String> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(format!("{:x}", hasher.finalize()))
}

/// Response from `GET /api/v1/binary/{sha256}`.
/// We keep it as raw JSON and extract fields for display.
pub type AnalysisJson = serde_json::Value;

/// Look up a binary by SHA256. Returns `Ok(None)` on 404.
pub fn get_binary(base: &str, sha256: &str) -> Result<Option<AnalysisJson>> {
    let url = format!("{base}/binary/{sha256}");
    let resp = ureq::get(&url).call();

    match resp {
        Ok(mut resp) => {
            let json: serde_json::Value =
                resp.body_mut().read_json().context("parse analysis JSON")?;
            Ok(Some(json))
        }
        Err(ureq::Error::StatusCode(404)) => Ok(None),
        Err(e) => bail!("API request failed: {e}"),
    }
}

/// Upload response — either already done or pending analysis.
pub enum UploadResult {
    /// Binary was already analyzed (dedup hit).
    AlreadyDone { sha256: String, name: String },
    /// Analysis enqueued — poll for progress.
    Pending { job_id: String },
}

/// Upload a binary for analysis. Returns either dedup hit or job ID.
pub fn upload(base: &str, path: &Path) -> Result<UploadResult> {
    let data = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let filename = path
        .file_name()
        .map_or_else(|| "upload".to_owned(), |n| n.to_string_lossy().into_owned());

    let form = Form::new().part("binary", Part::bytes(&data).file_name(&filename));

    let mut resp = ureq::post(&format!("{base}/upload"))
        .send(form)
        .context("upload binary")?;

    let json: serde_json::Value = resp
        .body_mut()
        .read_json()
        .context("parse upload response")?;

    let status = json
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");

    if status == "done" {
        let sha = json_str(&json, "sha256").to_owned();
        let name = json_str(&json, "name").to_owned();
        Ok(UploadResult::AlreadyDone { sha256: sha, name })
    } else {
        Ok(UploadResult::Pending {
            job_id: json_str_opt(&json, "job_id")
                .context("missing job_id in upload response")?
                .to_owned(),
        })
    }
}

/// Job status from the poll endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobStatus {
    Pending,
    Running,
    Done,
    Failed(String),
}

/// Poll the job status endpoint until terminal state. Calls `on_status` on
/// each change so the caller can update the display.
pub fn poll_job(
    base: &str,
    job_id: &str,
    on_status: &mut dyn FnMut(&JobStatus),
) -> Result<JobStatus> {
    let url = format!("{base}/job/{job_id}");
    let mut last = JobStatus::Pending;
    on_status(&last);

    loop {
        std::thread::sleep(Duration::from_millis(500));

        let mut resp = ureq::get(&url).call().context("poll job status")?;
        let json: serde_json::Value = resp.body_mut().read_json().context("parse job response")?;

        let status_str = json_str(&json, "status");
        let current = match status_str {
            "done" => JobStatus::Done,
            "failed" => {
                let err = json_str(&json, "error");
                let msg = if err.is_empty() { "unknown error" } else { err };
                JobStatus::Failed(msg.to_owned())
            }
            "running" => JobStatus::Running,
            _ => JobStatus::Pending,
        };

        if current != last {
            on_status(&current);
            last = current.clone();
        }

        match &current {
            JobStatus::Done | JobStatus::Failed(_) => return Ok(current),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_config_path() -> String {
    if let Some(rest) = CONFIG_PATH.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    CONFIG_PATH.to_owned()
}

/// Safe JSON string access — returns `""` if key missing or not a string.
fn json_str<'a>(json: &'a serde_json::Value, key: &str) -> &'a str {
    json.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

/// Safe JSON string access — returns `None` if key missing.
fn json_str_opt<'a>(json: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    json.get(key).and_then(|v| v.as_str())
}

/// Extract a string array from a JSON path like `["dna"]["sets"]["frameworks"]`.
pub fn extract_string_list(json: &serde_json::Value, keys: &[&str]) -> Vec<String> {
    let mut v = json;
    for key in keys {
        match v.get(*key) {
            Some(next) => v = next,
            None => return Vec::new(),
        }
    }
    v.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

/// Extract capabilities — handles both string array and object-with-category array.
pub fn extract_capabilities(json: &serde_json::Value) -> Vec<String> {
    let Some(arr) = json.get("capabilities").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|cap| {
            cap.as_str().map(String::from).or_else(|| {
                cap.get("category")
                    .and_then(|c| c.as_str())
                    .map(String::from)
            })
        })
        .collect()
}
