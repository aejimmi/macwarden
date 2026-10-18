//! Endpoint/config shim for the openbinary SDK client.
//!
//! The HTTP client, hashing, upload, and job-polling all live in the shared
//! `openbinary-agent-core` SDK. macwarden only owns endpoint resolution: it
//! reads `~/.macwarden/config.toml` `[openbinary] endpoint`, falling back to
//! the built-in default, and hands that base URL to [`OpenBinaryClient`]. The
//! SDK's own default endpoint is never consulted.

use std::fs;

use openbinary_agent_core::OpenBinaryClient;

/// Default public API endpoint. Overrides the SDK's own default so macwarden
/// users always target this host unless they opt into a config override.
pub const DEFAULT_ENDPOINT: &str = "https://api.openbinary.ai/api/v1";

/// Config file: `~/.macwarden/config.toml`.
const CONFIG_PATH: &str = "~/.macwarden/config.toml";

/// Read the openbinary API endpoint from `~/.macwarden/config.toml`.
///
/// Looks for `[openbinary] endpoint = "..."`. Falls back to the built-in
/// default if the file or key is missing.
pub fn endpoint() -> String {
    let resolved = resolve_path(CONFIG_PATH);
    if let Ok(contents) = fs::read_to_string(resolved)
        && let Ok(table) = contents.parse::<toml::Table>()
        && let Some(section) = table.get("openbinary").and_then(|v| v.as_table())
        && let Some(ep) = section.get("endpoint").and_then(|v| v.as_str())
    {
        return ep.trim_end_matches('/').to_owned();
    }
    DEFAULT_ENDPOINT.to_owned()
}

/// Build an [`OpenBinaryClient`] targeting macwarden's resolved endpoint.
///
/// Always constructed from [`endpoint`] so the SDK's own default endpoint
/// never takes over.
pub fn client() -> OpenBinaryClient {
    OpenBinaryClient::new(endpoint())
}

/// Resolve a path, expanding a leading `~/`.
fn resolve_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("~/")
        && let Ok(home) = std::env::var("HOME")
    {
        return format!("{home}/{rest}");
    }
    path.to_owned()
}
