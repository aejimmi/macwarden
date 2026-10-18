//! Boundary input validators (R9), all pure functions.
//!
//! Every request is a fixed typed enum, so there is no free-form command surface.
//! These validators harden the string fields that become filesystem slugs or
//! rule keys before the daemon acts: strict allow-lists reject injection and
//! path traversal, and the rules-dir guard asserts a derived path cannot escape
//! `~/.macwarden/net-rules/`.

use std::path::{Path, PathBuf};

/// A boundary-validation failure. Maps to
/// [`crate::protocol::ErrorKind::BadRequest`] on the wire.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// A hostname exceeded 253 characters total.
    #[error("hostname exceeds 253 characters")]
    HostnameTooLong,
    /// A hostname was empty.
    #[error("hostname is empty")]
    HostnameEmpty,
    /// A hostname label was empty, over 63 chars, or `-`-bounded.
    #[error("invalid hostname label")]
    HostnameLabel,
    /// A hostname contained a byte outside `[A-Za-z0-9.-]`.
    #[error("hostname contains an invalid character")]
    HostnameChar,
    /// A code id was empty or over the length bound.
    #[error("code id length out of bounds")]
    CodeIdLength,
    /// A code id contained a byte outside `[A-Za-z0-9._-]`.
    #[error("code id contains an invalid character")]
    CodeIdChar,
    /// A team id was not exactly 10 chars of `[A-Z0-9]`.
    #[error("team id must be 10 characters of [A-Z0-9]")]
    TeamId,
    /// An `Until` expiry was not strictly in the future.
    #[error("expiry is not in the future")]
    ExpiryPast,
    /// An `Until` expiry exceeded the bounded horizon.
    #[error("expiry exceeds the allowed horizon")]
    ExpiryTooFar,
    /// A derived rule path would escape the rules directory.
    #[error("path escapes the rules directory")]
    PathEscape,
    /// An allow-list entry set none of `app`/`team_id`/`host`/`ip`.
    #[error("allow-list entry must set at least one of app/team_id/host/ip")]
    AllowEntryEmpty,
    /// An allow-list entry set both `app` and `team_id`.
    #[error("allow-list entry cannot set both app and team_id")]
    AllowEntryConflict,
    /// An IP/CIDR field could not be parsed.
    #[error("invalid IP or CIDR")]
    InvalidIp,
    /// A group name did not match any built-in group.
    #[error("unknown network group")]
    UnknownGroup,
    /// A `SetRules` batch had no entries.
    #[error("rule batch is empty")]
    RuleBatchEmpty,
    /// A `SetRules` batch exceeded [`MAX_RULE_BATCH`] entries.
    #[error("rule batch exceeds the maximum of {MAX_RULE_BATCH} entries")]
    RuleBatchTooLarge,
}

/// Maximum code-id length (generous bound on reverse-DNS/bundle ids).
pub const MAX_CODE_ID_LEN: usize = 256;

/// Maximum entries in one [`crate::protocol::Request::SetRules`] batch (R9). Well
/// above any real group size, bounding the work one mutation can trigger.
pub const MAX_RULE_BATCH: usize = 128;

/// Validate a [`crate::protocol::Request::SetRules`] batch length (R9): non-empty
/// and at most [`MAX_RULE_BATCH`]. Per-entry field validation is applied
/// separately by the daemon as it processes each change.
pub fn validate_rule_batch_len(len: usize) -> Result<(), ValidationError> {
    if len == 0 {
        return Err(ValidationError::RuleBatchEmpty);
    }
    if len > MAX_RULE_BATCH {
        return Err(ValidationError::RuleBatchTooLarge);
    }
    Ok(())
}

/// Validate a hostname (R9): total length ≤ 253, ASCII only, each label 1–63
/// chars of `[A-Za-z0-9-]` with no leading or trailing `-`.
///
/// Accepts `googlevideo.com`; rejects `../etc`, `a b`, an over-length name, and
/// a label with a leading `-`.
pub fn validate_hostname(host: &str) -> Result<(), ValidationError> {
    if host.is_empty() {
        return Err(ValidationError::HostnameEmpty);
    }
    if host.len() > 253 {
        return Err(ValidationError::HostnameTooLong);
    }
    if !host.is_ascii() {
        return Err(ValidationError::HostnameChar);
    }
    for label in host.split('.') {
        validate_label(label)?;
    }
    Ok(())
}

/// Validate one hostname label: 1–63 chars of `[A-Za-z0-9-]`, not `-`-bounded.
fn validate_label(label: &str) -> Result<(), ValidationError> {
    if label.is_empty() || label.len() > 63 {
        return Err(ValidationError::HostnameLabel);
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(ValidationError::HostnameLabel);
    }
    for byte in label.bytes() {
        if !(byte.is_ascii_alphanumeric() || byte == b'-') {
            return Err(ValidationError::HostnameChar);
        }
    }
    Ok(())
}

/// Validate a code id (R9): reverse-DNS/bundle form — 1..=[`MAX_CODE_ID_LEN`]
/// chars of `[A-Za-z0-9._-]`. Rejects shell metacharacters and over-length input.
pub fn validate_code_id(code_id: &str) -> Result<(), ValidationError> {
    if code_id.is_empty() || code_id.len() > MAX_CODE_ID_LEN {
        return Err(ValidationError::CodeIdLength);
    }
    for byte in code_id.bytes() {
        let ok = byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-');
        if !ok {
            return Err(ValidationError::CodeIdChar);
        }
    }
    Ok(())
}

/// Validate an allow-list `app` selector: a path (leading `/`) or a code id.
///
/// A path is length-bounded and rejected for NUL/newline; a non-path is
/// validated as a code id via [`validate_code_id`].
pub fn validate_app(app: &str) -> Result<(), ValidationError> {
    if app.starts_with('/') {
        if app.len() > MAX_CODE_ID_LEN {
            return Err(ValidationError::CodeIdLength);
        }
        if app.bytes().any(|b| b == 0 || b == b'\n' || b == b'\r') {
            return Err(ValidationError::CodeIdChar);
        }
        return Ok(());
    }
    validate_code_id(app)
}

/// Validate a [`crate::protocol::Request::StartTrace`] `app_id` (R8/R9). An
/// `app_id` is a code id or an executable path, exactly like an allow-list `app`
/// selector, so this delegates to [`validate_app`]: a leading-`/` path is
/// length-bounded and rejected for NUL/newline, anything else is validated as a
/// code id. Rejects shell metacharacters and path traversal before the daemon
/// scopes a capture to the app.
pub fn validate_app_id(app_id: &str) -> Result<(), ValidationError> {
    validate_app(app_id)
}

/// Validate a signing team id (R9): exactly 10 chars of `[A-Z0-9]`.
pub fn validate_team_id(team_id: &str) -> Result<(), ValidationError> {
    if team_id.len() != 10 {
        return Err(ValidationError::TeamId);
    }
    for byte in team_id.bytes() {
        if !(byte.is_ascii_uppercase() || byte.is_ascii_digit()) {
            return Err(ValidationError::TeamId);
        }
    }
    Ok(())
}

/// Validate an `Until` expiry (R9): strictly after `now_ms` and within
/// `horizon_ms` of it. All times are unix milliseconds.
pub fn validate_expiry(
    expiry_ms: u64,
    now_ms: u64,
    horizon_ms: u64,
) -> Result<(), ValidationError> {
    if expiry_ms <= now_ms {
        return Err(ValidationError::ExpiryPast);
    }
    if expiry_ms.saturating_sub(now_ms) > horizon_ms {
        return Err(ValidationError::ExpiryTooFar);
    }
    Ok(())
}

/// Derive the safe rule-file slug for a validated hostname (R9). Because the
/// host is validated to `[A-Za-z0-9.-]`, it has no path separators and cannot
/// traverse — the slug is the host itself.
pub fn rule_slug(host: &str) -> Result<String, ValidationError> {
    validate_hostname(host)?;
    Ok(host.to_string())
}

/// Assert a rule path derived from `slug` stays within `rules_dir` (R9). Rejects
/// any slug containing a path separator or `..`, then asserts the joined path is
/// lexically within `rules_dir`. Pure — no filesystem access, so it is safe to
/// run before the target file exists (canonicalization at write time is the
/// daemon's second line of defense).
pub fn rules_path_within(rules_dir: &Path, slug: &str) -> Result<PathBuf, ValidationError> {
    if slug.is_empty()
        || slug.contains('/')
        || slug.contains('\\')
        || slug.split(['/', '\\']).any(|c| c == "..")
        || slug == ".."
    {
        return Err(ValidationError::PathEscape);
    }
    let candidate = rules_dir.join(slug);
    if !candidate.starts_with(rules_dir) {
        return Err(ValidationError::PathEscape);
    }
    Ok(candidate)
}

#[cfg(test)]
#[path = "validate_test.rs"]
mod validate_test;
