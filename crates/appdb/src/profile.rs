//! App profile types — identity, metadata, and connection context.
//!
//! An [`AppProfile`] describes a macOS application: who made it, what
//! category it belongs to, and (optionally) what network connections it
//! makes and what breaks when those connections are denied.
//!
//! Profiles are loaded from per-app TOML files in `knowledge/apps/`.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// AppCategory
// ---------------------------------------------------------------------------

/// Application category for bulk rules.
///
/// Used by both network firewall profiles (expand `{ category = "browser" }`
/// into individual code-ID rules) and execution gating (group decisions
/// by app type).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppCategory {
    /// Web browsers (Safari, Chrome, Firefox, Arc).
    Browser,
    /// Email, messaging, video calls (Mail, Slack, Zoom).
    Communication,
    /// Task managers, note-taking, docs (Things, Notion).
    Productivity,
    /// Music, video, streaming (Music, Spotify, IINA).
    Media,
    /// Graphics and UI tools (Figma, Sketch).
    Design,
    /// IDEs, terminals, build tools (Xcode, VS Code).
    Development,
    /// Cloud storage and sync (iCloud, Dropbox).
    Cloud,
    /// OS-level utilities (Finder, System Settings).
    System,
    /// Password managers, encryption (1Password).
    Security,
    /// Games and game platforms (Steam).
    Gaming,
    /// General-purpose utilities (Alfred, Raycast).
    Utility,
}

impl fmt::Display for AppCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Browser => "browser",
            Self::Communication => "communication",
            Self::Productivity => "productivity",
            Self::Media => "media",
            Self::Design => "design",
            Self::Development => "development",
            Self::Cloud => "cloud",
            Self::System => "system",
            Self::Security => "security",
            Self::Gaming => "gaming",
            Self::Utility => "utility",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// BreakageRisk
// ---------------------------------------------------------------------------

/// How badly an app degrades if a specific connection is denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BreakageRisk {
    /// No user-visible impact.
    None,
    /// Some features stop working but the app is usable.
    Degraded,
    /// The app cannot function at all.
    Critical,
}

impl fmt::Display for BreakageRisk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "none",
            Self::Degraded => "degraded",
            Self::Critical => "critical",
        };
        f.write_str(s)
    }
}

// ---------------------------------------------------------------------------
// ConnectionContext
// ---------------------------------------------------------------------------

/// Why an app connects to a specific domain, and what breaks if denied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionContext {
    /// Domain the app connects to (e.g. `"mindnode.com"`).
    pub host: String,
    /// Why the app connects here (e.g. `"Account sync and update checks"`).
    pub purpose: String,
    /// What breaks if this connection is denied.
    #[serde(default)]
    pub if_denied: Option<String>,
    /// Severity of breakage when denied.
    #[serde(default)]
    pub risk: Option<BreakageRisk>,
}

// ---------------------------------------------------------------------------
// AppProfile
// ---------------------------------------------------------------------------

/// Identity and metadata for a macOS application.
///
/// Loaded from per-app TOML files in `knowledge/apps/`. Serves both execution
/// gating (should this app be allowed to run?) and network gating (what
/// domains does it connect to and why?).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppProfile {
    /// Code signing identity (e.g. `"com.apple.Safari"`).
    pub code_id: String,
    /// Human-readable app name.
    pub name: String,
    /// Publisher / developer name.
    #[serde(default)]
    pub developer: Option<String>,
    /// Functional category.
    #[serde(default)]
    pub category: Option<AppCategory>,
    /// One-sentence description of what the app does.
    #[serde(default)]
    pub description: Option<String>,
    /// Network connections the app is known to make.
    #[serde(default)]
    pub connections: Vec<ConnectionContext>,
}
