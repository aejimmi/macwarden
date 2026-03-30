//! Telemetry category classification based on event name prefixes.

use serde::Serialize;
use std::fmt;

/// Telemetry category derived from an event name prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, PartialOrd, Ord)]
pub enum Category {
    /// App usage, versions, durations, activations.
    Apps,
    /// WiFi positioning, geofencing, location visits.
    Location,
    /// WiFi scans, Bluetooth connections, signal quality.
    Network,
    /// CoreML inference, LLM usage, generative models.
    Ai,
    /// User profiling, entity relevance, personalization.
    Behavioral,
    /// Photo analysis, image recognition, camera sessions.
    Media,
    /// Messaging stats, Siri, keyboard telemetry.
    Comms,
    /// Executable measurement, keychain access.
    Security,
    /// Browsing, autofill, extensions, search, tabs.
    Safari,
    /// Power, memory, scheduling, cleanup.
    System,
    /// Uncategorized events.
    Other,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Apps => write!(f, "Apps"),
            Self::Location => write!(f, "Location"),
            Self::Network => write!(f, "Network"),
            Self::Ai => write!(f, "AI"),
            Self::Behavioral => write!(f, "Behavioral"),
            Self::Media => write!(f, "Media"),
            Self::Comms => write!(f, "Comms"),
            Self::Security => write!(f, "Security"),
            Self::Safari => write!(f, "Safari"),
            Self::System => write!(f, "System"),
            Self::Other => write!(f, "Other"),
        }
    }
}

impl std::str::FromStr for Category {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "apps" => Ok(Self::Apps),
            "location" => Ok(Self::Location),
            "network" => Ok(Self::Network),
            "ai" => Ok(Self::Ai),
            "behavioral" => Ok(Self::Behavioral),
            "media" => Ok(Self::Media),
            "comms" => Ok(Self::Comms),
            "security" => Ok(Self::Security),
            "safari" => Ok(Self::Safari),
            "system" => Ok(Self::System),
            "other" => Ok(Self::Other),
            _ => Err(format!("unknown category: {s}")),
        }
    }
}

/// Prefix rules for category assignment, checked in order.
/// Most specific prefixes come first so they match before broader ones.
const PREFIX_RULES: &[(&[&str], Category)] = &[
    (
        &["osanalytics.appUsage", "appkit.app_config"],
        Category::Apps,
    ),
    (
        &["locationd.", "CoreRoutine.", "MicroLocation."],
        Category::Location,
    ),
    (&["wifi.", "Bluetooth."], Category::Network),
    (
        &[
            "CoreML.",
            "LLMInferenceEvent",
            "intelligenceplatform.",
            "GenerativeModels.",
            "Espresso.",
        ],
        Category::Ai,
    ),
    (
        &["proactive.PersonalizationPortrait.", "parsecd."],
        Category::Behavioral,
    ),
    (
        &["photos.", "mediaanalysisd.", "VisionKit.", "camera."],
        Category::Media,
    ),
    (&["Messages.", "Siri.", "Keyboard."], Category::Comms),
    (&["syspolicy.", "security."], Category::Security),
    (&["Safari.", "SafariShared."], Category::Safari),
    (
        &["power.", "memorytools.", "dasd.", "cachedelete."],
        Category::System,
    ),
];

/// Classify an event name into a telemetry category based on prefix matching.
///
/// The event name is matched against known prefixes. Some event names include a
/// `com.apple.` prefix which is stripped before matching. If no prefix matches,
/// returns [`Category::Other`].
pub fn categorize(event_name: &str) -> Category {
    // Strip common Apple prefix for matching
    let stripped = event_name.strip_prefix("com.apple.").unwrap_or(event_name);

    for (prefixes, category) in PREFIX_RULES {
        for prefix in *prefixes {
            if stripped.starts_with(prefix) {
                return *category;
            }
        }
    }

    Category::Other
}

#[cfg(test)]
#[path = "category_test.rs"]
mod category_test;
