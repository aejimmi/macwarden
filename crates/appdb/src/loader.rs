//! Loads built-in app profiles from embedded TOML data.
//!
//! Data files live in `knowledge/apps/` at the workspace root and are embedded
//! at compile time via `include_str!`. Contributors edit TOML, not Rust.
//!
//! To add a new app, create `knowledge/apps/<name>.toml` (see `_schema.toml`
//! for the format) and add an `include_str!` line to `APP_PROFILE_SOURCES`
//! below.

/// One entry per app file in `knowledge/apps/`.
pub(crate) const APP_PROFILE_SOURCES: &[&str] = &[
    include_str!("../../../knowledge/apps/1password.toml"),
    include_str!("../../../knowledge/apps/arc.toml"),
    include_str!("../../../knowledge/apps/chrome.toml"),
    include_str!("../../../knowledge/apps/discord.toml"),
    include_str!("../../../knowledge/apps/figma.toml"),
    include_str!("../../../knowledge/apps/finder.toml"),
    include_str!("../../../knowledge/apps/firefox.toml"),
    include_str!("../../../knowledge/apps/iina.toml"),
    include_str!("../../../knowledge/apps/mail.toml"),
    include_str!("../../../knowledge/apps/messages.toml"),
    include_str!("../../../knowledge/apps/music.toml"),
    include_str!("../../../knowledge/apps/safari.toml"),
    include_str!("../../../knowledge/apps/slack.toml"),
    include_str!("../../../knowledge/apps/spotify.toml"),
    include_str!("../../../knowledge/apps/steam.toml"),
    include_str!("../../../knowledge/apps/system-settings.toml"),
    include_str!("../../../knowledge/apps/terminal.toml"),
    include_str!("../../../knowledge/apps/vscode.toml"),
    include_str!("../../../knowledge/apps/xcode.toml"),
    include_str!("../../../knowledge/apps/zoom.toml"),
];

#[cfg(test)]
#[path = "loader_test.rs"]
mod loader_test;
