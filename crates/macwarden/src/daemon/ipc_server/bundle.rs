//! Executable-path → `.app` bundle-root resolution for panel icons, plus the
//! matching display-name derivation ([`app_display_name`], [`strip_hash_suffix`])
//! so a snapshot row and its inspector header read the friendly application name
//! rather than the raw executable leaf.
//!
//! The panel renders a real Finder icon via `NSWorkspace iconForFile` on the
//! `bundle_path` a snapshot row carries. A bare Unix daemon (`apsd`, `trustd`,
//! `cargo`) has no `.app`, so macOS shows the honest generic executable icon —
//! and that is what we keep for it. The upgrade this module provides is for
//! processes that *belong* to a real `.app` bundle: their executable lives deep
//! inside the bundle (a WebKit XPC service, a browser "Helper" under
//! `Contents/Frameworks`), so pointing the panel at the raw exe would show a
//! generic icon. Resolving to the outermost `.app` root makes the panel render
//! the real application icon instead.

/// Resolve an executable path to the root of its enclosing `.app` bundle.
///
/// Returns the path truncated at the **outermost** (topmost) path component
/// ending in `.app`, so a helper nested inside an app bundle maps to the top
/// application rather than a nested helper bundle:
///
/// - `/Applications/Safari.app/Contents/XPCServices/…/foo` → `/Applications/Safari.app`
/// - `/Applications/Google Chrome.app/Contents/Frameworks/…/Google Chrome Helper`
///   → `/Applications/Google Chrome.app`
///
/// Returns `None` when no path *component* ends in `.app` — a bare daemon or CLI
/// tool — so the caller can fall back to the exe path and the panel keeps the
/// honest generic executable icon. A trailing `.app` that is only the final
/// filename (with nothing nested under it) does not count as a bundle, since a
/// real bundle always encloses its executable.
#[must_use]
pub fn resolve_bundle_path(exe_path: &str) -> Option<String> {
    // A `.app` bundle always has content nested under it, so the marker is a
    // component ending in `.app` immediately followed by `/`. `find` yields the
    // leftmost — hence outermost — such component, so nested helper bundles map
    // to the top-level app. `.app/` cannot match mid-component (`foo.appimage/`
    // contains `.appi`, not `.app/`), so a filename that merely embeds `.app`
    // never mis-triggers.
    let marker = exe_path.find(".app/")?;
    let end = marker + ".app".len();
    exe_path.get(..end).map(ToOwned::to_owned)
}

/// The panel `bundle_path` for an executable path: the enclosing `.app` root
/// when one exists, else the executable path itself.
///
/// The passthrough preserves the pre-resolution behavior for daemons and CLI
/// tools (the panel shows a generic executable icon), while a bundled app or
/// helper is upgraded to its `.app` root so the panel shows the real app icon.
#[must_use]
pub fn bundle_path(exe: Option<&str>) -> Option<String> {
    exe.map(|p| resolve_bundle_path(p).unwrap_or_else(|| p.to_owned()))
}

/// The panel display name for an executable path.
///
/// For the **primary** executable of a `.app` bundle — a path of the exact shape
/// `<…>/X.app/Contents/MacOS/<leaf>` where `<leaf>` is a single component —
/// returns the outermost enclosing `.app` name, so the panel shows the real
/// application name regardless of what the raw leaf is called:
///
/// - `/Applications/Spotify.app/Contents/MacOS/Spotify` → `Spotify`
/// - `/Applications/Raycast.app/Contents/MacOS/macos` → `Raycast`
/// - `/Applications/Outer.app/Contents/Helpers/Inner.app/Contents/MacOS/Inner`
///   → `Outer` (outermost `.app` when nested)
///
/// Every other path returns `fallback_name` unchanged — a helper nested deeper
/// in a bundle (`Contents/XPCServices`, `Contents/Frameworks`) or a bare daemon
/// with no `.app` ancestor — so distinct helpers keep their distinct names
/// (`Safari.SafeBrowsing`, `WebKit.Networking`, `apsd`, `cargo`).
#[must_use]
pub fn app_display_name(exe_path: &str, fallback_name: &str) -> String {
    if is_main_app_executable(exe_path)
        && let Some(bundle) = resolve_bundle_path(exe_path)
        && let Some(name) = app_basename(&bundle)
    {
        return name.to_owned();
    }
    fallback_name.to_owned()
}

/// Whether `exe_path` is the primary executable of a `.app` bundle: a path
/// ending in `<…>.app/Contents/MacOS/<leaf>`. Helpers under `XPCServices`,
/// `Frameworks`, or `PlugIns` fail here (their parent ends in `.xpc`/`.appex`,
/// not `.app`), as do bare daemons.
fn is_main_app_executable(exe_path: &str) -> bool {
    let Some((dir, _leaf)) = exe_path.rsplit_once('/') else {
        return false;
    };
    dir.strip_suffix("/MacOS")
        .and_then(|d| d.strip_suffix("/Contents"))
        .and_then(app_basename)
        .is_some()
}

/// The application name from a `.app` bundle path: its final component minus the
/// `.app` extension. `None` when the component is not a `.app` or the stem is
/// empty.
fn app_basename(bundle_path: &str) -> Option<&str> {
    bundle_path
        .rsplit('/')
        .next()
        .and_then(|leaf| leaf.strip_suffix(".app"))
        .filter(|stem| !stem.is_empty())
}

/// Strip a trailing ad-hoc code-signing hash that `codesign` appends to
/// disambiguate non-bundle binaries, so `cargo-9b434e75c9a9c27f` displays as
/// `cargo`. Only a long, all-hexadecimal trailing segment is treated as a hash;
/// ordinary hyphenated names (`foo-bar`, `x86-64`) are left intact. The group
/// key keeps the full code id, so two same-named binaries stay distinct rows
/// while both display cleanly.
#[must_use]
pub(crate) fn strip_hash_suffix(name: &str) -> &str {
    if let Some((head, tail)) = name.rsplit_once('-')
        && !head.is_empty()
        && tail.len() >= 12
        && tail.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return head;
    }
    name
}

#[cfg(test)]
#[path = "bundle_test.rs"]
mod bundle_test;
