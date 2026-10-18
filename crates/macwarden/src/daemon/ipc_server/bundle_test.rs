use super::*;

#[test]
fn test_resolve_bundle_path_safari_helper_nested_to_app_root() {
    let exe = "/Applications/Safari.app/Contents/XPCServices/\
               com.apple.WebKit.Networking.xpc/Contents/MacOS/com.apple.WebKit.Networking";
    assert_eq!(
        resolve_bundle_path(exe).as_deref(),
        Some("/Applications/Safari.app")
    );
}

#[test]
fn test_resolve_bundle_path_chrome_helper_framework_to_app_root() {
    let exe = "/Applications/Google Chrome.app/Contents/Frameworks/\
               Google Chrome Framework.framework/Versions/Current/Helpers/\
               Google Chrome Helper.app/Contents/MacOS/Google Chrome Helper";
    assert_eq!(
        resolve_bundle_path(exe).as_deref(),
        Some("/Applications/Google Chrome.app")
    );
}

#[test]
fn test_resolve_bundle_path_bare_daemon_is_none() {
    assert_eq!(resolve_bundle_path("/usr/libexec/trustd"), None);
    assert_eq!(resolve_bundle_path("/usr/sbin/apsd"), None);
    assert_eq!(resolve_bundle_path("cargo"), None);
}

#[test]
fn test_resolve_bundle_path_dotapp_only_in_filename_does_not_trigger() {
    // A trailing `.app` with nothing nested under it is a filename, not a
    // bundle — a real bundle always encloses its executable.
    assert_eq!(resolve_bundle_path("/Users/x/backup.app"), None);
    assert_eq!(resolve_bundle_path("/tmp/report.app"), None);
}

#[test]
fn test_resolve_bundle_path_embedded_dotapp_substring_does_not_mistrigger() {
    // `.appimage` / `.application` embed `.app` but are not a `.app/` component.
    assert_eq!(resolve_bundle_path("/opt/foo.appimage/bin/run"), None);
    assert_eq!(resolve_bundle_path("/opt/x.application/bin/run"), None);
}

#[test]
fn test_resolve_bundle_path_outermost_app_when_nested() {
    // Two `.app` components nest: the outermost (topmost) one wins.
    let exe = "/Applications/Outer.app/Contents/Helpers/Inner.app/Contents/MacOS/Inner";
    assert_eq!(
        resolve_bundle_path(exe).as_deref(),
        Some("/Applications/Outer.app")
    );
}

#[test]
fn test_resolve_bundle_path_top_level_app_with_exe_inside() {
    let exe = "/Applications/Safari.app/Contents/MacOS/Safari";
    assert_eq!(
        resolve_bundle_path(exe).as_deref(),
        Some("/Applications/Safari.app")
    );
}

#[test]
fn test_bundle_path_passes_through_non_bundle_exe() {
    // Non-bundle daemon: keep the exe path so the panel shows the generic icon.
    assert_eq!(
        bundle_path(Some("/usr/libexec/trustd")).as_deref(),
        Some("/usr/libexec/trustd")
    );
}

#[test]
fn test_bundle_path_upgrades_bundled_helper_to_app_root() {
    let exe = "/Applications/Safari.app/Contents/XPCServices/x.xpc/Contents/MacOS/x";
    assert_eq!(
        bundle_path(Some(exe)).as_deref(),
        Some("/Applications/Safari.app")
    );
}

#[test]
fn test_bundle_path_none_passes_through() {
    assert_eq!(bundle_path(None), None);
}

#[test]
fn test_app_display_name_main_executable_uses_app_name() {
    assert_eq!(
        app_display_name("/Applications/Spotify.app/Contents/MacOS/Spotify", "client"),
        "Spotify"
    );
    // Raw leaf differs from the app name — the `.app` name still wins.
    assert_eq!(
        app_display_name("/Applications/Raycast.app/Contents/MacOS/macos", "macos"),
        "Raycast"
    );
    assert_eq!(
        app_display_name("/Applications/Safari.app/Contents/MacOS/Safari", "Safari"),
        "Safari"
    );
}

#[test]
fn test_app_display_name_handles_spaces_in_app_name() {
    assert_eq!(
        app_display_name(
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "Google Chrome"
        ),
        "Google Chrome"
    );
}

#[test]
fn test_app_display_name_nested_uses_outermost_app() {
    let exe = "/Applications/Outer.app/Contents/Helpers/Inner.app/Contents/MacOS/Inner";
    assert_eq!(app_display_name(exe, "Inner"), "Outer");
}

#[test]
fn test_app_display_name_helper_keeps_fallback() {
    // A WebKit XPC helper is not a `<…>.app/Contents/MacOS/<leaf>` primary
    // executable (its parent ends in `.xpc`), so the distinct name is kept.
    let exe = "/Applications/Safari.app/Contents/XPCServices/\
               com.apple.Safari.SafeBrowsing.Service.xpc/Contents/MacOS/\
               com.apple.Safari.SafeBrowsing.Service";
    assert_eq!(
        app_display_name(exe, "Safari.SafeBrowsing"),
        "Safari.SafeBrowsing"
    );
}

#[test]
fn test_app_display_name_bare_binary_keeps_fallback() {
    assert_eq!(app_display_name("/usr/sbin/apsd", "apsd"), "apsd");
    assert_eq!(app_display_name("cargo", "cargo"), "cargo");
    // A bare `.app` path (no enclosed executable) is not a primary executable.
    assert_eq!(
        app_display_name("/Applications/App.app", "fallback"),
        "fallback"
    );
}

#[test]
fn test_strip_hash_suffix_removes_adhoc_codesign_hash() {
    assert_eq!(strip_hash_suffix("cargo-9b434e75c9a9c27f"), "cargo");
    assert_eq!(
        strip_hash_suffix("macwarden_ui-30638d75c786f8fd"),
        "macwarden_ui"
    );
    assert_eq!(strip_hash_suffix("blissd-cb55aa456cf4db7e"), "blissd");
}

#[test]
fn test_strip_hash_suffix_keeps_ordinary_hyphenated_names() {
    // Short or non-hex trailing segments are real name parts, not a hash.
    assert_eq!(strip_hash_suffix("x86-64"), "x86-64");
    assert_eq!(strip_hash_suffix("foo-bar"), "foo-bar");
    assert_eq!(strip_hash_suffix("google-chrome"), "google-chrome");
    assert_eq!(strip_hash_suffix("cargo"), "cargo");
    // An empty head (a leading hash) is not stripped.
    assert_eq!(strip_hash_suffix("-deadbeefdeadbeef"), "-deadbeefdeadbeef");
}
