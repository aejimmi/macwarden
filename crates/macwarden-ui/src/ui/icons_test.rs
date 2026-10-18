use super::*;

#[test]
fn test_resolve_app_bundle_upgrades_nested_executable() {
    let exe = Path::new("/Applications/Spotify.app/Contents/MacOS/Spotify");
    assert_eq!(
        resolve_app_bundle(exe),
        Some(PathBuf::from("/Applications/Spotify.app"))
    );
}

#[test]
fn test_resolve_app_bundle_deeply_nested_helper_to_outer_app() {
    let exe = "/Applications/Safari.app/Contents/XPCServices/\
               com.apple.WebKit.Networking.xpc/Contents/MacOS/Networking";
    assert_eq!(
        resolve_app_bundle(Path::new(exe)),
        Some(PathBuf::from("/Applications/Safari.app"))
    );
}

#[test]
fn test_resolve_app_bundle_already_app_root_is_none() {
    // A path that is already the `.app` root has no `.app/` marker, so the
    // loader falls through to using the path verbatim (idempotent).
    assert_eq!(
        resolve_app_bundle(Path::new("/Applications/Spotify.app")),
        None
    );
}

#[test]
fn test_resolve_app_bundle_bare_daemon_is_none() {
    assert_eq!(resolve_app_bundle(Path::new("/usr/libexec/trustd")), None);
}

#[test]
fn test_resolve_app_bundle_ignores_app_substring_in_filename() {
    // `.appimage` embeds `.app` but not `.app/`, so it must not match.
    assert_eq!(
        resolve_app_bundle(Path::new("/opt/tools/foo.appimage")),
        None
    );
}
