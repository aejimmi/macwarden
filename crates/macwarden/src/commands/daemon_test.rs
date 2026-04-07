use super::*;

// ---------------------------------------------------------------------------
// generate_plist
// ---------------------------------------------------------------------------

#[test]
fn test_generate_plist_contains_label() {
    let plist = generate_plist("/usr/local/bin/macwarden", "/tmp/monitor.log");
    assert!(
        plist.contains("<string>com.macwarden.monitor</string>"),
        "plist must contain the agent label"
    );
}

#[test]
fn test_generate_plist_contains_exe_path() {
    let exe = "/usr/local/bin/macwarden";
    let plist = generate_plist(exe, "/tmp/monitor.log");
    assert!(
        plist.contains(&format!("<string>{exe}</string>")),
        "plist must contain the executable path"
    );
}

#[test]
fn test_generate_plist_contains_monitor_argument() {
    let plist = generate_plist("/usr/local/bin/macwarden", "/tmp/monitor.log");
    assert!(
        plist.contains("<string>monitor</string>"),
        "plist must pass 'monitor' as argument"
    );
}

#[test]
fn test_generate_plist_contains_log_path() {
    let log = "/Users/test/.macwarden/monitor.log";
    let plist = generate_plist("/usr/local/bin/macwarden", log);
    // stdout and stderr should both point to the log.
    let count = plist.matches(log).count();
    assert_eq!(count, 2, "log path should appear twice (stdout + stderr)");
}

#[test]
fn test_generate_plist_keep_alive_true() {
    let plist = generate_plist("/usr/local/bin/macwarden", "/tmp/log");
    assert!(
        plist.contains("<key>KeepAlive</key>"),
        "plist must set KeepAlive"
    );
    // KeepAlive should be true.
    let ka_pos = plist.find("<key>KeepAlive</key>").unwrap();
    let after = &plist[ka_pos..];
    assert!(after.contains("<true/>"), "KeepAlive must be true");
}

#[test]
fn test_generate_plist_run_at_load() {
    let plist = generate_plist("/usr/local/bin/macwarden", "/tmp/log");
    assert!(plist.contains("<key>RunAtLoad</key>"));
}

#[test]
fn test_generate_plist_low_priority_io() {
    let plist = generate_plist("/usr/local/bin/macwarden", "/tmp/log");
    assert!(plist.contains("<key>LowPriorityIO</key>"));
}

#[test]
fn test_generate_plist_background_process_type() {
    let plist = generate_plist("/usr/local/bin/macwarden", "/tmp/log");
    assert!(plist.contains("<string>Background</string>"));
}

#[test]
fn test_generate_plist_valid_xml_header() {
    let plist = generate_plist("/usr/local/bin/macwarden", "/tmp/log");
    assert!(plist.starts_with("<?xml version=\"1.0\""));
    assert!(plist.contains("<!DOCTYPE plist"));
}

#[test]
fn test_generate_plist_rust_log_env() {
    let plist = generate_plist("/usr/local/bin/macwarden", "/tmp/log");
    assert!(plist.contains("<key>RUST_LOG</key>"));
    assert!(plist.contains("<string>info</string>"));
}

#[test]
fn test_generate_plist_parseable_by_plist_crate() {
    let plist_xml = generate_plist("/usr/local/bin/macwarden", "/tmp/monitor.log");
    let parsed: Result<plist::Dictionary, _> = plist::from_bytes(plist_xml.as_bytes());
    assert!(
        parsed.is_ok(),
        "generated plist must be parseable: {:?}",
        parsed.err()
    );

    let dict = parsed.unwrap();
    assert_eq!(
        dict.get("Label").and_then(|v| v.as_string()),
        Some("com.macwarden.monitor")
    );
}
