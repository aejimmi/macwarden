use super::*;

// ---------------------------------------------------------------------------
// TCC output parsing
// ---------------------------------------------------------------------------

#[test]
fn test_parse_tcc_output_camera_and_mic() {
    let output = "\
kTCCServiceCamera|com.apple.Safari|2
kTCCServiceCamera|us.zoom.xos|2
kTCCServiceMicrophone|com.apple.Siri|2
kTCCServiceMicrophone|us.zoom.xos|0
";

    let entries = parse_tcc_output(output);
    assert_eq!(entries.len(), 4);
    assert_eq!(entries[0].service, "kTCCServiceCamera");
    assert_eq!(entries[0].client, "com.apple.Safari");
    assert_eq!(entries[0].auth_value, 2);
    assert_eq!(entries[3].service, "kTCCServiceMicrophone");
    assert_eq!(entries[3].client, "us.zoom.xos");
    assert_eq!(entries[3].auth_value, 0);
}

#[test]
fn test_parse_tcc_output_empty() {
    let entries = parse_tcc_output("");
    assert!(entries.is_empty());
}

#[test]
fn test_parse_tcc_output_malformed_lines_skipped() {
    let output = "\
kTCCServiceCamera|com.apple.Safari|2
bad_line_no_pipe
|empty_service|2
kTCCServiceMicrophone|com.apple.Siri|2
";

    let entries = parse_tcc_output(output);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].client, "com.apple.Safari");
    assert_eq!(entries[1].client, "com.apple.Siri");
}

#[test]
fn test_parse_tcc_output_path_client() {
    let output = "kTCCServiceMicrophone|/usr/libexec/siriactionsd|2\n";
    let entries = parse_tcc_output(output);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].client, "/usr/libexec/siriactionsd");
    assert_eq!(entries[0].auth_value, 2);
}

#[test]
fn test_parse_tcc_output_denied_entry() {
    let output = "kTCCServiceCamera|com.google.Chrome|0\n";
    let entries = parse_tcc_output(output);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].auth_value, 0);
}

#[test]
fn test_parse_tcc_output_invalid_auth_value() {
    let output = "kTCCServiceCamera|com.example.App|notanumber\n";
    let entries = parse_tcc_output(output);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].auth_value, -1);
}

// ---------------------------------------------------------------------------
// ps output parsing
// ---------------------------------------------------------------------------

#[test]
fn test_parse_ps_output_basic() {
    let output = "\
  123 /usr/sbin/coreaudiod
  456 /Applications/Safari.app/Contents/MacOS/Safari
 7890 /usr/libexec/siriactionsd
";

    let procs = parse_ps_output(output);
    assert_eq!(procs.len(), 3);
    assert_eq!(procs[0].pid, 123);
    assert_eq!(procs[0].command, "/usr/sbin/coreaudiod");
    assert_eq!(procs[1].pid, 456);
    assert!(procs[1].command.contains("Safari"));
}

#[test]
fn test_parse_ps_output_empty() {
    let procs = parse_ps_output("");
    assert!(procs.is_empty());
}

// ---------------------------------------------------------------------------
// Process resolution
// ---------------------------------------------------------------------------

#[test]
fn test_resolve_exact_label_match() {
    let mut pid_to_label = HashMap::new();
    pid_to_label.insert(100, "com.apple.coreaudiod".to_owned());

    let procs = vec![];
    let groups: Vec<ServiceGroup> = vec![];

    let (running, pid, _group) =
        resolve_process("com.apple.coreaudiod", &pid_to_label, &procs, &groups);

    assert!(running);
    assert_eq!(pid, Some(100));
}

#[test]
fn test_resolve_application_label() {
    let mut pid_to_label = HashMap::new();
    pid_to_label.insert(200, "application.us.zoom.xos.12345.67890".to_owned());

    let procs = vec![];
    let groups: Vec<ServiceGroup> = vec![];

    let (running, pid, _group) = resolve_process("us.zoom.xos", &pid_to_label, &procs, &groups);

    assert!(running);
    assert_eq!(pid, Some(200));
}

#[test]
fn test_resolve_by_basename() {
    let pid_to_label: HashMap<u32, String> = HashMap::new();

    let procs = vec![RunningProc {
        pid: 300,
        command: "/Applications/Safari.app/Contents/MacOS/Safari".to_owned(),
    }];
    let groups: Vec<ServiceGroup> = vec![];

    let (running, pid, _group) =
        resolve_process("com.apple.Safari", &pid_to_label, &procs, &groups);

    assert!(running);
    assert_eq!(pid, Some(300));
}

#[test]
fn test_resolve_not_running() {
    let pid_to_label: HashMap<u32, String> = HashMap::new();
    let procs: Vec<RunningProc> = vec![];
    let groups: Vec<ServiceGroup> = vec![];

    let (running, pid, group) =
        resolve_process("com.nonexistent.App", &pid_to_label, &procs, &groups);

    assert!(!running);
    assert!(pid.is_none());
    assert!(group.is_none());
}

// ---------------------------------------------------------------------------
// Display
// ---------------------------------------------------------------------------

#[test]
fn test_device_display() {
    assert_eq!(Device::Camera.to_string(), "camera");
    assert_eq!(Device::Microphone.to_string(), "mic");
}

#[test]
fn test_tcc_status_display() {
    assert_eq!(TccStatus::Allowed.to_string(), "allowed");
    assert_eq!(TccStatus::Denied.to_string(), "denied");
    assert_eq!(TccStatus::Limited.to_string(), "limited");
}

// ---------------------------------------------------------------------------
// Truncate
// ---------------------------------------------------------------------------

#[test]
fn test_truncate_short_string() {
    assert_eq!(truncate("hello", 10), "hello");
}

#[test]
fn test_truncate_long_string() {
    let result = truncate("com.apple.very.long.bundle.identifier.here", 20);
    assert_eq!(result.chars().count(), 20);
    assert!(result.ends_with('\u{2026}'));
}
