use super::*;

#[test]
fn test_parse_launchctl_output_normal() {
    let output = "PID\tStatus\tLabel\n123\t0\tcom.apple.example\n";
    let entries = parse_launchctl_output(output);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].label, "com.apple.example");
    assert_eq!(entries[0].pid, Some(123));
    assert_eq!(entries[0].last_exit_status, Some(0));
}

#[test]
fn test_parse_launchctl_output_dash_pid() {
    let output = "PID\tStatus\tLabel\n-\t0\tcom.apple.stopped\n";
    let entries = parse_launchctl_output(output);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].label, "com.apple.stopped");
    assert_eq!(entries[0].pid, None);
    assert_eq!(entries[0].last_exit_status, Some(0));
}

#[test]
fn test_parse_launchctl_output_header_skipped() {
    let output = "PID\tStatus\tLabel\n";
    let entries = parse_launchctl_output(output);

    assert!(entries.is_empty());
}

#[test]
fn test_parse_launchctl_output_empty() {
    let entries = parse_launchctl_output("");
    assert!(entries.is_empty());
}

#[test]
fn test_parse_launchctl_output_multiple_entries() {
    let output = "\
PID\tStatus\tLabel
123\t0\tcom.apple.running
-\t78\tcom.apple.stopped
456\t0\tcom.apple.another
";
    let entries = parse_launchctl_output(output);

    assert_eq!(entries.len(), 3);

    assert_eq!(entries[0].label, "com.apple.running");
    assert_eq!(entries[0].pid, Some(123));

    assert_eq!(entries[1].label, "com.apple.stopped");
    assert_eq!(entries[1].pid, None);
    assert_eq!(entries[1].last_exit_status, Some(78));

    assert_eq!(entries[2].label, "com.apple.another");
    assert_eq!(entries[2].pid, Some(456));
}

#[test]
fn test_parse_launchctl_output_malformed_line() {
    // Lines without enough tabs are skipped
    let output = "PID\tStatus\tLabel\nbadline\n123\t0\tcom.apple.ok\n";
    let entries = parse_launchctl_output(output);

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].label, "com.apple.ok");
}

#[test]
fn test_parse_sip_output_enabled() {
    let output = "System Integrity Protection status: enabled.";
    assert_eq!(parse_sip_output(output), SipState::Enabled);
}

#[test]
fn test_parse_sip_output_disabled() {
    let output = "System Integrity Protection status: disabled.";
    assert_eq!(parse_sip_output(output), SipState::Disabled);
}

#[test]
fn test_parse_sip_output_unknown() {
    let output = "something unexpected";
    assert_eq!(parse_sip_output(output), SipState::Unknown);
}

// ---------------------------------------------------------------------------
// parse_launchctl_print tests
// ---------------------------------------------------------------------------

const FIXTURE_RUNNING: &str = r#"gui/501/com.apple.assistant_cdmd = {
	active count = 5
	path = /System/Library/LaunchAgents/com.apple.assistant_cdmd.plist
	type = LaunchAgent
	state = running
	program = /System/Library/PrivateFrameworks/ContinuousDialogManagerService.framework/assistant_cdmd
	arguments = {
		/System/Library/PrivateFrameworks/ContinuousDialogManagerService.framework/assistant_cdmd
	}
	default environment = {
		PATH => /usr/bin:/bin:/usr/sbin:/sbin
	}
	domain = gui/501 [100023]
	minimum runtime = 10
	exit timeout = 5
	runs = 3
	pid = 88370
	forks = 0
	execs = 1
	endpoints = {
		"com.apple.assistant_cdmd" = {
			port = 0xd1c0b
			active = 0
			managed = 1
			reset = 0
			hide = 0
		}
	}
}"#;

#[test]
fn test_parse_launchctl_print_running_service() {
    let detail = parse_launchctl_print(FIXTURE_RUNNING);

    assert_eq!(detail.state, "running");
    assert_eq!(detail.pid, Some(88370));
    assert_eq!(
        detail.program.as_deref(),
        Some(
            "/System/Library/PrivateFrameworks/ContinuousDialogManagerService.framework/assistant_cdmd"
        )
    );
    assert_eq!(detail.exit_timeout, Some(5));
    assert_eq!(detail.runs, Some(3));
    assert_eq!(detail.arguments.len(), 1);
    assert!(detail.arguments[0].contains("assistant_cdmd"));
    assert_eq!(detail.mach_services.len(), 1);
    assert_eq!(detail.mach_services[0], "com.apple.assistant_cdmd");
}

const FIXTURE_STOPPED: &str = r#"gui/501/com.apple.example = {
	state = waiting
	program = /usr/bin/example
	exit timeout = 30
}"#;

#[test]
fn test_parse_launchctl_print_stopped_service() {
    let detail = parse_launchctl_print(FIXTURE_STOPPED);

    assert_eq!(detail.state, "waiting");
    assert_eq!(detail.pid, None);
    assert_eq!(detail.program.as_deref(), Some("/usr/bin/example"));
    assert_eq!(detail.exit_timeout, Some(30));
    assert!(detail.arguments.is_empty());
    assert!(detail.mach_services.is_empty());
}

#[test]
fn test_parse_launchctl_print_empty() {
    let detail = parse_launchctl_print("");

    assert_eq!(detail.state, "");
    assert_eq!(detail.pid, None);
    assert!(detail.program.is_none());
    assert!(detail.arguments.is_empty());
    assert!(detail.mach_services.is_empty());
}

#[test]
fn test_parse_launchctl_print_multiple_endpoints() {
    let output = r#"gui/501/com.apple.multi = {
	state = running
	pid = 100
	endpoints = {
		"com.apple.service_a" = {
			port = 0x1
		}
		"com.apple.service_b" = {
			port = 0x2
		}
	}
}"#;
    let detail = parse_launchctl_print(output);

    assert_eq!(detail.mach_services.len(), 2);
    assert!(
        detail
            .mach_services
            .contains(&"com.apple.service_a".to_owned())
    );
    assert!(
        detail
            .mach_services
            .contains(&"com.apple.service_b".to_owned())
    );
}
