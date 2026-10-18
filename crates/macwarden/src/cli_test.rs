use super::*;

#[test]
fn test_default_log_directive_interactive_commands_are_quiet() {
    // Human-output commands default to error so warnings don't leak into output.
    assert_eq!(
        default_log_directive(Some(&Commands::Status {
            format: OutputFormat::Table,
        })),
        "error",
    );
    assert_eq!(
        default_log_directive(Some(&Commands::Net {
            command: NetCommand::Scan {
                process: None,
                denied: false,
                trackers: false,
                json: false,
            },
        })),
        "error",
    );
}

#[test]
fn test_default_log_directive_no_command_is_quiet() {
    // No subcommand launches the panel — no stderr noise on the terminal.
    assert_eq!(default_log_directive(None), "error");
}

#[test]
fn test_default_log_directive_daemon_commands_keep_warnings() {
    assert_eq!(default_log_directive(Some(&Commands::Serve)), "warn");
    assert_eq!(
        default_log_directive(Some(&Commands::Watch {
            profile: None,
            install: false,
            uninstall: false,
        })),
        "warn",
    );
}

#[test]
fn test_default_log_directive_streaming_net_commands_keep_warnings() {
    assert_eq!(
        default_log_directive(Some(&Commands::Net {
            command: NetCommand::Log,
        })),
        "warn",
    );
    assert_eq!(
        default_log_directive(Some(&Commands::Net {
            command: NetCommand::Learn {
                duration: None,
                apply: false,
                json: false,
            },
        })),
        "warn",
    );
}
