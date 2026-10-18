use super::*;

use std::path::PathBuf;

#[test]
fn test_daemon_command_targets_the_given_binary() {
    let bin = PathBuf::from("/opt/macwarden/bin/macwarden");
    let cmd = daemon_command(&bin);

    assert_eq!(cmd.get_program(), bin.as_os_str());
}

#[test]
fn test_daemon_command_passes_serve_subcommand() {
    let bin = PathBuf::from("/usr/local/bin/macwarden");
    let cmd = daemon_command(&bin);

    let args: Vec<_> = cmd.get_args().collect();
    assert_eq!(args, ["serve"]);
}
