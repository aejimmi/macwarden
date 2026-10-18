#![allow(clippy::panic)]

use ipc::client::Selection;

use super::*;

#[test]
fn test_socket_absent_selects_fallback() {
    // A missing socket surfaces as `Unavailable`, which the panel resolves to
    // the `nettop` LiveSource fallback.
    let selection: Selection<()> = Selection::Unavailable;
    assert_eq!(selection_status(&selection), SourceSelection::Fallback);
}

#[test]
fn test_untrusted_socket_selects_fallback() {
    let selection: Selection<()> = Selection::Untrusted;
    assert_eq!(selection_status(&selection), SourceSelection::Fallback);
}

#[test]
fn test_version_mismatch_selects_incompatible() {
    let selection: Selection<()> = Selection::Incompatible {
        daemon_version: "9.9.9".to_string(),
    };
    assert_eq!(
        selection_status(&selection),
        SourceSelection::Incompatible {
            daemon_version: "9.9.9".to_string()
        }
    );
}

#[test]
fn test_labels_are_stable() {
    assert_eq!(SourceSelection::Fallback.label(), "live");
    assert_eq!(SourceSelection::Demo.label(), "demo");
    assert_eq!(
        SourceSelection::Incompatible {
            daemon_version: "x".to_string()
        }
        .label(),
        "live (daemon out of date)"
    );
    assert_eq!(
        SourceSelection::Daemon {
            daemon_version: "x".to_string()
        }
        .label(),
        "daemon"
    );
}

#[test]
fn test_is_daemon_only_true_for_daemon() {
    assert!(
        SourceSelection::Daemon {
            daemon_version: "x".to_string()
        }
        .is_daemon()
    );
    assert!(!SourceSelection::Fallback.is_daemon());
    assert!(!SourceSelection::Demo.is_daemon());
}
