use super::*;

#[test]
fn test_daemon_stale_true_when_daemon_not_live() {
    // A daemon source whose worker has lost the connection reads not-live → show
    // the "Reconnecting…" affordance instead of pretending the snapshot is fresh.
    assert!(daemon_stale("daemon", false));
}

#[test]
fn test_daemon_stale_false_when_daemon_live() {
    assert!(!daemon_stale("daemon", true));
}

#[test]
fn test_daemon_stale_false_for_non_daemon_sources() {
    // demo / nettop live are never "reconnecting" — they have no daemon worker.
    assert!(!daemon_stale("demo", false));
    assert!(!daemon_stale("live", false));
    assert!(!daemon_stale("live", true));
}
