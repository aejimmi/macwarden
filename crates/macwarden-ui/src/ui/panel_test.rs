use super::*;

// The idle-skip policy behind `Panel::tick_should_notify`. A quiet panel at the
// tab root must not repaint; live sub-views, sweeps, and real changes must.

#[test]
fn test_should_notify_skips_when_unchanged_at_tab_root() {
    // Same version as last render, nothing pinned → skip the repaint.
    assert!(!should_notify(Some(7), Some(7), false));
}

#[test]
fn test_should_notify_repaints_when_version_advances() {
    assert!(should_notify(Some(8), Some(7), false));
}

#[test]
fn test_should_notify_repaints_on_first_tick() {
    // No prior version recorded yet → first tick always repaints.
    assert!(should_notify(Some(1), None, false));
}

#[test]
fn test_should_notify_always_repaints_for_sourceless_version() {
    // A source that cannot report change (demo / `nettop` live) always repaints,
    // even when the (absent) version matches.
    assert!(should_notify(None, None, false));
}

#[test]
fn test_should_notify_pinned_forces_repaint_even_when_unchanged() {
    // A pushed inspector/trace view or an active sweep pins the repaint on even
    // for an unchanged snapshot.
    assert!(should_notify(Some(7), Some(7), true));
}

// The daemon retry re-arm policy behind `Panel::maybe_reconnect_daemon` (R8).

#[test]
fn test_no_retry_without_a_retry_factory() {
    // Demo (and any launch without a retry factory) never retries.
    assert!(!should_retry_daemon(false, false, false));
    assert!(!should_retry_daemon(false, true, false));
}

#[test]
fn test_no_retry_on_a_live_daemon() {
    // A healthy daemon source self-heals via its own worker — the panel stays out
    // of the way.
    assert!(!should_retry_daemon(true, true, true));
}

#[test]
fn test_retries_a_stale_daemon_so_it_is_re_adopted() {
    // The degradation case: still nominally on the "daemon" source, but it has
    // gone stale/fallback (not live). The panel must re-arm and re-adopt a fresh
    // daemon rather than serve a dead daemon's snapshot forever.
    assert!(should_retry_daemon(true, true, false));
}

#[test]
fn test_retries_while_on_the_fallback_source() {
    // On the read-only fallback (not the daemon), keep retrying so a daemon that
    // comes up after launch is adopted. Liveness of the fallback is irrelevant.
    assert!(should_retry_daemon(true, false, false));
    assert!(should_retry_daemon(true, false, true));
}
