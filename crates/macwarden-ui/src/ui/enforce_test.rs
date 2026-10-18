use super::*;

// -- EnforceMode::derive ------------------------------------------------------

#[test]
fn test_derive_enforcing_when_filter_active() {
    // A live daemon advertising NetworkEnforcement — the only enforcing state.
    assert_eq!(
        EnforceMode::derive(true, true, true),
        EnforceMode::Enforcing
    );
}

#[test]
fn test_derive_preview_for_monitor_only_daemon() {
    // Today's default: policy present, filter not active. Staging is meaningful,
    // so it is Preview — never Enforcing.
    assert_eq!(EnforceMode::derive(false, true, true), EnforceMode::Preview);
}

#[test]
fn test_derive_preview_for_live_monitor_without_policy() {
    // A live nettop-style monitor with no policy backend still previews toggles.
    assert_eq!(
        EnforceMode::derive(false, true, false),
        EnforceMode::Preview
    );
}

#[test]
fn test_derive_preview_for_stale_daemon_that_kept_its_policy_backend() {
    // A daemon gone stale reads not-live and not-enforcing, but its policy
    // backend still exists → Preview (never Enforcing), so the controls degrade
    // to staging rather than claiming live blocks.
    assert_eq!(
        EnforceMode::derive(false, false, true),
        EnforceMode::Preview
    );
}

#[test]
fn test_derive_inactive_for_demo() {
    // Demo: not live, no policy backend — inert illustrative preview only.
    assert_eq!(
        EnforceMode::derive(false, false, false),
        EnforceMode::Inactive
    );
}

// -- shows_live_verdict / is_preview ------------------------------------------

#[test]
fn test_only_enforcing_shows_live_verdict() {
    assert!(EnforceMode::Enforcing.shows_live_verdict());
    assert!(!EnforceMode::Preview.shows_live_verdict());
    assert!(!EnforceMode::Inactive.shows_live_verdict());
}

#[test]
fn test_is_preview_only_for_preview() {
    assert!(EnforceMode::Preview.is_preview());
    assert!(!EnforceMode::Enforcing.is_preview());
    assert!(!EnforceMode::Inactive.is_preview());
}

// -- shown_verdict ------------------------------------------------------------

#[test]
fn test_shown_verdict_fabricates_blocked_only_when_enforcing() {
    // Blocked toggle + enforcing → the real red "Blocked" dot.
    assert_eq!(
        shown_verdict(EnforceMode::Enforcing, false, Verdict::Allow),
        Verdict::Blocked
    );
}

#[test]
fn test_shown_verdict_preview_keeps_real_verdict_for_blocked_toggle() {
    // Blocked toggle while previewing must NOT paint a fabricated block — the
    // destination is still flowing, so show its real verdict.
    assert_eq!(
        shown_verdict(EnforceMode::Preview, false, Verdict::Tracker),
        Verdict::Tracker
    );
    assert_eq!(
        shown_verdict(EnforceMode::Inactive, false, Verdict::Allow),
        Verdict::Allow
    );
}

#[test]
fn test_shown_verdict_allowed_always_shows_real_verdict() {
    for mode in [
        EnforceMode::Enforcing,
        EnforceMode::Preview,
        EnforceMode::Inactive,
    ] {
        assert_eq!(
            shown_verdict(mode, true, Verdict::Tracker),
            Verdict::Tracker
        );
    }
}

// -- mode_pill_tone -----------------------------------------------------------

#[test]
fn test_pill_block_is_red_only_when_enforcing() {
    assert_eq!(
        mode_pill_tone(EnforceMode::Enforcing, Some(WireMode::BlockAll)),
        (PillTone::Block, "Block")
    );
}

#[test]
fn test_pill_block_is_neutral_while_previewing() {
    // Staged Block-All on a monitor-only daemon: grayscale, never red — the
    // header must not claim global blocking that isn't in effect.
    assert_eq!(
        mode_pill_tone(EnforceMode::Preview, Some(WireMode::BlockAll)),
        (PillTone::Neutral, "Block")
    );
}

#[test]
fn test_pill_allow_is_accent_in_every_posture() {
    for mode in [EnforceMode::Enforcing, EnforceMode::Preview] {
        assert_eq!(
            mode_pill_tone(mode, Some(WireMode::AllowAll)),
            (PillTone::Allow, "Allow")
        );
    }
}

#[test]
fn test_pill_neutral_without_profile() {
    assert_eq!(
        mode_pill_tone(EnforceMode::Preview, None),
        (PillTone::Neutral, "Rules")
    );
}
