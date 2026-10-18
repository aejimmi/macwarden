use super::{enforcement_hint, row_dot_tone};
use crate::data::openbinary::ObTone;

#[test]
fn test_enforcement_hint_live_copy_when_enforcing() {
    // Capability present → live copy, never the "preview only" wording, whether or
    // not the source is otherwise "live".
    let copy = enforcement_hint(true, true);
    assert!(copy.contains("Enforcing live"));
    assert!(!copy.contains("preview only"));
    assert!(!enforcement_hint(true, false).contains("preview only"));
}

#[test]
fn test_enforcement_hint_preview_copy_only_when_not_enforcing() {
    // A live daemon without the enforcement capability keeps the preview hint.
    let copy = enforcement_hint(false, true);
    assert!(copy.contains("preview only"));

    // Demo (not live, not enforcing) gets the neutral "requires daemon" copy and
    // still never claims enforcement.
    let demo = enforcement_hint(false, false);
    assert!(!demo.contains("preview only"));
    assert!(!demo.contains("Enforcing live"));

    // Invariant: "preview only" is reachable only on a not-enforcing branch.
    for live in [true, false] {
        assert!(!enforcement_hint(true, live).contains("preview only"));
    }
}

#[test]
fn test_row_dot_tone_flags_malicious_and_suspicious() {
    // Rows show a dot only for malicious/suspicious — and only a dot, never a
    // text chip (the chip widget no longer exists).
    assert_eq!(row_dot_tone(ObTone::Bad), Some(ObTone::Bad));
    assert_eq!(row_dot_tone(ObTone::Warn), Some(ObTone::Warn));
}

#[test]
fn test_row_dot_tone_ignores_good_and_neutral() {
    assert_eq!(row_dot_tone(ObTone::Good), None);
    assert_eq!(row_dot_tone(ObTone::Neutral), None);
}
