use super::*;

// The pure encode/decode halves of the `~/.macwarden/ui-prefs.json` layer,
// exercised without touching `$HOME`.

#[test]
fn test_encode_decode_round_trips_every_rate() {
    for rate in RefreshRate::all() {
        assert_eq!(decode(&encode(rate)), rate, "round trip for {rate:?}");
    }
}

#[test]
fn test_decode_unknown_key_falls_back_to_default() {
    assert_eq!(
        decode(r#"{"refresh_rate":"turbo"}"#),
        RefreshRate::default()
    );
}

#[test]
fn test_decode_missing_key_falls_back_to_default() {
    assert_eq!(decode("{}"), RefreshRate::default());
}

#[test]
fn test_decode_corrupt_body_falls_back_to_default() {
    assert_eq!(decode("not json at all"), RefreshRate::default());
}

#[test]
fn test_encoded_body_uses_the_stable_key() {
    // Persistence stores the stable key, not the enum's discriminant, so the
    // file survives reordering the variants.
    assert!(encode(RefreshRate::Relaxed).contains("relaxed"));
}
