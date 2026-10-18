use super::{OB_BINARY_URL, link_glyph};

#[test]
fn test_link_glyph_present_with_hash_absent_without() {
    // Every state that has a SHA gets the ↗ link cue; a state with no hash
    // (pre-hash "Checking…") gets none.
    assert_eq!(link_glyph(Some("deadbeef")), Some("\u{2197}"));
    assert_eq!(link_glyph(None), None);
}

#[test]
fn test_ob_binary_url_is_the_public_page() {
    let url = format!("{OB_BINARY_URL}{}", "abc123");
    assert_eq!(url, "https://www.openbinary.ai/binary/abc123");
}
