#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use super::*;

#[test]
fn test_bare_seconds() {
    assert_eq!(parse_duration("30"), Some(30));
    assert_eq!(parse_duration("0"), Some(0));
}

#[test]
fn test_unit_suffixes() {
    assert_eq!(parse_duration("45s"), Some(45));
    assert_eq!(parse_duration("10m"), Some(600));
    assert_eq!(parse_duration("1h"), Some(3_600));
    assert_eq!(parse_duration("2d"), Some(172_800));
    assert_eq!(parse_duration("1w"), Some(604_800));
}

#[test]
fn test_uppercase_units() {
    assert_eq!(parse_duration("1H"), Some(3_600));
    assert_eq!(parse_duration("2D"), Some(172_800));
}

#[test]
fn test_whitespace_trimmed() {
    assert_eq!(parse_duration("  1h  "), Some(3_600));
}

#[test]
fn test_rejects_malformed() {
    assert_eq!(parse_duration(""), None);
    assert_eq!(parse_duration("   "), None);
    assert_eq!(parse_duration("abc"), None);
    assert_eq!(parse_duration("1x"), None);
    assert_eq!(parse_duration("-5"), None);
    assert_eq!(parse_duration("1.5h"), None);
    assert_eq!(parse_duration("h"), None);
    assert_eq!(parse_duration("m"), None);
}

#[test]
fn test_overflow_is_none() {
    assert_eq!(parse_duration("99999999999999999999w"), None);
}
