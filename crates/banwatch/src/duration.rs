//! Duration-string parser for the banwatch config.
//!
//! Ported from `fail2ban-rs`'s config duration handling: a bare integer is
//! seconds; a trailing `s`/`m`/`h`/`d`/`w` scales it. `"0"` parses to `0`
//! (used by `ban_count_decay = "0"` to disable decay). Parsing is total — an
//! unrecognized string yields `None`, and the config layer falls back to the
//! field default with a `warn!` rather than failing the whole file.

/// Parse a duration string into whole seconds.
///
/// Accepts a non-negative integer optionally followed by a unit suffix:
/// `s` (seconds), `m` (minutes), `h` (hours), `d` (days), `w` (weeks). A bare
/// number is seconds. Returns `None` for anything else (empty, negative,
/// non-numeric, unknown unit, or an overflowing value).
#[must_use]
pub fn parse_duration(input: &str) -> Option<i64> {
    let s = input.trim();
    if s.is_empty() {
        return None;
    }
    let (digits, scale) = split_unit(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let value: i64 = digits.parse().ok()?;
    value.checked_mul(scale)
}

/// Split a duration string into its numeric prefix and per-unit second scale.
///
/// A recognized trailing unit letter is consumed; otherwise the whole string is
/// treated as a seconds count (scale `1`).
fn split_unit(s: &str) -> (&str, i64) {
    let scale = match s.as_bytes().last() {
        Some(b's' | b'S') => 1,
        Some(b'm' | b'M') => 60,
        Some(b'h' | b'H') => 3_600,
        Some(b'd' | b'D') => 86_400,
        Some(b'w' | b'W') => 604_800,
        _ => return (s, 1),
    };
    (&s[..s.len() - 1], scale)
}

#[cfg(test)]
#[path = "duration_test.rs"]
mod duration_test;
