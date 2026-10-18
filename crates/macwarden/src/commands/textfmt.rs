//! Small text-formatting helpers shared across human-facing commands.

/// Render a count with the grammatically correct noun form.
///
/// Returns `"1 command"` for a count of one and `"3 commands"` otherwise, so
/// human output never reads `"1 commands"`. The caller supplies both forms
/// because English plurals are irregular (`process` → `processes`).
///
/// ```ignore
/// assert_eq!(pluralize(1, "command", "commands"), "1 command");
/// assert_eq!(pluralize(0, "command", "commands"), "0 commands");
/// ```
#[must_use]
pub fn pluralize(count: usize, singular: &str, plural: &str) -> String {
    if count == 1 {
        format!("{count} {singular}")
    } else {
        format!("{count} {plural}")
    }
}

#[cfg(test)]
#[path = "textfmt_test.rs"]
mod textfmt_test;
