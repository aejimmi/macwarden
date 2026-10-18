use super::*;

#[test]
fn test_pluralize_one_uses_singular() {
    assert_eq!(pluralize(1, "command", "commands"), "1 command");
    assert_eq!(pluralize(1, "process", "processes"), "1 process");
}

#[test]
fn test_pluralize_zero_uses_plural() {
    assert_eq!(pluralize(0, "command", "commands"), "0 commands");
}

#[test]
fn test_pluralize_many_uses_plural() {
    assert_eq!(pluralize(3, "command", "commands"), "3 commands");
    assert_eq!(pluralize(2, "process", "processes"), "2 processes");
}
