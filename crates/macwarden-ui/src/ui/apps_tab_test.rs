use super::SwitchState;
use super::group_toggle_state;

#[test]
fn test_group_toggle_all_allowed_is_on() {
    assert_eq!(group_toggle_state([true, true, true]), SwitchState::On);
}

#[test]
fn test_group_toggle_all_blocked_is_off() {
    assert_eq!(group_toggle_state([false, false]), SwitchState::Off);
}

#[test]
fn test_group_toggle_mixed_is_mixed() {
    assert_eq!(group_toggle_state([true, false, true]), SwitchState::Mixed);
}

#[test]
fn test_group_toggle_empty_is_off() {
    let empty: [bool; 0] = [];
    assert_eq!(group_toggle_state(empty), SwitchState::Off);
}
