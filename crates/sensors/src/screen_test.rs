use super::*;

#[test]
fn test_is_active_does_not_panic() {
    // Just verify it doesn't crash.
    let _ = is_active();
}

#[test]
fn test_screen_device_has_correct_kind() {
    let dev = screen_device();
    assert_eq!(dev.kind, MediaDeviceKind::Screen);
    assert!(!dev.name.is_empty());
}

#[test]
fn test_screen_monitor_start_and_drop() {
    let (tx, _rx) = mpsc::channel();
    match ScreenMonitor::start(tx) {
        Ok(monitor) => {
            // Give it a brief moment then drop cleanly.
            std::thread::sleep(Duration::from_millis(100));
            drop(monitor);
        }
        Err(e) => {
            eprintln!("ScreenMonitor::start failed: {e}");
        }
    }
}
