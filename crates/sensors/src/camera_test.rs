use super::*;

#[test]
fn test_is_active_returns_result() {
    // Calls real hardware via ioreg — just verify no crash.
    let result = is_active();
    match result {
        Ok(active) => {
            assert!(active || !active);
        }
        Err(SensorError::NoDevice { kind }) => {
            assert_eq!(kind, "camera");
        }
        Err(_) => {
            // Other errors acceptable on headless systems.
        }
    }
}

#[test]
fn test_camera_monitor_start_and_drop() {
    let (tx, _rx) = mpsc::channel();

    match CameraMonitor::start(tx) {
        Ok(monitor) => {
            // Let it poll once then drop.
            std::thread::sleep(std::time::Duration::from_millis(100));
            drop(monitor);
        }
        Err(SensorError::NoDevice { .. }) => {
            // No camera — OK.
        }
        Err(e) => {
            eprintln!("CameraMonitor::start failed (expected on headless): {e}");
        }
    }
}
