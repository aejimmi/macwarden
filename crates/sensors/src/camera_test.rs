use super::*;

#[test]
fn test_is_active_returns_result() {
    // Calls real hardware via ioreg — just verify no crash.
    let result = is_active();
    match result {
        Ok(_active) => {} // Camera either active or not.
        Err(SensorError::NoDevice { kind }) => {
            assert_eq!(kind, "camera");
        }
        Err(_) => {} // Other errors acceptable on headless systems.
    }
}

#[test]
fn test_enumerate_cameras() {
    match enumerate_cameras() {
        Ok(cameras) => {
            assert!(!cameras.is_empty());
            for cam in &cameras {
                assert_eq!(cam.kind, MediaDeviceKind::Camera);
                assert!(!cam.name.is_empty());
            }
        }
        Err(SensorError::NoDevice { .. }) => {} // No camera — OK.
        Err(e) => {
            eprintln!("enumerate_cameras failed: {e}");
        }
    }
}

#[test]
fn test_camera_monitor_start_and_drop() {
    let (tx, _rx) = mpsc::channel();

    match CameraMonitor::start(tx) {
        Ok(monitor) => {
            // Let it initialize briefly then drop.
            std::thread::sleep(Duration::from_millis(100));
            drop(monitor);
        }
        Err(SensorError::NoDevice { .. }) => {} // No camera — OK.
        Err(e) => {
            eprintln!("CameraMonitor::start failed (expected on headless): {e}");
        }
    }
}
