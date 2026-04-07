use super::*;

#[test]
fn test_enumerate_input_devices_returns_at_least_one() {
    // On any Mac with a built-in mic, this should find at least one device.
    let devices = enumerate_input_devices();
    // On CI or headless systems this may fail — skip gracefully.
    if let Ok(devs) = devices {
        assert!(!devs.is_empty());
        for d in &devs {
            assert_eq!(d.kind, MediaDeviceKind::Microphone);
            assert!(!d.name.is_empty(), "device name should not be empty");
            assert_ne!(d.id, 0, "device id should not be zero");
        }
    }
}

#[test]
fn test_is_active_does_not_panic() {
    // Just verify it doesn't crash — result depends on hardware state.
    let _ = is_active();
}

#[test]
fn test_mic_monitor_start_stop_lifecycle() {
    let (tx, _rx) = mpsc::channel();
    // On a Mac with a mic, this should succeed.
    match MicMonitor::start(&tx) {
        Ok(monitor) => {
            // Drop should clean up all listeners without panic.
            drop(monitor);
        }
        Err(e) => {
            // Acceptable on headless/CI systems.
            eprintln!("MicMonitor::start failed (expected on CI): {e}");
        }
    }
}

#[test]
fn test_all_audio_device_ids_returns_devices() {
    if let Ok(ids) = all_audio_device_ids() {
        assert!(!ids.is_empty(), "should have at least one audio device");
    }
}
