use std::sync::mpsc;
use std::time::Duration;

use super::*;
use crate::{MediaDevice, MediaDeviceKind, SensorEvent};

fn test_device(id: u64, kind: MediaDeviceKind) -> MediaDevice {
    MediaDevice {
        id,
        name: format!("Test {kind} {id}"),
        uid: format!("test-{id}"),
        kind,
    }
}

#[test]
fn test_rapid_events_debounced() {
    let (tx, rx) = mpsc::channel();
    let debounced = DebouncedSender::with_window(tx, Duration::from_millis(100));

    let mic = test_device(1, MediaDeviceKind::Microphone);

    // Send rapid on/off/on — second and third should be suppressed.
    debounced
        .send(SensorEvent::DeviceActivated(mic.clone()))
        .unwrap();
    debounced
        .send(SensorEvent::DeviceDeactivated(mic.clone()))
        .unwrap();
    debounced
        .send(SensorEvent::DeviceActivated(mic.clone()))
        .unwrap();

    // Only the first event should have been forwarded.
    let first = rx.try_recv().unwrap();
    assert!(matches!(first, SensorEvent::DeviceActivated(_)));
    assert!(
        rx.try_recv().is_err(),
        "subsequent rapid events should be suppressed"
    );
}

#[test]
fn test_events_after_window_pass_through() {
    let (tx, rx) = mpsc::channel();
    let debounced = DebouncedSender::with_window(tx, Duration::from_millis(50));

    let mic = test_device(1, MediaDeviceKind::Microphone);

    debounced
        .send(SensorEvent::DeviceActivated(mic.clone()))
        .unwrap();
    std::thread::sleep(Duration::from_millis(60));
    debounced
        .send(SensorEvent::DeviceDeactivated(mic.clone()))
        .unwrap();

    // Both should pass through.
    assert!(rx.try_recv().is_ok());
    assert!(rx.try_recv().is_ok());
}

#[test]
fn test_connect_disconnect_never_debounced() {
    let (tx, rx) = mpsc::channel();
    let debounced = DebouncedSender::with_window(tx, Duration::from_secs(10));

    let mic = test_device(1, MediaDeviceKind::Microphone);

    // Rapid connect/disconnect should all pass through.
    debounced
        .send(SensorEvent::DeviceConnected(mic.clone()))
        .unwrap();
    debounced
        .send(SensorEvent::DeviceDisconnected(mic.clone()))
        .unwrap();
    debounced
        .send(SensorEvent::DeviceConnected(mic.clone()))
        .unwrap();

    assert!(rx.try_recv().is_ok());
    assert!(rx.try_recv().is_ok());
    assert!(rx.try_recv().is_ok());
}

#[test]
fn test_different_devices_independent() {
    let (tx, rx) = mpsc::channel();
    let debounced = DebouncedSender::with_window(tx, Duration::from_millis(100));

    let mic1 = test_device(1, MediaDeviceKind::Microphone);
    let mic2 = test_device(2, MediaDeviceKind::Microphone);

    // Events for different devices should both pass through.
    debounced
        .send(SensorEvent::DeviceActivated(mic1.clone()))
        .unwrap();
    debounced
        .send(SensorEvent::DeviceActivated(mic2.clone()))
        .unwrap();

    assert!(rx.try_recv().is_ok());
    assert!(rx.try_recv().is_ok());
}
