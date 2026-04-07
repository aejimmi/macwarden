use super::*;

#[test]
fn test_media_device_kind_display() {
    assert_eq!(MediaDeviceKind::Camera.to_string(), "camera");
    assert_eq!(MediaDeviceKind::Microphone.to_string(), "microphone");
}

#[test]
fn test_media_device_construction() {
    let device = MediaDevice {
        id: 42,
        name: "FaceTime HD Camera".into(),
        uid: "0x1234".into(),
        kind: MediaDeviceKind::Camera,
    };
    assert_eq!(device.id, 42);
    assert_eq!(device.name, "FaceTime HD Camera");
    assert_eq!(device.kind, MediaDeviceKind::Camera);
}

#[test]
fn test_sensor_event_device_accessor() {
    let device = MediaDevice {
        id: 1,
        name: "Built-in Microphone".into(),
        uid: "built-in-mic".into(),
        kind: MediaDeviceKind::Microphone,
    };

    let activated = SensorEvent::DeviceActivated(device.clone());
    assert_eq!(activated.device(), &device);

    let deactivated = SensorEvent::DeviceDeactivated(device.clone());
    assert_eq!(deactivated.device(), &device);

    let connected = SensorEvent::DeviceConnected(device.clone());
    assert_eq!(connected.device(), &device);

    let disconnected = SensorEvent::DeviceDisconnected(device.clone());
    assert_eq!(disconnected.device(), &device);
}

#[test]
fn test_media_device_serialize() {
    let device = MediaDevice {
        id: 10,
        name: "Test Mic".into(),
        uid: "uid-abc".into(),
        kind: MediaDeviceKind::Microphone,
    };
    let json = serde_json::to_string(&device);
    assert!(json.is_ok(), "MediaDevice should serialize to JSON");
    let s = json.expect("already checked");
    assert!(s.contains("Test Mic"));
    assert!(s.contains("Microphone"));
}
