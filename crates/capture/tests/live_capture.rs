//! Live BPF capture integration test (spec R2/R13).
//!
//! This is the **only** test that opens a real device. It is `#[ignore]` by
//! default so CI and ordinary `cargo test` runs skip it, and it is compiled only
//! with the `capture-live` feature on macOS. It requires **root** or membership
//! in the **`access_bpf`** group to open `/dev/bpf*`.
//!
//! Run it manually with:
//!
//! ```sh
//! sudo cargo test -p capture --features capture-live -- --ignored
//! ```

#![cfg(all(feature = "capture-live", target_os = "macos"))]

use capture::{CaptureConfig, CaptureSession, FlowTuple, L4Proto};
use std::net::UdpSocket;
use std::time::Duration;

#[test]
#[ignore = "requires root or access_bpf; run: sudo cargo test -p capture --features capture-live -- --ignored"]
fn live_loopback_captures_self_generated_packets() {
    // Loopback is DLT_NULL on macOS; scope the filter to self-generated UDP to
    // the discard port so only our own packets match.
    let target = "127.0.0.1".parse().expect("valid loopback ip");
    let tuples = [FlowTuple::new(target, 9, L4Proto::Udp)];
    let config = CaptureConfig {
        device: Some("lo0".to_string()),
        ..CaptureConfig::default()
    };

    let session = CaptureSession::start(&config, &tuples).expect("open loopback capture");

    // Generate a handful of matching packets.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind sender");
    for _ in 0..8 {
        let _ = sock.send_to(b"macwarden-trace-probe", "127.0.0.1:9");
    }
    std::thread::sleep(Duration::from_millis(400));

    let packets = session.drain();
    let stats = session.stats();
    session.stop();

    assert!(
        !packets.is_empty(),
        "expected to capture self-generated loopback packets"
    );
    for pkt in &packets {
        assert_eq!(pkt.dst.port, Some(9), "filter should scope to port 9");
    }
    // The ring must never exceed its configured bound.
    assert!(stats.ring.retained <= config.ring_max_packets);
}
