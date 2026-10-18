//! Live BPF/pcap capture session (spec R2/R6/R7) — the **impure** half.
//!
//! This module is gated `#[cfg(all(feature = "capture-live", target_os =
//! "macos"))]`; the default build never compiles it, so the crate stays pure
//! and Linux-CI-clean. It opens a real capture on one interface via the
//! vendored [`pcap`] crate, narrows it to the target app's 5-tuples with a
//! [`build_bpf_filter`] program, and runs a read loop on a dedicated thread that
//! feeds each frame through the stage-1 [`parse_frame`] and into a bounded
//! [`PacketRing`].
//!
//! # Ownership and permissions
//!
//! A [`CaptureSession`] is owned by the **privileged daemon**, never the panel.
//! Opening a capture reads `/dev/bpf*`, which requires **root** or membership in
//! the **`access_bpf`** group (the Wireshark "ChmodBPF" convention). Raw packet
//! capture is forbidden in the App Store sandbox, so this is a Developer-ID /
//! **non-MAS** capability. The next stage (the daemon `TraceSession`) drives
//! this type from IPC: `StartTrace` → [`CaptureSession::start`], periodic
//! scanner refresh → [`CaptureSession::update_filter`], drains records via
//! [`CaptureSession::drain`] into `WirePacketRecord` events, and `StopTrace` /
//! disconnect → drop (which stops the capture thread and releases the handle).
//!
//! # Never blocks on a slow consumer
//!
//! The capture thread pushes into a shared [`PacketRing`] that drops the oldest
//! record (with a counter) when full, so it never blocks waiting for the daemon
//! to drain — a hostile flood costs bounded memory and CPU, not a stall.

use crate::bpf::{FlowTuple, build_bpf_filter};
use crate::link::LinkType;
use crate::parse::parse_frame;
use crate::ring::{DEFAULT_MAX_BYTES, DEFAULT_MAX_PACKETS, PacketRing, RateLimiter, RingStats};
use crate::types::Timestamp;
use pcap::{Active, Capture, Device, Linktype};
use std::net::IpAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, warn};

/// Default snaplen — large enough to capture a full TLS Client Hello (spec R2).
pub const DEFAULT_SNAPLEN: i32 = 262_144;
/// Default read timeout in milliseconds; short so the loop checks its stop flag
/// promptly.
pub const DEFAULT_TIMEOUT_MS: i32 = 100;
/// Default per-second packet processing cap (a flood over this is dropped).
pub const DEFAULT_RATE_LIMIT_PER_SEC: u32 = 200_000;

/// A failure opening or configuring a live capture.
#[derive(Debug, Error)]
pub enum CaptureError {
    /// No capture device was found (named device absent, or no default).
    #[error("no capture device available")]
    NoDevice,
    /// The interface's data-link type is not one the stage-1 parser handles.
    #[error("unsupported data-link type: {0}")]
    UnsupportedLinkType(i32),
    /// The underlying pcap library reported an error.
    #[error("pcap error: {0}")]
    Pcap(String),
    /// The capture thread could not be spawned.
    #[error("failed to spawn capture thread: {0}")]
    Spawn(String),
    /// The session's capture thread has already stopped.
    #[error("capture session is stopped")]
    Stopped,
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "used as a `map_err` handler, which passes the error by value"
)]
fn pcap_err(e: pcap::Error) -> CaptureError {
    CaptureError::Pcap(e.to_string())
}

/// Tunables for a capture session.
#[derive(Debug, Clone)]
pub struct CaptureConfig {
    /// Interface name to capture on; `None` selects the default device.
    pub device: Option<String>,
    /// Maximum bytes captured per packet.
    pub snaplen: i32,
    /// Read timeout in milliseconds.
    pub timeout_ms: i32,
    /// Ring capacity in packets.
    pub ring_max_packets: usize,
    /// Ring capacity in retained raw bytes.
    pub ring_max_bytes: usize,
    /// Packets processed per second before excess is dropped (`0` = unlimited).
    pub rate_limit_per_sec: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            device: None,
            snaplen: DEFAULT_SNAPLEN,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            ring_max_packets: DEFAULT_MAX_PACKETS,
            ring_max_bytes: DEFAULT_MAX_BYTES,
            rate_limit_per_sec: DEFAULT_RATE_LIMIT_PER_SEC,
        }
    }
}

/// Combined capture accounting surfaced to the daemon/UI (spec R6 footer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureStats {
    /// Ring occupancy and overflow-drop count.
    pub ring: RingStats,
    /// Packets dropped by the rate limiter.
    pub rate_dropped: u64,
    /// Frames skipped because they failed to parse (malformed/truncated).
    pub parse_errors: u64,
}

/// A command sent to the capture thread. Stopping is signalled via the shared
/// atomic flag instead, so a dropped session stops even if the channel is idle.
enum Command {
    UpdateFilter(String),
}

/// A live per-app packet capture running on a dedicated thread.
///
/// Dropping the session stops the capture thread and releases the BPF handle
/// (RAII), so the daemon does not need an explicit stop on every path — this is
/// what makes "connection closed without `StopTrace`" still tear down the
/// capture (spec R9).
pub struct CaptureSession {
    cmd_tx: Sender<Command>,
    ring: Arc<Mutex<PacketRing>>,
    stop: Arc<AtomicBool>,
    rate_dropped: Arc<AtomicU64>,
    parse_errors: Arc<AtomicU64>,
    thread: Option<JoinHandle<()>>,
    device: String,
    link_type: LinkType,
}

impl CaptureSession {
    /// Open a capture on the configured interface, apply the initial filter
    /// built from `tuples`, and start the read loop.
    ///
    /// The device is the configured one, or the default interface when unset.
    /// Only traffic on this one interface is seen; loopback and secondary
    /// interfaces (Wi-Fi vs. Ethernet vs. VPN utun) require separate handles and
    /// are out of scope for a single trace.
    pub fn start(config: &CaptureConfig, tuples: &[FlowTuple]) -> Result<Self, CaptureError> {
        let device = select_device(config.device.as_deref())?;
        let device_name = device.name.clone();
        let local_ips: Vec<IpAddr> = device.addresses.iter().map(|a| a.addr).collect();

        let mut cap = open_capture(device, config)?;
        let link_type = map_link_type(cap.get_datalink())?;
        let filter = build_bpf_filter(tuples);
        cap.filter(&filter, true).map_err(pcap_err)?;
        debug!(device = %device_name, %filter, "capture opened and filtered");

        let ring = Arc::new(Mutex::new(PacketRing::new(
            config.ring_max_packets,
            config.ring_max_bytes,
        )));
        let stop = Arc::new(AtomicBool::new(false));
        let rate_dropped = Arc::new(AtomicU64::new(0));
        let parse_errors = Arc::new(AtomicU64::new(0));
        let (cmd_tx, cmd_rx) = mpsc::channel();

        let worker = CaptureWorker {
            cap,
            cmd_rx,
            ring: Arc::clone(&ring),
            stop: Arc::clone(&stop),
            rate_dropped: Arc::clone(&rate_dropped),
            parse_errors: Arc::clone(&parse_errors),
            local_ips,
            link_type,
            rate: RateLimiter::new(config.rate_limit_per_sec),
        };
        let thread = std::thread::Builder::new()
            .name("mw-capture".to_string())
            .spawn(move || worker.run())
            .map_err(|e| CaptureError::Spawn(e.to_string()))?;

        Ok(Self {
            cmd_tx,
            ring,
            stop,
            rate_dropped,
            parse_errors,
            thread: Some(thread),
            device: device_name,
            link_type,
        })
    }

    /// Rebuild and re-apply the BPF filter from a refreshed tuple set as the app
    /// opens new flows (spec R2/R7). The capture thread applies it between reads.
    pub fn update_filter(&self, tuples: &[FlowTuple]) -> Result<(), CaptureError> {
        let filter = build_bpf_filter(tuples);
        self.cmd_tx
            .send(Command::UpdateFilter(filter))
            .map_err(|_| CaptureError::Stopped)
    }

    /// Remove and return all buffered records (oldest first). The `dropped`
    /// counter in [`stats`](Self::stats) is preserved across drains.
    #[must_use]
    pub fn drain(&self) -> Vec<crate::parse::PacketRecord> {
        match self.ring.lock() {
            Ok(mut ring) => ring.drain(),
            Err(poisoned) => poisoned.into_inner().drain(),
        }
    }

    /// The raw bytes for one retained `seq`, or `None` if evicted/absent.
    #[must_use]
    pub fn bytes(&self, seq: u64) -> Option<Vec<u8>> {
        let ring = self
            .ring
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ring.bytes(seq).map(<[u8]>::to_vec)
    }

    /// A snapshot of capture accounting for the UI footer.
    #[must_use]
    pub fn stats(&self) -> CaptureStats {
        let ring = match self.ring.lock() {
            Ok(g) => g.stats(),
            Err(p) => p.into_inner().stats(),
        };
        CaptureStats {
            ring,
            rate_dropped: self.rate_dropped.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
        }
    }

    /// The interface this session is capturing on.
    #[must_use]
    pub fn device(&self) -> &str {
        &self.device
    }

    /// The data-link type of the captured interface.
    #[must_use]
    pub fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Signal the capture thread to stop and join it, releasing the BPF handle.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.take()
            && handle.join().is_err()
        {
            warn!("capture thread terminated abnormally");
        }
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// The state owned exclusively by the capture thread. `Capture<Active>` is
/// `!Sync`, so it lives here and is never shared; filter changes arrive over the
/// command channel instead.
struct CaptureWorker {
    cap: Capture<Active>,
    cmd_rx: Receiver<Command>,
    ring: Arc<Mutex<PacketRing>>,
    stop: Arc<AtomicBool>,
    rate_dropped: Arc<AtomicU64>,
    parse_errors: Arc<AtomicU64>,
    local_ips: Vec<IpAddr>,
    link_type: LinkType,
    rate: RateLimiter,
}

impl CaptureWorker {
    /// Run the read loop until the stop flag is set. The whole loop is wrapped
    /// in `catch_unwind` so a panic in the pcap FFI (or anywhere) tears down the
    /// thread cleanly instead of unwinding across the FFI boundary.
    fn run(mut self) {
        let result = catch_unwind(AssertUnwindSafe(|| self.read_loop()));
        if result.is_err() {
            warn!("capture read loop panicked; capture stopped");
        }
    }

    fn read_loop(&mut self) {
        let base = Instant::now();
        let mut seq: u64 = 0;
        while !self.stop.load(Ordering::Relaxed) {
            self.apply_pending_commands();
            match self.cap.next_packet() {
                Ok(packet) => {
                    let now = base.elapsed().as_nanos() as u64;
                    if !self.rate.allow(now) {
                        self.rate_dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    // `packet` borrows `self.cap`; pass only the disjoint
                    // fields `handle_packet` needs so the borrows don't overlap.
                    Self::handle_packet(
                        &self.ring,
                        &self.parse_errors,
                        self.link_type,
                        &self.local_ips,
                        packet.header,
                        packet.data,
                        seq,
                    );
                    seq = seq.wrapping_add(1);
                }
                // Timeout: no packet this interval — loop back and re-check stop.
                Err(pcap::Error::TimeoutExpired) => {}
                // Any other read error is treated as transient; the loop
                // continues and observes the stop flag rather than crashing.
                Err(e) => {
                    debug!(error = %e, "transient capture read error");
                }
            }
        }
    }

    fn apply_pending_commands(&mut self) {
        while let Ok(cmd) = self.cmd_rx.try_recv() {
            match cmd {
                Command::UpdateFilter(filter) => {
                    if let Err(e) = self.cap.filter(&filter, true) {
                        warn!(error = %e, "failed to apply refreshed BPF filter");
                    } else {
                        debug!(%filter, "refreshed BPF filter");
                    }
                }
            }
        }
    }

    fn handle_packet(
        ring: &Mutex<PacketRing>,
        parse_errors: &AtomicU64,
        link_type: LinkType,
        local_ips: &[IpAddr],
        header: &pcap::PacketHeader,
        data: &[u8],
        seq: u64,
    ) {
        let ts = Timestamp::new(header.ts.tv_sec, i64::from(header.ts.tv_usec));
        match parse_frame(data, link_type, seq, ts, local_ips) {
            Ok(record) => match ring.lock() {
                Ok(mut ring) => ring.push(record),
                Err(poisoned) => poisoned.into_inner().push(record),
            },
            // A malformed/truncated frame is skipped and counted, never fatal.
            Err(_) => {
                parse_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Select the capture device: the named interface (found in the device list so
/// its addresses are populated for direction), or — when unset — the interface
/// that actually **routes to the internet**.
///
/// pcap's own `lookup()` default is unreliable on macOS: it returns the first
/// "up" device, which is frequently a VPN `utun*` tunnel that carries none of the
/// app's traffic, so a live trace captures zero packets. Instead we resolve the
/// primary interface by asking the OS which local address it would use to reach a
/// public host (a routing query — no packets are sent), then pick the device that
/// owns that address. Falls back to pcap's `lookup()` if that can't be resolved.
fn select_device(name: Option<&str>) -> Result<Device, CaptureError> {
    if let Some(wanted) = name {
        return Device::list()
            .map_err(pcap_err)?
            .into_iter()
            .find(|d| d.name == wanted)
            .ok_or(CaptureError::NoDevice);
    }
    let devices = Device::list().map_err(pcap_err)?;
    if let Some(primary) = primary_local_ip()
        && let Some(device) = devices
            .iter()
            .find(|d| d.addresses.iter().any(|a| a.addr == primary))
    {
        debug!(device = %device.name, %primary, "capture default: primary-route interface");
        return Ok(device.clone());
    }
    Device::lookup()
        .map_err(pcap_err)?
        .ok_or(CaptureError::NoDevice)
}

/// The local IP the OS would use to reach the public internet — i.e. the address
/// of the default-route interface. A `connect` on a UDP socket only sets the
/// route (no datagram is sent), so this is a cheap, side-effect-free query.
fn primary_local_ip() -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    // A public, routable address; no traffic leaves the host.
    socket.connect("8.8.8.8:53").ok()?;
    socket.local_addr().ok().map(|addr| addr.ip())
}

/// Open and activate a capture with a bounded snaplen, immediate mode, and a
/// short read timeout so the loop stays responsive (spec R2).
fn open_capture(device: Device, config: &CaptureConfig) -> Result<Capture<Active>, CaptureError> {
    Capture::from_device(device)
        .map_err(pcap_err)?
        .snaplen(config.snaplen)
        .immediate_mode(true)
        .timeout(config.timeout_ms)
        .open()
        .map_err(pcap_err)
}

/// Map a libpcap data-link type to the stage-1 [`LinkType`]. DLT numeric values:
/// EN10MB=1, RAW=101, IPV4=228, IPV6=229, NULL=0, LOOP=108, LINUX_SLL=113,
/// LINUX_SLL2=276.
fn map_link_type(linktype: Linktype) -> Result<LinkType, CaptureError> {
    match linktype.0 {
        1 => Ok(LinkType::Ethernet),
        101 | 228 | 229 => Ok(LinkType::RawIp),
        0 | 108 => Ok(LinkType::Null),
        113 => Ok(LinkType::LinuxSll),
        276 => Ok(LinkType::LinuxSll2),
        other => Err(CaptureError::UnsupportedLinkType(other)),
    }
}

#[cfg(test)]
#[path = "session_test.rs"]
mod session_test;
