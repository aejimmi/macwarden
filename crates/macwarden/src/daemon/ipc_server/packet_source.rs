//! The packet source behind a [`super::trace_session::TraceSession`] (spec R9).
//!
//! A trace pulls parsed [`PacketRecord`]s from a [`PacketSource`] and refreshes
//! its capture filter as the app opens new flows. Two implementations sit behind
//! the trait:
//!
//! * [`DemoSource`] — emits a **scripted, synthetic** stream (a TCP handshake, a
//!   TLS Client Hello carrying an SNI, a DNS query, a TLS application-data
//!   record, and an inbound segment) built as real Ethernet/IP frames and run
//!   through the exact stage-1 [`parse_frame`] path. It needs no root, no BPF,
//!   and no `capture-live` feature, so the whole StartTrace → `Event::Packet` →
//!   GetPacketBytes flow (decode tree + hex included) is demonstrable on any
//!   build, including Linux CI.
//! * `LiveSource` — wraps `capture::CaptureSession`, the real BPF capture. It is
//!   compiled only under `capture-live` + macOS and selected at runtime only
//!   when the daemon actually has BPF access (root / `access_bpf`).
//!
//! [`select_source`] prefers the live backend when it is available and can open
//! a device, and falls back to the demo otherwise — so a panel can always
//! exercise the trace view, and real capture slots in under root with no code
//! change on the daemon path.

use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use capture::{FlowTuple, LinkType, PacketRecord, Timestamp, parse_frame};
use etherparse::PacketBuilder;
use ipc::protocol::WireTraceSource;
use tracing::debug;

/// The synthetic local host address stamped on demo frames; outbound demo
/// packets use it as their source so [`capture::Direction::Outbound`] is derived.
const DEMO_LOCAL_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);

/// A source of parsed packets for a trace, refreshable as the app's flows change.
///
/// Implementations own whatever capture state they need; the trace pump calls
/// [`PacketSource::drain`] on a cadence and [`PacketSource::update_filter`] when
/// the scanner reports new flows for the traced app (spec R2/R7).
pub trait PacketSource: Send {
    /// Remove and return the packets captured since the last drain (oldest
    /// first). Never blocks.
    fn drain(&mut self) -> Vec<PacketRecord>;

    /// Re-scope the capture to a refreshed 5-tuple set (spec R2). The demo source
    /// records the set for realism; the live source rebuilds its BPF program.
    fn update_filter(&mut self, tuples: &[FlowTuple]);

    /// A human label for the source's interface, surfaced in the trace footer.
    fn device(&self) -> &str;
}

/// Select the best available packet source for a trace's initial tuple set, and
/// report **which** source was chosen so the panel can be honest about it.
///
/// Prefers the live BPF backend when it is compiled in and can open a device
/// (root / `access_bpf`); otherwise returns the [`DemoSource`] with the reason it
/// fell back — no BPF access (feature present) vs. no capture compiled in. The
/// flow is always demonstrable; real capture requires only BPF access, with no
/// change to this call site.
#[must_use]
pub fn select_source(tuples: &[FlowTuple]) -> (Box<dyn PacketSource>, WireTraceSource) {
    // Unit/integration tests are deterministic on the demo source — they must
    // never depend on this machine having (or lacking) real BPF access, which
    // would make results vary with the CI runner. `FORCE_DEMO_SOURCE` defaults on
    // under `cfg(test)`, so tests always exercise the synthetic stream.
    #[cfg(test)]
    if FORCE_DEMO_SOURCE.load(std::sync::atomic::Ordering::Relaxed) {
        return (Box::new(DemoSource::new(tuples)), demo_source_kind());
    }
    match try_live_source(tuples) {
        Some(live) => (live, WireTraceSource::Live),
        None => (Box::new(DemoSource::new(tuples)), demo_source_kind()),
    }
}

/// Test-only switch (default on) forcing [`select_source`] to the demo stream so
/// trace tests never touch real BPF. A future test that needs the live path can
/// flip it off.
#[cfg(test)]
pub(super) static FORCE_DEMO_SOURCE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(true);

/// Why the demo source was chosen: the feature is compiled but no BPF device
/// could be opened (`DemoNoAccess`), or live capture is not compiled in at all
/// (`DemoNoCapture`, feature off / non-macOS).
#[cfg(all(feature = "capture-live", target_os = "macos"))]
fn demo_source_kind() -> WireTraceSource {
    WireTraceSource::DemoNoAccess
}

#[cfg(not(all(feature = "capture-live", target_os = "macos")))]
fn demo_source_kind() -> WireTraceSource {
    WireTraceSource::DemoNoCapture
}

/// Try to open the real live capture backend. Returns `None` when the feature is
/// off, the platform is not macOS, or the device cannot be opened (no BPF
/// access) — the caller then falls back to [`DemoSource`].
#[cfg(all(feature = "capture-live", target_os = "macos"))]
fn try_live_source(tuples: &[FlowTuple]) -> Option<Box<dyn PacketSource>> {
    let config = capture::CaptureConfig::default();
    match capture::CaptureSession::start(&config, tuples) {
        Ok(session) => {
            debug!(device = session.device(), "trace using live BPF capture");
            Some(Box::new(live::LiveSource::new(session)))
        }
        Err(e) => {
            debug!(error = %e, "live capture unavailable; using demo source");
            None
        }
    }
}

/// Non-macOS / feature-off build: there is no live backend, always demo.
#[cfg(not(all(feature = "capture-live", target_os = "macos")))]
fn try_live_source(_tuples: &[FlowTuple]) -> Option<Box<dyn PacketSource>> {
    None
}

/// The live BPF capture source, wrapping `capture::CaptureSession`.
#[cfg(all(feature = "capture-live", target_os = "macos"))]
mod live {
    use super::{FlowTuple, PacketRecord, PacketSource};

    /// Wraps the real capture; [`Drop`] on the inner session releases the BPF
    /// handle (RAII), so dropping the trace tears the capture down.
    pub struct LiveSource {
        session: capture::CaptureSession,
    }

    impl LiveSource {
        pub fn new(session: capture::CaptureSession) -> Self {
            Self { session }
        }
    }

    impl PacketSource for LiveSource {
        fn drain(&mut self) -> Vec<PacketRecord> {
            self.session.drain()
        }

        fn update_filter(&mut self, tuples: &[FlowTuple]) {
            if let Err(e) = self.session.update_filter(tuples) {
                tracing::debug!(error = %e, "failed to refresh live capture filter");
            }
        }

        fn device(&self) -> &str {
            self.session.device()
        }
    }
}

/// A scripted synthetic source: one packet per [`drain`](PacketSource::drain),
/// cycling a realistic template set with monotonic sequence numbers and live
/// timestamps so the trace stream looks and behaves like a real capture.
pub struct DemoSource {
    templates: Vec<DemoFrame>,
    cursor: usize,
    seq: u64,
    device: String,
}

/// One demo frame: pre-built raw Ethernet bytes plus the interface addresses to
/// pass to [`parse_frame`] so [`capture::Direction`] resolves correctly.
struct DemoFrame {
    raw: Vec<u8>,
    local_ips: Vec<IpAddr>,
}

impl DemoSource {
    /// Build the scripted template set. `tuples` is accepted for parity with the
    /// live backend's constructor; the demo emits its own realistic traffic
    /// regardless of the app's actual flows.
    #[must_use]
    pub fn new(_tuples: &[FlowTuple]) -> Self {
        Self {
            templates: demo_frames(),
            cursor: 0,
            seq: 0,
            device: "demo0".to_owned(),
        }
    }
}

impl PacketSource for DemoSource {
    fn drain(&mut self) -> Vec<PacketRecord> {
        let Some(frame) = self.templates.get(self.cursor) else {
            return Vec::new();
        };
        self.cursor = (self.cursor + 1) % self.templates.len().max(1);
        let seq = self.seq;
        self.seq += 1;
        match parse_frame(
            &frame.raw,
            LinkType::Ethernet,
            seq,
            now_ts(),
            &frame.local_ips,
        ) {
            Ok(record) => vec![record],
            Err(e) => {
                debug!(error = %e, "demo frame failed to parse (skipped)");
                Vec::new()
            }
        }
    }

    fn update_filter(&mut self, _tuples: &[FlowTuple]) {
        // The demo stream is fixed; a real refresh only matters for live capture.
    }

    fn device(&self) -> &str {
        &self.device
    }
}

/// Current time as a capture [`Timestamp`].
fn now_ts() -> Timestamp {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    Timestamp::new(d.as_secs() as i64, i64::from(d.subsec_micros()))
}

/// The scripted demo traffic, most-illustrative first: a plain TCP segment, a
/// TLS Client Hello with an SNI, a DNS query, an opaque TLS application-data
/// record (the Tier-1 boundary), and an inbound segment.
fn demo_frames() -> Vec<DemoFrame> {
    let local = vec![IpAddr::V4(DEMO_LOCAL_IP)];
    let cdn = Ipv4Addr::new(93, 184, 216, 34);
    let resolver = Ipv4Addr::new(1, 1, 1, 1);
    vec![
        DemoFrame {
            raw: eth_ipv4_tcp(DEMO_LOCAL_IP, cdn, 52344, 443, 1000, &[]),
            local_ips: local.clone(),
        },
        DemoFrame {
            raw: eth_ipv4_tcp(
                DEMO_LOCAL_IP,
                cdn,
                52344,
                443,
                1001,
                &client_hello("example.com"),
            ),
            local_ips: local.clone(),
        },
        DemoFrame {
            raw: eth_ipv4_udp(
                DEMO_LOCAL_IP,
                resolver,
                51000,
                53,
                &dns_query("example.com"),
            ),
            local_ips: local.clone(),
        },
        DemoFrame {
            raw: eth_ipv4_tcp(DEMO_LOCAL_IP, cdn, 52344, 443, 1500, &tls_app_data(240)),
            local_ips: local.clone(),
        },
        DemoFrame {
            raw: eth_ipv4_tcp(cdn, DEMO_LOCAL_IP, 443, 52344, 9000, &tls_app_data(1300)),
            local_ips: local,
        },
    ]
}

/// Build a real Ethernet+IPv4+TCP frame with the given payload via `etherparse`.
fn eth_ipv4_tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    seq: u32,
    payload: &[u8],
) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4(src.octets(), dst.octets(), 64)
        .tcp(sport, dport, seq, 64240);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    // Writing to a `Vec` is infallible; on the impossible error we return the
    // partial buffer, which `parse_frame` then simply skips.
    if let Err(e) = builder.write(&mut out, payload) {
        debug!(error = %e, "demo TCP frame build failed");
    }
    out
}

/// Build a real Ethernet+IPv4+UDP frame with the given payload via `etherparse`.
fn eth_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let builder = PacketBuilder::ethernet2([0x02, 0, 0, 0, 0, 1], [0x02, 0, 0, 0, 0, 2])
        .ipv4(src.octets(), dst.octets(), 64)
        .udp(sport, dport);
    let mut out = Vec::with_capacity(builder.size(payload.len()));
    if let Err(e) = builder.write(&mut out, payload) {
        debug!(error = %e, "demo UDP frame build failed");
    }
    out
}

/// A minimal, well-formed TLS 1.2 Client Hello record carrying a single SNI
/// server-name extension for `host`. Lengths are computed so `tls-parser`
/// accepts it and extracts the SNI (spec R4).
fn client_hello(host: &str) -> Vec<u8> {
    let mut sni = Vec::new();
    let name = host.as_bytes();
    // ServerName entry: name_type(host_name=0) + 2-byte name length + name.
    let mut server_name = vec![0x00];
    server_name.extend_from_slice(&(name.len() as u16).to_be_bytes());
    server_name.extend_from_slice(name);
    // ServerNameList: 2-byte list length + the entry.
    let mut sni_list = (server_name.len() as u16).to_be_bytes().to_vec();
    sni_list.extend_from_slice(&server_name);
    // Extension: type(0x0000 server_name) + 2-byte ext length + list.
    sni.extend_from_slice(&[0x00, 0x00]);
    sni.extend_from_slice(&(sni_list.len() as u16).to_be_bytes());
    sni.extend_from_slice(&sni_list);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version = TLS 1.2
    body.extend_from_slice(&[0x11; 32]); // 32-byte random
    body.push(0x00); // session_id length
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites: TLS_AES_128_GCM_SHA256
    body.extend_from_slice(&[0x01, 0x00]); // compression methods: null
    body.extend_from_slice(&(sni.len() as u16).to_be_bytes()); // extensions length
    body.extend_from_slice(&sni);

    // Handshake header: msg_type(ClientHello=1) + 3-byte length + body.
    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&u24_be(body.len()));
    handshake.extend_from_slice(&body);

    // Record header: content_type(handshake=0x16) + version + 2-byte length.
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// A TLS application-data record header (`content_type = 0x17`) followed by
/// `len` opaque bytes — parses to `{ content_type, length }` only, never a body
/// (the Tier-1 boundary, spec R1).
fn tls_app_data(len: usize) -> Vec<u8> {
    let mut record = vec![0x17, 0x03, 0x03];
    record.extend_from_slice(&(len as u16).to_be_bytes());
    record.extend(std::iter::repeat_n(0xab, len));
    record
}

/// A minimal DNS A-record query for `host` (RFC 1035 header + question).
fn dns_query(host: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(&[0x1a, 0x2b]); // transaction id
    msg.extend_from_slice(&[0x01, 0x00]); // flags: standard query, recursion desired
    msg.extend_from_slice(&[0x00, 0x01]); // qdcount = 1
    msg.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // an/ns/ar = 0
    for label in host.split('.') {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0x00); // root label
    msg.extend_from_slice(&[0x00, 0x01]); // qtype = A
    msg.extend_from_slice(&[0x00, 0x01]); // qclass = IN
    msg
}

/// A 24-bit big-endian length, as TLS handshake headers use.
fn u24_be(n: usize) -> [u8; 3] {
    [(n >> 16) as u8, (n >> 8) as u8, n as u8]
}

#[cfg(test)]
#[path = "packet_source_test.rs"]
mod packet_source_test;
