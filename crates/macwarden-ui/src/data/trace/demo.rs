//! A synthetic packet source for the trace view — no socket, no root.
//!
//! [`DemoTraceBackend`] spawns a worker that emits deterministic
//! [`WirePacketRecord`]s on a timer (so the list fills live) and answers
//! `GetPacketBytes` from a matching [`WirePacketBytes`] built for the same
//! sequence number. Both record and bytes are pure functions of `seq`, so a
//! fetch is consistent whether or not the packet is still "in the ring". This
//! makes the whole trace view (list, filter, decode tree, hex) provable from
//! `--demo` on any platform.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError, channel};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipc::protocol::{
    WireAppProto, WireDecodeNode, WireDecodeTree, WireDirection, WireL4Proto, WirePacketBytes,
    WirePacketRecord, WireTraceSource,
};

use super::super::source::TraceBackend;
use super::{TraceCmd, TraceSession, session_from_parts};

/// How often the demo worker emits a synthetic packet.
const EMIT_INTERVAL: Duration = Duration::from_millis(120);

/// Packets seeded synchronously at session start so the list is never empty on
/// the first render.
const SEED_COUNT: u64 = 14;

/// One synthetic flow template.
struct Template {
    l4: WireL4Proto,
    app: WireAppProto,
    sni: Option<&'static str>,
    tls_version: Option<&'static str>,
    dst_ip: &'static str,
    port: u16,
}

/// The rotating set of plausible flows the demo cycles through.
const TEMPLATES: &[Template] = &[
    Template {
        l4: WireL4Proto::Tcp,
        app: WireAppProto::Tls,
        sni: Some("rr3---sn-googlevideo.com"),
        tls_version: Some("TLS 1.3"),
        dst_ip: "142.250.72.14",
        port: 443,
    },
    Template {
        l4: WireL4Proto::Udp,
        app: WireAppProto::Dns,
        sni: Some("analytics.example.com"),
        tls_version: None,
        dst_ip: "1.1.1.1",
        port: 53,
    },
    Template {
        l4: WireL4Proto::Tcp,
        app: WireAppProto::Tls,
        sni: Some("edge.slack.com"),
        tls_version: Some("TLS 1.3"),
        dst_ip: "3.89.11.200",
        port: 443,
    },
    Template {
        l4: WireL4Proto::Udp,
        app: WireAppProto::Quic,
        sni: Some("www.youtube.com"),
        tls_version: Some("TLS 1.3"),
        dst_ip: "142.250.72.14",
        port: 443,
    },
    Template {
        l4: WireL4Proto::Tcp,
        app: WireAppProto::Tls,
        sni: Some("stats.doubleclick.net"),
        tls_version: Some("TLS 1.2"),
        dst_ip: "172.217.14.98",
        port: 443,
    },
    Template {
        l4: WireL4Proto::Tcp,
        app: WireAppProto::Http,
        sni: Some("ocsp.apple.com"),
        tls_version: None,
        dst_ip: "17.253.144.10",
        port: 80,
    },
    Template {
        l4: WireL4Proto::Udp,
        app: WireAppProto::Dns,
        sni: Some("push.apple.com"),
        tls_version: None,
        dst_ip: "1.1.1.1",
        port: 53,
    },
    Template {
        l4: WireL4Proto::Tcp,
        app: WireAppProto::Tls,
        sni: Some("api.segment.io"),
        tls_version: Some("TLS 1.3"),
        dst_ip: "52.71.63.9",
        port: 443,
    },
];

/// The local host endpoint the synthetic flows originate from / return to.
const LOCAL_IP: &str = "192.168.1.42";

/// Whether a sequence number is a synthetic ICMP error (feeds the Errors tab).
fn is_error(seq: u64) -> bool {
    seq % 13 == 7
}

/// The current unix time in milliseconds.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default()
}

/// Build the synthetic light record for `seq` at capture time `timestamp_ms`.
#[must_use]
pub fn synthetic_record(seq: u64, timestamp_ms: u64) -> WirePacketRecord {
    if is_error(seq) {
        let ephemeral = 49_152 + (seq % 16_000) as u16;
        return WirePacketRecord {
            seq,
            timestamp_ms,
            src: "8.8.4.4".to_string(),
            dst: format!("{LOCAL_IP}:{ephemeral}"),
            proto: WireL4Proto::Icmp,
            length: 96,
            direction: WireDirection::In,
            app_proto: WireAppProto::Unknown,
            sni: None,
            tls_version: None,
            summary: "ICMP destination unreachable (port unreachable)".to_string(),
        };
    }
    let t = template(seq);
    let outbound = seq.is_multiple_of(2);
    let ephemeral = 49_152 + (seq % 16_000) as u16;
    let local = format!("{LOCAL_IP}:{ephemeral}");
    let remote = format!("{}:{}", t.dst_ip, t.port);
    let (src, dst, direction) = if outbound {
        (local, remote, WireDirection::Out)
    } else {
        (remote, local, WireDirection::In)
    };
    WirePacketRecord {
        seq,
        timestamp_ms,
        src,
        dst,
        proto: t.l4,
        length: 128 + (seq % 900) as u32,
        direction,
        app_proto: t.app,
        sni: t.sni.map(str::to_string),
        tls_version: t.tls_version.map(str::to_string),
        summary: summary(t, seq, outbound),
    }
}

/// The template for a (non-error) sequence number.
fn template(seq: u64) -> &'static Template {
    let idx = (seq as usize) % TEMPLATES.len();
    TEMPLATES
        .get(idx)
        .expect("idx is seq % len, always in range")
}

/// A Proxyman-style one-line summary.
fn summary(t: &Template, seq: u64, outbound: bool) -> String {
    let arrow = if outbound { "→" } else { "←" };
    match t.app {
        WireAppProto::Tls => format!(
            "{arrow} Client Hello  SNI={}  {}",
            t.sni.unwrap_or("?"),
            t.tls_version.unwrap_or("TLS")
        ),
        WireAppProto::Quic => format!("{arrow} QUIC Initial  {}", t.sni.unwrap_or("?")),
        WireAppProto::Dns => format!("{arrow} DNS query  {}", t.sni.unwrap_or("?")),
        WireAppProto::Http => format!("{arrow} GET http://{}/ping", t.sni.unwrap_or("?")),
        WireAppProto::Unknown => format!("{arrow} {} bytes", 128 + (seq % 900)),
    }
}

/// Build the synthetic heavy payload (raw bytes + decode tree) for `seq`.
#[must_use]
pub fn synthetic_bytes(seq: u64) -> WirePacketBytes {
    let rec = synthetic_record(seq, 0);
    let raw = synthetic_frame(&rec);
    let tree = decode_tree(&rec, &raw);
    WirePacketBytes {
        seq,
        available: true,
        raw,
        tree: Some(tree),
    }
}

/// Compose a plausible raw frame: Ethernet(14) + IPv4(20) + L4(20/8) + payload,
/// with the SNI/summary text embedded so the hex/ASCII gutter reads like real
/// cleartext handshake bytes.
fn synthetic_frame(rec: &WirePacketRecord) -> Vec<u8> {
    let mut raw = Vec::with_capacity(96);
    // Ethernet: dst MAC, src MAC, ethertype 0x0800 (IPv4).
    raw.extend_from_slice(&[0x3c, 0x22, 0xfb, 0x11, 0x22, 0x33]);
    raw.extend_from_slice(&[0xa4, 0x83, 0xe7, 0x44, 0x55, 0x66]);
    raw.extend_from_slice(&[0x08, 0x00]);
    // IPv4 header (20 bytes), version/IHL then a compact filler.
    raw.push(0x45);
    raw.extend_from_slice(&[0x00, 0x00, 0x3c, 0x1a, 0x2b, 0x40, 0x00, 0x40]);
    raw.push(match rec.proto {
        WireL4Proto::Udp => 17,
        WireL4Proto::Icmp => 1,
        _ => 6,
    });
    raw.extend_from_slice(&[0x00, 0x00, 0xc0, 0xa8, 0x01, 0x2a, 0x8e, 0xfa, 0x48, 0x0e]);
    // L4 header (TCP 20 / UDP 8 / ICMP 8), a compact filler for the demo.
    let l4_len = if rec.proto == WireL4Proto::Tcp { 20 } else { 8 };
    for i in 0..l4_len {
        raw.push(0x50u8.wrapping_add(i as u8));
    }
    // Application payload: the summary text, so the ASCII gutter reads clean.
    raw.extend_from_slice(rec.summary.as_bytes());
    raw
}

/// Build the Frame → Ethernet → IPv4 → L4 → app decode tree over `raw`.
fn decode_tree(rec: &WirePacketRecord, raw: &[u8]) -> WireDecodeTree {
    let l4_len = if rec.proto == WireL4Proto::Tcp { 20 } else { 8 };
    let l4_end = 34 + l4_len;
    let mut children = vec![
        node(
            "Ethernet II",
            "3c:22:fb:… → a4:83:e7:… (IPv4)",
            0..14,
            vec![],
        ),
        node(
            "IPv4",
            &format!("{} → {}", trim_ip(&rec.src), trim_ip(&rec.dst)),
            14..34,
            vec![
                ("Version", "4".into()),
                ("Header Length", "20".into()),
                ("Total Length", rec.length.to_string()),
            ],
        ),
        l4_node(rec, l4_len),
    ];
    if raw.len() > l4_end {
        children.push(app_node(rec, l4_end..raw.len()));
    }
    let root = WireDecodeNode {
        label: "Frame".to_string(),
        summary: format!("{} bytes on the wire", raw.len()),
        byte_range: 0..raw.len(),
        fields: vec![("Captured Length".into(), raw.len().to_string())],
        children,
    };
    WireDecodeTree { root }
}

/// The transport-layer decode node.
fn l4_node(rec: &WirePacketRecord, l4_len: usize) -> WireDecodeNode {
    let range = 34..34 + l4_len;
    match rec.proto {
        WireL4Proto::Tcp => node(
            "TCP",
            &format!("{} (PSH, ACK)", ports(rec)),
            range,
            vec![("Flags", "PSH, ACK".into()), ("Window", "65535".into())],
        ),
        WireL4Proto::Udp => node(
            "UDP",
            &ports(rec),
            range,
            vec![("Length", l4_len.to_string())],
        ),
        WireL4Proto::Icmp => node(
            "ICMP",
            "Type 3 (Destination Unreachable), Code 3",
            range,
            vec![("Type", "3".into()), ("Code", "3".into())],
        ),
        _ => node("Transport", "—", range, vec![]),
    }
}

/// The application-layer decode node (handshake metadata only — never a body).
fn app_node(rec: &WirePacketRecord, range: std::ops::Range<usize>) -> WireDecodeNode {
    match rec.app_proto {
        WireAppProto::Tls => node(
            "TLS",
            "Handshake: Client Hello",
            range,
            vec![
                ("Content Type", "Handshake (22)".into()),
                ("Version", rec.tls_version.clone().unwrap_or_default()),
                ("Server Name", rec.sni.clone().unwrap_or_default()),
            ],
        ),
        WireAppProto::Dns => node(
            "DNS",
            "Standard query A",
            range,
            vec![("Query", rec.sni.clone().unwrap_or_default())],
        ),
        WireAppProto::Http => node(
            "HTTP",
            "GET /ping HTTP/1.1",
            range,
            vec![("Host", rec.sni.clone().unwrap_or_default())],
        ),
        WireAppProto::Quic => node(
            "QUIC",
            "Initial packet (encrypted payload)",
            range,
            vec![("Server Name", rec.sni.clone().unwrap_or_default())],
        ),
        WireAppProto::Unknown => node("Payload", "raw application data", range, vec![]),
    }
}

/// The `ip:port → ip:port` label from the record endpoints.
fn ports(rec: &WirePacketRecord) -> String {
    format!("{} → {}", port_of(&rec.src), port_of(&rec.dst))
}

/// The port suffix of an `ip:port` endpoint (or the whole string if none).
fn port_of(ep: &str) -> &str {
    ep.rsplit(':').next().unwrap_or(ep)
}

/// Drop the port suffix of an `ip:port` endpoint for the IP-layer summary.
fn trim_ip(ep: &str) -> &str {
    ep.rsplit_once(':').map_or(ep, |(ip, _)| ip)
}

/// Construct a decode node.
fn node(
    label: &str,
    summary: &str,
    byte_range: std::ops::Range<usize>,
    fields: Vec<(&str, String)>,
) -> WireDecodeNode {
    WireDecodeNode {
        label: label.to_string(),
        summary: summary.to_string(),
        byte_range,
        fields: fields
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        children: Vec::new(),
    }
}

/// A [`TraceBackend`] that streams synthetic packets with no socket or root.
pub struct DemoTraceBackend;

impl TraceBackend for DemoTraceBackend {
    fn start_trace(&self, _app_id: &str) -> Option<TraceSession> {
        Some(demo_trace())
    }
}

/// Spawn a demo trace session: seed a first batch, then emit on a timer.
fn demo_trace() -> TraceSession {
    let (packets_tx, packets_rx) = channel();
    let (cmd_tx, cmd_rx) = channel();
    let stop = Arc::new(AtomicBool::new(false));
    for seq in 0..SEED_COUNT {
        let _ = packets_tx.send(synthetic_record(seq, now_ms()));
    }
    let worker_stop = Arc::clone(&stop);
    let worker = thread::Builder::new()
        .name("ui-trace-demo".into())
        .spawn(move || run_demo_worker(SEED_COUNT, &packets_tx, &cmd_rx, &worker_stop))
        .expect("spawn demo trace worker");
    // The panel's own `--demo` trace is synthetic and never touches a daemon, so
    // it reports "no capture compiled in" — the badge is honestly non-live.
    session_from_parts(
        packets_rx,
        cmd_tx,
        stop,
        worker,
        WireTraceSource::DemoNoCapture,
    )
}

/// The demo worker loop: emit a synthetic packet each interval and answer
/// `GetBytes` commands from the synthetic byte builder.
fn run_demo_worker(
    mut seq: u64,
    packets_tx: &std::sync::mpsc::Sender<WirePacketRecord>,
    cmd_rx: &Receiver<TraceCmd>,
    stop: &AtomicBool,
) {
    while !stop.load(Ordering::Relaxed) {
        match cmd_rx.try_recv() {
            Ok(TraceCmd::GetBytes { seq: want, reply }) => {
                let _ = reply.send(synthetic_bytes(want));
                continue;
            }
            Err(TryRecvError::Disconnected) => break,
            Err(TryRecvError::Empty) => {}
        }
        if packets_tx.send(synthetic_record(seq, now_ms())).is_err() {
            break;
        }
        seq += 1;
        thread::sleep(EMIT_INTERVAL);
    }
}
