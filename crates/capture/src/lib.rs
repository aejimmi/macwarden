//! `capture` — the pure, no-root packet-parse core of the packet-trace feature.
//!
//! This crate takes **raw packet bytes** (from a fixture or a live capture) and
//! produces parsed structures: a [`PacketRecord`] (addresses, ports, protocol,
//! direction, summary), cleartext-TLS-**handshake** metadata ([`TlsInfo`] — SNI,
//! version, cipher, best-effort cert CN), and a [`DecodeTree`] + [`hex_dump`]
//! for the inspector. It reuses the vendored sniffnet L2/L3/L4 parse path over
//! `etherparse` (see [`link`]) and the audited `tls-parser` grammar for TLS.
//!
//! # Stage boundary
//!
//! This is **stage 1**: pure parsing only. It has **zero** platform, root, or
//! Apple dependencies, so it builds and unit-tests on Linux CI entirely from
//! byte-slice / `.pcap`-style fixtures. Deferred to later stages:
//!
//! * **Stage 2** — live BPF/pcap capture, the 5-tuple BPF filter builder, the
//!   bounded ring buffer, and rate-limiting. This is the only part that needs
//!   root / `access_bpf` and is macOS-only + feature-gated.
//! * **Stage 3** — the IPC trace protocol (`crates/ipc` DTOs, `ServerFrame`).
//! * **Stage 4** — the daemon `TraceSession` lifecycle and server-push writer.
//! * **Stage 5** — the panel trace view.
//!
//! # Security
//!
//! The parser walks **attacker-controlled bytes** (in a root daemon, once
//! stage 2 lands). Every parse path is total: malformed, truncated, or
//! segment-split input yields a typed [`ParseError`] or `None`, never a panic
//! and never an out-of-bounds read. There is **no decryption** — the Tier-1
//! boundary is structural: [`PacketRecord`] and [`TlsInfo`] carry only handshake
//! metadata and there is nowhere for a decrypted HTTPS body to live (an
//! application-data record parses to `{ content_type, length }` only).
//!
//! Live capture (stage 2) will read `/dev/bpf*`, which requires **root or
//! membership in the `access_bpf` group** (the Wireshark "ChmodBPF"
//! convention); raw packet capture is forbidden in the App Store sandbox, so
//! the live feature is a **Developer-ID / non-MAS** capability. This stage-1
//! parse core imposes none of those requirements.
//!
//! # Stage 2 (this build)
//!
//! The pure filter builder ([`build_bpf_filter`]) and bounded buffering
//! ([`PacketRing`], [`RateLimiter`]) are always compiled and unit-tested without
//! root. The live [`CaptureSession`] — which opens a real BPF device — is gated
//! behind the `capture-live` feature **and** `target_os = "macos"`, so the
//! default build stays pure and Linux-CI-clean. The privileged daemon owns the
//! session; the panel never opens a BPF device.

mod bpf;
mod decode;
mod error;
mod link;
mod parse;
mod ring;
mod tls;
mod types;

#[cfg(all(feature = "capture-live", target_os = "macos"))]
mod session;

#[cfg(test)]
mod testkit;

pub use bpf::{FlowTuple, MATCH_NOTHING_FILTER, build_bpf_filter};
pub use decode::{DecodeNode, DecodeTree, decode_tree, hex_dump};
pub use error::ParseError;
pub use link::LinkType;
pub use parse::{PacketRecord, parse_frame};
pub use ring::{DEFAULT_MAX_BYTES, DEFAULT_MAX_PACKETS, PacketRing, RateLimiter, RingStats};
pub use tls::{TlsHandshakeKind, TlsInfo, TlsRecordKind, parse_tls};
pub use types::{AppProto, Direction, L4Proto, SocketEndpoint, Timestamp};

#[cfg(all(feature = "capture-live", target_os = "macos"))]
pub use session::{
    CaptureConfig, CaptureError, CaptureSession, CaptureStats, DEFAULT_RATE_LIMIT_PER_SEC,
    DEFAULT_SNAPLEN, DEFAULT_TIMEOUT_MS,
};
