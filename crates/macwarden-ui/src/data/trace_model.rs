//! Pure view-model for the panel trace view (R11) — no GPUI, fully unit-tested.
//!
//! [`TraceModel`] holds the bounded ring of streamed [`WirePacketRecord`]s, the
//! active protocol [`ProtoFilter`], the selected packet, and its on-demand
//! [`WirePacketBytes`] detail. The GPUI trace view owns one and reads it every
//! render; the streaming worker (see [`super::trace`]) feeds records in via
//! [`TraceModel::extend`]. All list/filter/selection logic lives here so it can
//! be exercised without rendering.

use std::collections::VecDeque;
use std::ops::Range;

use ipc::protocol::{WireAppProto, WireL4Proto, WirePacketBytes, WirePacketRecord};

/// Maximum packets retained in the client-side ring. Older records are evicted
/// (bumping the drop counter, R6) so a busy app cannot grow the view unbounded.
pub const RING_CAP: usize = 512;

/// Bytes per hex-dump row.
const HEX_COLS: usize = 16;

/// Maximum raw bytes rendered in the hex pane, so a full-snaplen frame does not
/// produce thousands of rows. The pane scrolls within this bound.
pub const HEX_MAX: usize = 512;

/// The protocol filter tabs over the received packets (R11). `Errors` collects
/// ICMP / ARP / otherwise-unclassified frames — the "malformed / RST / error"
/// bucket in the Proxyman layout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProtoFilter {
    /// Everything.
    #[default]
    All,
    /// TCP transport.
    Tcp,
    /// UDP transport.
    Udp,
    /// DNS application protocol.
    Dns,
    /// Cleartext HTTP.
    Http,
    /// TLS (handshake visible; body opaque).
    Tls,
    /// ICMP / ARP / unclassified — the error bucket.
    Errors,
}

impl ProtoFilter {
    /// The tabs in display order.
    #[must_use]
    pub fn all() -> [ProtoFilter; 7] {
        [
            ProtoFilter::All,
            ProtoFilter::Tcp,
            ProtoFilter::Udp,
            ProtoFilter::Dns,
            ProtoFilter::Http,
            ProtoFilter::Tls,
            ProtoFilter::Errors,
        ]
    }

    /// The short tab label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ProtoFilter::All => "All",
            ProtoFilter::Tcp => "TCP",
            ProtoFilter::Udp => "UDP",
            ProtoFilter::Dns => "DNS",
            ProtoFilter::Http => "HTTP",
            ProtoFilter::Tls => "TLS",
            ProtoFilter::Errors => "Err",
        }
    }

    /// Whether a record passes this filter.
    #[must_use]
    pub fn matches(self, rec: &WirePacketRecord) -> bool {
        match self {
            ProtoFilter::All => true,
            ProtoFilter::Tcp => rec.proto == WireL4Proto::Tcp,
            ProtoFilter::Udp => rec.proto == WireL4Proto::Udp,
            ProtoFilter::Dns => rec.app_proto == WireAppProto::Dns,
            ProtoFilter::Http => rec.app_proto == WireAppProto::Http,
            ProtoFilter::Tls => rec.app_proto == WireAppProto::Tls,
            ProtoFilter::Errors => matches!(rec.proto, WireL4Proto::Icmp | WireL4Proto::Arp),
        }
    }
}

/// The effective protocol chip shown for a record: the application protocol when
/// identified (TLS/DNS/HTTP/QUIC), else the transport (TCP/UDP/ICMP/ARP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChipProto {
    /// TLS handshake / opaque body.
    Tls,
    /// DNS.
    Dns,
    /// Cleartext HTTP.
    Http,
    /// QUIC over UDP.
    Quic,
    /// Plain TCP.
    Tcp,
    /// Plain UDP.
    Udp,
    /// ICMP.
    Icmp,
    /// ARP.
    Arp,
    /// Anything else.
    Other,
}

impl ChipProto {
    /// Classify a record's most-specific protocol for the list chip.
    #[must_use]
    pub fn of(rec: &WirePacketRecord) -> ChipProto {
        match rec.app_proto {
            WireAppProto::Tls => ChipProto::Tls,
            WireAppProto::Dns => ChipProto::Dns,
            WireAppProto::Http => ChipProto::Http,
            WireAppProto::Quic => ChipProto::Quic,
            WireAppProto::Unknown => match rec.proto {
                WireL4Proto::Tcp => ChipProto::Tcp,
                WireL4Proto::Udp => ChipProto::Udp,
                WireL4Proto::Icmp => ChipProto::Icmp,
                WireL4Proto::Arp => ChipProto::Arp,
                WireL4Proto::Other => ChipProto::Other,
            },
        }
    }

    /// The chip label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            ChipProto::Tls => "TLS",
            ChipProto::Dns => "DNS",
            ChipProto::Http => "HTTP",
            ChipProto::Quic => "QUIC",
            ChipProto::Tcp => "TCP",
            ChipProto::Udp => "UDP",
            ChipProto::Icmp => "ICMP",
            ChipProto::Arp => "ARP",
            ChipProto::Other => "—",
        }
    }
}

/// One formatted hex-dump row: byte offset, the 16-byte hex column, and the
/// printable-ASCII gutter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexRow {
    /// The row's starting byte offset within the frame.
    pub offset: usize,
    /// The hex column, space-separated pairs (padded to a full row width).
    pub hex: String,
    /// The ASCII gutter (`.` for non-printable bytes).
    pub ascii: String,
    /// The byte range this row covers within the frame.
    pub range: Range<usize>,
}

/// Format `raw` (capped at [`HEX_MAX`]) into offset/hex/ASCII rows for the pane.
#[must_use]
pub fn hex_rows(raw: &[u8]) -> Vec<HexRow> {
    let shown = raw.len().min(HEX_MAX);
    raw.get(..shown)
        .unwrap_or(raw)
        .chunks(HEX_COLS)
        .enumerate()
        .map(|(i, chunk)| {
            let offset = i * HEX_COLS;
            HexRow {
                offset,
                hex: hex_column(chunk),
                ascii: ascii_gutter(chunk),
                range: offset..offset + chunk.len(),
            }
        })
        .collect()
}

/// The space-separated hex pairs for one row, right-padded so short final rows
/// keep the ASCII gutter aligned.
fn hex_column(chunk: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(HEX_COLS * 3);
    for (i, b) in chunk.iter().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let _ = write!(out, "{b:02x}");
    }
    for i in chunk.len()..HEX_COLS {
        if i > 0 {
            out.push(' ');
        }
        out.push_str("  ");
    }
    out
}

/// The printable-ASCII gutter for one row (`.` for control/non-ASCII bytes).
fn ascii_gutter(chunk: &[u8]) -> String {
    chunk
        .iter()
        .map(|&b| {
            if (0x20..0x7f).contains(&b) {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

/// The client-side trace state: the bounded packet ring, the active filter, and
/// the selected packet's fetched bytes (R11).
#[derive(Debug, Default)]
pub struct TraceModel {
    packets: VecDeque<WirePacketRecord>,
    total: u64,
    dropped: u64,
    filter: ProtoFilter,
    selected: Option<u64>,
    bytes: Option<WirePacketBytes>,
    bytes_loading: bool,
    /// Set when a byte fetch returned nothing (worker gone / timed out) — a
    /// terminal state distinct from "still loading" and from "no selection", so
    /// the detail pane never hangs on "Loading packet…".
    bytes_failed: bool,
    highlight: Option<Range<usize>>,
}

impl TraceModel {
    /// A fresh empty model.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one streamed record, evicting the oldest and bumping `dropped`
    /// when the ring is full (R6).
    pub fn push(&mut self, rec: WirePacketRecord) {
        self.total = self.total.saturating_add(1);
        if self.packets.len() >= RING_CAP {
            self.packets.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.packets.push_back(rec);
    }

    /// Append a batch of streamed records.
    pub fn extend(&mut self, recs: impl IntoIterator<Item = WirePacketRecord>) {
        for rec in recs {
            self.push(rec);
        }
    }

    /// The records passing the active filter, oldest first.
    #[must_use]
    pub fn visible(&self) -> Vec<&WirePacketRecord> {
        self.packets
            .iter()
            .filter(|r| self.filter.matches(r))
            .collect()
    }

    /// The lowest retained sequence number, if any (used by the auto-select
    /// debug hook and as a sensible default selection).
    #[must_use]
    pub fn first_seq(&self) -> Option<u64> {
        self.packets.front().map(|r| r.seq)
    }

    /// Total records received since the trace (or last [`Self::clear`]) started.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.total
    }

    /// The count currently retained in the ring.
    #[must_use]
    pub fn retained(&self) -> usize {
        self.packets.len()
    }

    /// Records dropped from the ring on overflow (R6).
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// The active protocol filter.
    #[must_use]
    pub fn filter(&self) -> ProtoFilter {
        self.filter
    }

    /// Switch the protocol filter tab.
    pub fn set_filter(&mut self, filter: ProtoFilter) {
        self.filter = filter;
    }

    /// The selected packet sequence number, if any.
    #[must_use]
    pub fn selected(&self) -> Option<u64> {
        self.selected
    }

    /// Select a packet and mark its bytes as loading (clears any prior detail).
    pub fn select(&mut self, seq: u64) {
        self.selected = Some(seq);
        self.bytes = None;
        self.highlight = None;
        self.bytes_loading = true;
        self.bytes_failed = false;
    }

    /// Whether the selected packet's bytes fetch is in flight.
    #[must_use]
    pub fn bytes_loading(&self) -> bool {
        self.bytes_loading
    }

    /// Whether the byte fetch failed terminally (no reply / timed out), so the
    /// detail pane shows a "couldn't load" message instead of hanging.
    #[must_use]
    pub fn bytes_failed(&self) -> bool {
        self.bytes_failed
    }

    /// Store the fetched bytes + decode tree for the selected packet.
    pub fn set_bytes(&mut self, bytes: WirePacketBytes) {
        self.bytes_loading = false;
        self.bytes_failed = false;
        self.bytes = Some(bytes);
    }

    /// Mark the byte fetch as terminally failed (worker gone / timed out) — a
    /// terminal state so the pane never stays stuck on "Loading packet…".
    pub fn fail_bytes(&mut self) {
        self.bytes_loading = false;
        self.bytes_failed = true;
        self.bytes = None;
    }

    /// The fetched bytes for the selected packet, if landed.
    #[must_use]
    pub fn bytes(&self) -> Option<&WirePacketBytes> {
        self.bytes.as_ref()
    }

    /// The decode-node byte range currently cross-highlighted in the hex pane.
    #[must_use]
    pub fn highlight(&self) -> Option<&Range<usize>> {
        self.highlight.as_ref()
    }

    /// Cross-highlight a decode node's byte range in the hex pane (R5). Toggles
    /// off when the same range is clicked again.
    pub fn toggle_highlight(&mut self, range: Range<usize>) {
        if self.highlight.as_ref() == Some(&range) {
            self.highlight = None;
        } else {
            self.highlight = Some(range);
        }
    }

    /// Clear the client-side list without stopping capture (R11 Clear control):
    /// drop retained packets and any selection, but keep the totals honest by
    /// resetting the received/dropped counters to zero for the fresh view.
    pub fn clear(&mut self) {
        self.packets.clear();
        self.total = 0;
        self.dropped = 0;
        self.selected = None;
        self.bytes = None;
        self.highlight = None;
        self.bytes_loading = false;
        self.bytes_failed = false;
    }
}

#[cfg(test)]
#[path = "trace_model_test.rs"]
mod trace_model_test;
