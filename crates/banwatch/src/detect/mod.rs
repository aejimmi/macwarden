//! Curated, typed detectors — the total parse boundary that turns a stream of
//! source events into failure [`Signal`](crate::record::Signal)s.
//!
//! macwarden deliberately ships a small set of named detectors instead of a
//! user-authored regex-jail system (see spec 010): attacker-controlled regex
//! over attacker-controlled log lines is exactly the surface we do not want.
//! Each analyzer is **total over attacker-influenced input** — a crafted line,
//! packet, or verdict never panics, never indexes out of bounds, and never
//! extracts a spoofed IP as the offender.
//!
//! - [`repeat_verdict`] — repeated deny verdicts from the daemon's own
//!   connection stream (no privilege).
//! - [`authlog`] — a parser from a unified-log `sshd` / Screen Sharing line to
//!   an auth failure or a redaction marker (opt-in; needs `log stream`).
//! - [`portscan`] — distinct-port / SYN-spray detection over typed
//!   `(ip, port, syn)` events (needs the BPF capture feed).

pub mod authlog;
pub mod portscan;
pub mod repeat_verdict;

pub use authlog::{AuthLine, parse_auth_failure};
pub use portscan::PortScanDetector;
pub use repeat_verdict::on_verdict;
