//! Typed errors for the pure packet-parse layer.
//!
//! Parsing walks attacker-controlled bytes, so every failure is a typed
//! [`ParseError`] the caller treats as "skip this packet" — the parser never
//! panics and never reads out of bounds.

use thiserror::Error;

/// A recoverable failure while parsing one captured frame.
///
/// A caller feeding a stream of frames treats any `Err` as "skip this packet
/// and continue"; nothing here is fatal to a capture session.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// The link type is not one this crate knows how to strip (see
    /// [`crate::link::LinkType`]).
    #[error("unsupported link type: {0}")]
    UnsupportedLinkType(&'static str),

    /// The frame was too short to contain the declared link-layer header.
    #[error("frame too short for {layer} header: have {have} bytes")]
    TruncatedLink {
        /// The layer whose header could not be read.
        layer: &'static str,
        /// The number of bytes actually present.
        have: usize,
    },

    /// `etherparse` rejected the L2/L3/L4 headers (malformed or truncated).
    #[error("header parse failed: {0}")]
    Headers(String),

    /// Headers parsed but carried no usable network layer (e.g. an unhandled
    /// EtherType, or an ARP frame with a non-IP protocol address).
    #[error("no usable network-layer address in frame")]
    NoNetworkLayer,
}
