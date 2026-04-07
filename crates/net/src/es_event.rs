//! Parser for ES `RESERVED_5` network AUTH event payloads.
//!
//! The `ES_EVENT_TYPE_RESERVED_5` (type 153) event was reverse-engineered
//! by Patrick Wardle (March 2026). Apple has NOT documented this event.
//! The struct layout may change between macOS releases.
//!
//! This module provides a safe parser that converts raw event bytes into
//! a [`ParsedNetworkEvent`] with validated fields. All validation happens
//! before any field is used. If validation fails, the parser returns an
//! error so the caller can auto-allow and log a warning.
//!
//! # Byte layout (from Wardle's reverse engineering)
//!
//! ```text
//! Offset  Size  Field
//! 0x00    4     address_family     (AF_INET=2, AF_INET6=30)
//! 0x04    20    _padding1          (unknown/reserved)
//! 0x18    4     address_family2    (repeated)
//! 0x1c    4     resolved_ip        (IPv4 address, network byte order)
//! 0x20    32    _padding2          (unknown/reserved)
//! 0x40    4     hostname_len       (length of hostname string)
//! 0x44    12    _padding3          (unknown/reserved)
//! 0x50    256   hostname           (null-terminated hostname)
//! ```
//!
//! Total minimum size: `0x150` (336 bytes).
//!
//! # Safety
//!
//! This module contains NO unsafe code. It reads from `&[u8]` slices
//! using bounds-checked accessors. The `#[repr(C)]` struct is provided
//! for documentation and size assertions only -- actual parsing uses
//! manual byte reads for robustness against alignment issues.

use std::net::{IpAddr, Ipv4Addr};

use crate::connection::{AddressFamily, Destination};
use crate::error::NetError;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// `AF_INET` (IPv4) on macOS/Darwin.
const AF_INET: u32 = 2;

/// `AF_INET6` (IPv6) on macOS/Darwin.
const AF_INET6: u32 = 30;

/// Maximum hostname length we accept.
const MAX_HOSTNAME_LEN: u32 = 255;

/// Minimum event payload size (up through the hostname field).
const MIN_EVENT_SIZE: usize = 0x150; // 0x50 + 256

// ---------------------------------------------------------------------------
// Offsets
// ---------------------------------------------------------------------------

/// Byte offset of the `address_family` field.
const OFF_AF: usize = 0x00;

/// Byte offset of the `address_family2` field (repeated).
const OFF_AF2: usize = 0x18;

/// Byte offset of the `resolved_ip` field (4 bytes, IPv4).
const OFF_IP: usize = 0x1c;

/// Byte offset of the `hostname_len` field.
const OFF_HOSTNAME_LEN: usize = 0x40;

/// Byte offset of the `hostname` field (null-terminated, up to 256 bytes).
const OFF_HOSTNAME: usize = 0x50;

// ---------------------------------------------------------------------------
// RawNetworkEvent (repr(C) reference)
// ---------------------------------------------------------------------------

/// Reference layout for the ES `RESERVED_5` event payload.
///
/// This struct is NOT used for actual parsing (we use manual byte reads
/// for safety). It exists for documentation and `size_of` assertions.
#[repr(C)]
#[cfg(test)]
struct RawNetworkEvent {
    /// `AF_INET` (2) or `AF_INET6` (30).
    _address_family: u32,
    /// Unknown/reserved bytes.
    _padding1: [u8; 20],
    /// Repeated address family.
    _address_family2: u32,
    /// IPv4 resolved address (network byte order).
    _resolved_ip: [u8; 4],
    /// Unknown/reserved bytes. 32 bytes so `hostname_len` lands at 0x40.
    _padding2: [u8; 32],
    /// Length of the hostname string.
    _hostname_len: u32,
    /// Unknown/reserved bytes. 12 bytes so `hostname` lands at 0x50.
    _padding3: [u8; 12],
    /// Null-terminated hostname (up to 256 bytes including null).
    _hostname: [u8; 256],
}

// ---------------------------------------------------------------------------
// ParsedNetworkEvent
// ---------------------------------------------------------------------------

/// A validated network event extracted from raw ES `RESERVED_5` bytes.
///
/// All fields have been validated: address family is known, hostname is
/// valid UTF-8 and within length bounds, and the resolved IP is present.
#[derive(Debug, Clone)]
pub struct ParsedNetworkEvent {
    /// Address family (IPv4 or IPv6).
    pub address_family: AddressFamily,
    /// Resolved IPv4 address.
    pub resolved_ip: Ipv4Addr,
    /// Hostname string (may be empty if the event had no hostname).
    pub hostname: Option<String>,
}

impl ParsedNetworkEvent {
    /// Convert this parsed event into a [`Destination`] for the rule engine.
    ///
    /// Port and protocol are always `None` because the ES `RESERVED_5`
    /// event does not include them.
    pub fn to_destination(&self) -> Destination {
        Destination {
            host: self.hostname.clone(),
            ip: IpAddr::V4(self.resolved_ip),
            port: None,
            protocol: None,
            address_family: self.address_family,
        }
    }
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a raw ES `RESERVED_5` event payload into a validated struct.
///
/// # Validation
///
/// Before using any field, the parser checks:
/// - Buffer is at least [`MIN_EVENT_SIZE`] bytes
/// - `address_family` is `AF_INET` (2) or `AF_INET6` (30)
/// - `hostname_len` is less than [`MAX_HOSTNAME_LEN`]
/// - Hostname bytes (if present) are valid UTF-8
/// - Resolved IP is not all-zeros when no hostname is present
///
/// # Errors
///
/// Returns `NetError::InvalidRule` (repurposed as a parse error) if
/// any validation check fails. The caller should auto-allow the
/// connection and log a warning.
pub fn parse_reserved5_event(buf: &[u8]) -> Result<ParsedNetworkEvent, NetError> {
    // Size check.
    if buf.len() < MIN_EVENT_SIZE {
        return Err(parse_err(format!(
            "event buffer too small: {} bytes (need at least {MIN_EVENT_SIZE})",
            buf.len(),
        )));
    }

    // Address family.
    let af_raw = read_u32_le(buf, OFF_AF)?;
    let address_family = match af_raw {
        AF_INET => AddressFamily::Inet,
        AF_INET6 => AddressFamily::Inet6,
        other => {
            return Err(parse_err(format!(
                "unknown address family: {other} (expected {AF_INET} or {AF_INET6})",
            )));
        }
    };

    // Sanity: address_family2 should match.
    let af2_raw = read_u32_le(buf, OFF_AF2)?;
    if af2_raw != af_raw {
        return Err(parse_err(format!(
            "address_family mismatch: primary={af_raw}, secondary={af2_raw}",
        )));
    }

    // Resolved IP.
    let ip_bytes = read_4bytes(buf, OFF_IP)?;
    let resolved_ip = Ipv4Addr::new(ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);

    // Hostname length.
    let hostname_len = read_u32_le(buf, OFF_HOSTNAME_LEN)?;
    if hostname_len > MAX_HOSTNAME_LEN {
        return Err(parse_err(format!(
            "hostname_len too large: {hostname_len} (max {MAX_HOSTNAME_LEN})",
        )));
    }

    // Hostname.
    let hostname = if hostname_len > 0 {
        let end = OFF_HOSTNAME + hostname_len as usize;
        if end > buf.len() {
            return Err(parse_err(format!(
                "hostname extends past buffer: offset {OFF_HOSTNAME} + len {hostname_len} > {}",
                buf.len(),
            )));
        }
        let raw = buf.get(OFF_HOSTNAME..end).ok_or_else(|| {
            parse_err(format!(
                "hostname slice out of bounds: {OFF_HOSTNAME}..{end}",
            ))
        })?;
        // Trim any null terminators.
        let trimmed = trim_nulls(raw);
        if trimmed.is_empty() {
            None
        } else {
            let s = std::str::from_utf8(trimmed)
                .map_err(|e| parse_err(format!("hostname is not valid UTF-8: {e}")))?;
            Some(s.to_owned())
        }
    } else {
        None
    };

    // If no hostname, the resolved IP must not be all-zeros.
    if hostname.is_none() && resolved_ip == Ipv4Addr::UNSPECIFIED {
        return Err(parse_err(
            "no hostname and resolved IP is 0.0.0.0 -- unusable event".to_owned(),
        ));
    }

    Ok(ParsedNetworkEvent {
        address_family,
        resolved_ip,
        hostname,
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a little-endian u32 from a byte slice at the given offset.
///
/// Returns `NetError` if the slice is too short.
fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32, NetError> {
    let chunk: &[u8] = buf
        .get(offset..offset + 4)
        .ok_or_else(|| parse_err(format!("buffer too short for u32 at offset {offset:#x}")))?;
    // chunk is exactly 4 bytes; try_into cannot fail.
    let arr: [u8; 4] = chunk
        .try_into()
        .map_err(|_| parse_err(format!("slice conversion failed at offset {offset:#x}")))?;
    Ok(u32::from_le_bytes(arr))
}

/// Read 4 bytes from a buffer at the given offset.
///
/// Returns `NetError` if the slice is too short.
fn read_4bytes(buf: &[u8], offset: usize) -> Result<[u8; 4], NetError> {
    let chunk: &[u8] = buf.get(offset..offset + 4).ok_or_else(|| {
        parse_err(format!(
            "buffer too short for 4 bytes at offset {offset:#x}"
        ))
    })?;
    chunk
        .try_into()
        .map_err(|_| parse_err(format!("slice conversion failed at offset {offset:#x}")))
}

/// Trim trailing null bytes from a slice.
fn trim_nulls(bytes: &[u8]) -> &[u8] {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    bytes.get(..end).unwrap_or(bytes)
}

/// Construct a parse error.
fn parse_err(message: String) -> NetError {
    NetError::InvalidRule { message }
}

// ---------------------------------------------------------------------------
// Static assertions
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::ref_as_ptr, clippy::borrow_as_ptr)]
mod layout_assertions {
    use super::*;

    /// Verify that the `#[repr(C)]` struct has the expected size and
    /// that fields land at the documented offsets.
    #[test]
    fn test_raw_layout_size() {
        // 4 + 20 + 4 + 4 + 32 + 4 + 12 + 256 = 336 = 0x150
        assert_eq!(
            std::mem::size_of::<RawNetworkEvent>(),
            MIN_EVENT_SIZE,
            "RawNetworkEvent size must be exactly {MIN_EVENT_SIZE} (0x{MIN_EVENT_SIZE:x})",
        );
    }

    /// Verify field offsets via pointer arithmetic on a zeroed struct.
    #[test]
    fn test_raw_layout_offsets() {
        let event = RawNetworkEvent {
            _address_family: 0,
            _padding1: [0; 20],
            _address_family2: 0,
            _resolved_ip: [0; 4],
            _padding2: [0; 32],
            _hostname_len: 0,
            _padding3: [0; 12],
            _hostname: [0; 256],
        };
        let base = &event as *const RawNetworkEvent as usize;

        let af_off = &event._address_family as *const u32 as usize - base;
        assert_eq!(af_off, OFF_AF, "address_family offset");

        let af2_off = &event._address_family2 as *const u32 as usize - base;
        assert_eq!(af2_off, OFF_AF2, "address_family2 offset");

        let ip_off = event._resolved_ip.as_ptr() as usize - base;
        assert_eq!(ip_off, OFF_IP, "resolved_ip offset");

        let hl_off = &event._hostname_len as *const u32 as usize - base;
        assert_eq!(hl_off, OFF_HOSTNAME_LEN, "hostname_len offset");

        let hn_off = event._hostname.as_ptr() as usize - base;
        assert_eq!(hn_off, OFF_HOSTNAME, "hostname offset");
    }
}

#[cfg(test)]
#[path = "es_event_test.rs"]
mod es_event_test;
