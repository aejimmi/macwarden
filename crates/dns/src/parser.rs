//! DNS wire format response parser (RFC 1035).
//!
//! Parses DNS response packets and extracts A, AAAA, and CNAME answer
//! records. Only processes responses (QR=1) with no errors (RCODE=0)
//! and no truncation (TC=0).

use std::net::{Ipv4Addr, Ipv6Addr};

/// Maximum pointer follow depth to prevent infinite loops from malformed packets.
const MAX_POINTER_DEPTH: u8 = 16;

/// DNS header size in bytes.
const HEADER_SIZE: usize = 12;

/// DNS record type: A (IPv4 address).
const TYPE_A: u16 = 1;

/// DNS record type: CNAME (canonical name).
const TYPE_CNAME: u16 = 5;

/// DNS record type: AAAA (IPv6 address).
const TYPE_AAAA: u16 = 28;

/// A record data length (4 bytes for IPv4).
const A_RDATA_LEN: u16 = 4;

/// AAAA record data length (16 bytes for IPv6).
const AAAA_RDATA_LEN: u16 = 16;

/// Errors that can occur while parsing a DNS response packet.
#[derive(Debug, thiserror::Error)]
pub enum DnsParseError {
    /// Packet is shorter than the minimum DNS header size (12 bytes).
    #[error("packet too short: {0} bytes (minimum {HEADER_SIZE})")]
    TooShort(usize),

    /// Packet is not a DNS response (QR bit is 0).
    #[error("packet is a query, not a response")]
    NotResponse,

    /// A domain name label or pointer is invalid.
    #[error("invalid domain name at offset {0}")]
    InvalidName(usize),

    /// A resource record is malformed or truncated.
    #[error("invalid resource record at offset {0}")]
    InvalidRecord(usize),
}

/// Parsed DNS response containing answer records.
#[derive(Debug, Clone)]
pub struct DnsResponse {
    /// Answer records extracted from the response.
    pub answers: Vec<DnsAnswer>,
}

/// A single DNS answer record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsAnswer {
    /// A record: hostname to IPv4 address.
    A {
        /// The queried domain name.
        name: String,
        /// Resolved IPv4 address.
        ip: Ipv4Addr,
        /// Time-to-live in seconds.
        ttl: u32,
    },
    /// AAAA record: hostname to IPv6 address.
    Aaaa {
        /// The queried domain name.
        name: String,
        /// Resolved IPv6 address.
        ip: Ipv6Addr,
        /// Time-to-live in seconds.
        ttl: u32,
    },
    /// CNAME record: alias to canonical name.
    Cname {
        /// The alias domain name.
        name: String,
        /// The canonical (target) domain name.
        cname: String,
        /// Time-to-live in seconds.
        ttl: u32,
    },
}

/// Parse a DNS response packet from raw UDP payload bytes.
///
/// Returns the extracted answer records (A, AAAA, CNAME). Records of
/// other types are silently skipped. Returns an empty answer set for
/// truncated responses (TC=1) or responses with RCODE != 0.
///
/// # Errors
///
/// Returns [`DnsParseError`] if the packet is too short, is not a
/// response, or contains malformed names/records.
pub fn parse_dns_response(data: &[u8]) -> Result<DnsResponse, DnsParseError> {
    if data.len() < HEADER_SIZE {
        return Err(DnsParseError::TooShort(data.len()));
    }

    let flags = read_u16(data, 2)?;

    // QR bit (bit 15) must be 1 for a response.
    if flags & 0x8000 == 0 {
        return Err(DnsParseError::NotResponse);
    }

    // TC bit (bit 9) -- truncated response, skip.
    if flags & 0x0200 != 0 {
        return Ok(DnsResponse {
            answers: Vec::new(),
        });
    }

    // RCODE (bits 0-3) must be 0 (NOERROR).
    if flags & 0x000F != 0 {
        return Ok(DnsResponse {
            answers: Vec::new(),
        });
    }

    let qdcount = read_u16(data, 4)? as usize;
    let ancount = read_u16(data, 6)? as usize;

    // Skip past question section.
    let mut offset = HEADER_SIZE;
    for _ in 0..qdcount {
        offset = skip_name(data, offset)?;
        // QTYPE (2) + QCLASS (2)
        offset = advance(data, offset, 4)?;
    }

    // Parse answer section.
    let mut answers = Vec::with_capacity(ancount);
    for _ in 0..ancount {
        let (answer, next_offset) = parse_resource_record(data, offset)?;
        if let Some(a) = answer {
            answers.push(a);
        }
        offset = next_offset;
    }

    Ok(DnsResponse { answers })
}

/// Parse a single resource record starting at `offset`.
/// Returns the parsed answer (if it's a type we care about) and the
/// offset past this record.
fn parse_resource_record(
    data: &[u8],
    offset: usize,
) -> Result<(Option<DnsAnswer>, usize), DnsParseError> {
    let name = read_name(data, offset)?;
    let name_end = skip_name(data, offset)?;

    // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) = 10 bytes after name
    if data.len() < name_end + 10 {
        return Err(DnsParseError::InvalidRecord(offset));
    }

    let rtype = read_u16(data, name_end)?;
    // class at name_end + 2 (we don't need it)
    let ttl = read_u32(data, name_end + 4)?;
    let rdlength = read_u16(data, name_end + 8)? as usize;
    let rdata_start = name_end + 10;
    let rdata_end = rdata_start + rdlength;

    if data.len() < rdata_end {
        return Err(DnsParseError::InvalidRecord(offset));
    }

    let answer = match rtype {
        TYPE_A => {
            if rdlength != A_RDATA_LEN as usize {
                return Err(DnsParseError::InvalidRecord(rdata_start));
            }
            let octets: [u8; 4] = [
                *data
                    .get(rdata_start)
                    .ok_or(DnsParseError::InvalidRecord(rdata_start))?,
                *data
                    .get(rdata_start + 1)
                    .ok_or(DnsParseError::InvalidRecord(rdata_start))?,
                *data
                    .get(rdata_start + 2)
                    .ok_or(DnsParseError::InvalidRecord(rdata_start))?,
                *data
                    .get(rdata_start + 3)
                    .ok_or(DnsParseError::InvalidRecord(rdata_start))?,
            ];
            Some(DnsAnswer::A {
                name,
                ip: Ipv4Addr::from(octets),
                ttl,
            })
        }
        TYPE_AAAA => {
            if rdlength != AAAA_RDATA_LEN as usize {
                return Err(DnsParseError::InvalidRecord(rdata_start));
            }
            let mut octets = [0u8; 16];
            for (i, byte) in octets.iter_mut().enumerate() {
                *byte = *data
                    .get(rdata_start + i)
                    .ok_or(DnsParseError::InvalidRecord(rdata_start))?;
            }
            Some(DnsAnswer::Aaaa {
                name,
                ip: Ipv6Addr::from(octets),
                ttl,
            })
        }
        TYPE_CNAME => {
            let cname = read_name(data, rdata_start)?;
            Some(DnsAnswer::Cname { name, cname, ttl })
        }
        _ => None, // Skip unknown record types.
    };

    Ok((answer, rdata_end))
}

/// Read a DNS domain name starting at `offset`, following compression pointers.
fn read_name(data: &[u8], offset: usize) -> Result<String, DnsParseError> {
    let mut name = String::with_capacity(64);
    read_name_inner(data, offset, &mut name, 0)?;

    // Remove trailing dot if present.
    if name.ends_with('.') {
        name.pop();
    }

    if name.is_empty() {
        return Err(DnsParseError::InvalidName(offset));
    }

    Ok(name)
}

/// Recursive name reader with pointer depth tracking.
fn read_name_inner(
    data: &[u8],
    mut offset: usize,
    name: &mut String,
    depth: u8,
) -> Result<(), DnsParseError> {
    if depth > MAX_POINTER_DEPTH {
        return Err(DnsParseError::InvalidName(offset));
    }

    loop {
        let label_byte = *data.get(offset).ok_or(DnsParseError::InvalidName(offset))?;

        if label_byte == 0 {
            // End of name.
            break;
        }

        // Compression pointer: top two bits are 11.
        if label_byte & 0xC0 == 0xC0 {
            let next_byte = *data
                .get(offset + 1)
                .ok_or(DnsParseError::InvalidName(offset))?;
            let pointer = (u16::from(label_byte & 0x3F) << 8) | u16::from(next_byte);
            return read_name_inner(data, pointer as usize, name, depth + 1);
        }

        // Regular label.
        let label_len = label_byte as usize;
        if label_len > 63 {
            return Err(DnsParseError::InvalidName(offset));
        }

        let label_start = offset + 1;
        let label_end = label_start + label_len;
        if label_end > data.len() {
            return Err(DnsParseError::InvalidName(offset));
        }

        // Total name must not exceed 253 characters.
        if name.len() + label_len + 1 > 254 {
            return Err(DnsParseError::InvalidName(offset));
        }

        for i in label_start..label_end {
            let ch = *data.get(i).ok_or(DnsParseError::InvalidName(i))?;
            name.push(ch as char);
        }
        name.push('.');

        offset = label_end;
    }

    Ok(())
}

/// Skip past a DNS name (following pointer boundaries but not recursing into them).
/// Returns the offset immediately after the name.
fn skip_name(data: &[u8], mut offset: usize) -> Result<usize, DnsParseError> {
    loop {
        let label_byte = *data.get(offset).ok_or(DnsParseError::InvalidName(offset))?;

        if label_byte == 0 {
            return Ok(offset + 1);
        }

        // Compression pointer: 2 bytes total, done.
        if label_byte & 0xC0 == 0xC0 {
            return Ok(offset + 2);
        }

        let label_len = label_byte as usize;
        offset = offset + 1 + label_len;

        if offset > data.len() {
            return Err(DnsParseError::InvalidName(offset));
        }
    }
}

/// Read a big-endian u16 at the given offset.
fn read_u16(data: &[u8], offset: usize) -> Result<u16, DnsParseError> {
    let hi = *data
        .get(offset)
        .ok_or(DnsParseError::TooShort(data.len()))?;
    let lo = *data
        .get(offset + 1)
        .ok_or(DnsParseError::TooShort(data.len()))?;
    Ok(u16::from(hi) << 8 | u16::from(lo))
}

/// Read a big-endian u32 at the given offset.
fn read_u32(data: &[u8], offset: usize) -> Result<u32, DnsParseError> {
    let a = *data
        .get(offset)
        .ok_or(DnsParseError::TooShort(data.len()))?;
    let b = *data
        .get(offset + 1)
        .ok_or(DnsParseError::TooShort(data.len()))?;
    let c = *data
        .get(offset + 2)
        .ok_or(DnsParseError::TooShort(data.len()))?;
    let d = *data
        .get(offset + 3)
        .ok_or(DnsParseError::TooShort(data.len()))?;
    Ok(u32::from(a) << 24 | u32::from(b) << 16 | u32::from(c) << 8 | u32::from(d))
}

/// Advance the offset by `count` bytes, returning an error if out of bounds.
fn advance(data: &[u8], offset: usize, count: usize) -> Result<usize, DnsParseError> {
    let next = offset + count;
    if next > data.len() {
        return Err(DnsParseError::InvalidRecord(offset));
    }
    Ok(next)
}
