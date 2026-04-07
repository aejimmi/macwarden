#![allow(clippy::indexing_slicing)] // Tests assert length before indexing.

use super::*;

use std::net::{Ipv4Addr, Ipv6Addr};

use parser::{DnsAnswer, DnsParseError, parse_dns_response};

// ---------------------------------------------------------------------------
// Helper: build a minimal DNS response packet from parts
// ---------------------------------------------------------------------------

/// Build a DNS header.
fn header(id: u16, flags: u16, qdcount: u16, ancount: u16) -> Vec<u8> {
    let mut h = Vec::with_capacity(12);
    h.extend_from_slice(&id.to_be_bytes());
    h.extend_from_slice(&flags.to_be_bytes());
    h.extend_from_slice(&qdcount.to_be_bytes());
    h.extend_from_slice(&ancount.to_be_bytes());
    h.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    h.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    h
}

/// Encode a DNS name as a sequence of labels (no compression).
fn encode_name(name: &str) -> Vec<u8> {
    let mut buf = Vec::new();
    for label in name.split('.') {
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0); // terminator
    buf
}

/// Build a question section entry.
fn question(name: &str, qtype: u16) -> Vec<u8> {
    let mut q = encode_name(name);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&1u16.to_be_bytes()); // QCLASS IN
    q
}

/// Build an answer resource record with arbitrary rdata.
fn answer_rr(name_bytes: &[u8], rtype: u16, ttl: u32, rdata: &[u8]) -> Vec<u8> {
    let mut rr = Vec::new();
    rr.extend_from_slice(name_bytes);
    rr.extend_from_slice(&rtype.to_be_bytes());
    rr.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    rr.extend_from_slice(&ttl.to_be_bytes());
    rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    rr.extend_from_slice(rdata);
    rr
}

// Standard response flags: QR=1, OPCODE=0, AA=1, RCODE=0 -> 0x8400
// Alternative: QR=1, RD=1, RA=1 -> 0x8180
const RESPONSE_FLAGS: u16 = 0x8180;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_parse_a_record_single() {
    // Response for example.com -> 93.184.216.34
    let mut pkt = header(0x1234, RESPONSE_FLAGS, 1, 1);
    pkt.extend_from_slice(&question("example.com", 1));

    // Answer: pointer to question name (offset 12 = 0x0C)
    let name_ptr = [0xC0, 0x0C];
    let rdata = [93, 184, 216, 34];
    pkt.extend_from_slice(&answer_rr(&name_ptr, 1, 300, &rdata));

    let resp = parse_dns_response(&pkt).expect("should parse");
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(
        resp.answers[0],
        DnsAnswer::A {
            name: "example.com".to_owned(),
            ip: Ipv4Addr::new(93, 184, 216, 34),
            ttl: 300,
        }
    );
}

#[test]
fn test_parse_aaaa_record_single() {
    // Response for ipv6.example.com -> 2001:db8::1
    let mut pkt = header(0xABCD, RESPONSE_FLAGS, 1, 1);
    pkt.extend_from_slice(&question("ipv6.example.com", 28));

    let name_ptr = [0xC0, 0x0C];
    let ip6 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1);
    let rdata = ip6.octets();
    pkt.extend_from_slice(&answer_rr(&name_ptr, 28, 600, &rdata));

    let resp = parse_dns_response(&pkt).expect("should parse");
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(
        resp.answers[0],
        DnsAnswer::Aaaa {
            name: "ipv6.example.com".to_owned(),
            ip: ip6,
            ttl: 600,
        }
    );
}

#[test]
fn test_parse_multiple_a_answers() {
    // Two A records for multi.example.com
    let mut pkt = header(0x0001, RESPONSE_FLAGS, 1, 2);
    pkt.extend_from_slice(&question("multi.example.com", 1));

    let name_ptr = [0xC0, 0x0C];
    pkt.extend_from_slice(&answer_rr(&name_ptr, 1, 120, &[1, 2, 3, 4]));
    pkt.extend_from_slice(&answer_rr(&name_ptr, 1, 120, &[5, 6, 7, 8]));

    let resp = parse_dns_response(&pkt).expect("should parse");
    assert_eq!(resp.answers.len(), 2);
    assert_eq!(
        resp.answers[0],
        DnsAnswer::A {
            name: "multi.example.com".to_owned(),
            ip: Ipv4Addr::new(1, 2, 3, 4),
            ttl: 120,
        }
    );
    assert_eq!(
        resp.answers[1],
        DnsAnswer::A {
            name: "multi.example.com".to_owned(),
            ip: Ipv4Addr::new(5, 6, 7, 8),
            ttl: 120,
        }
    );
}

#[test]
fn test_parse_cname_then_a_record() {
    // www.example.com CNAME example.com, then example.com A 93.184.216.34
    let mut pkt = header(0x5678, RESPONSE_FLAGS, 1, 2);
    let q = question("www.example.com", 1);
    pkt.extend_from_slice(&q);

    // CNAME answer: pointer to question name, rdata is the canonical name
    let name_ptr = [0xC0, 0x0C];
    let cname_rdata = encode_name("example.com");
    pkt.extend_from_slice(&answer_rr(&name_ptr, 5, 3600, &cname_rdata));

    // A answer: inline name "example.com"
    let a_name = encode_name("example.com");
    pkt.extend_from_slice(&answer_rr(&a_name, 1, 300, &[93, 184, 216, 34]));

    let resp = parse_dns_response(&pkt).expect("should parse");
    assert_eq!(resp.answers.len(), 2);
    assert_eq!(
        resp.answers[0],
        DnsAnswer::Cname {
            name: "www.example.com".to_owned(),
            cname: "example.com".to_owned(),
            ttl: 3600,
        }
    );
    assert_eq!(
        resp.answers[1],
        DnsAnswer::A {
            name: "example.com".to_owned(),
            ip: Ipv4Addr::new(93, 184, 216, 34),
            ttl: 300,
        }
    );
}

#[test]
fn test_parse_compressed_name_pointer() {
    // Build a response where the answer name uses a pointer back into the
    // question section. This is the most common compression pattern.
    let mut pkt = header(0x9999, RESPONSE_FLAGS, 1, 1);
    let q = question("compress.test.org", 1);
    // Question name starts at offset 12 in the packet.
    pkt.extend_from_slice(&q);

    // Answer name: pointer 0xC00C -> offset 12 -> "compress.test.org"
    let name_ptr = [0xC0, 0x0C];
    pkt.extend_from_slice(&answer_rr(&name_ptr, 1, 60, &[10, 20, 30, 40]));

    let resp = parse_dns_response(&pkt).expect("should parse");
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(
        resp.answers[0],
        DnsAnswer::A {
            name: "compress.test.org".to_owned(),
            ip: Ipv4Addr::new(10, 20, 30, 40),
            ttl: 60,
        }
    );
}

#[test]
fn test_parse_not_response_returns_error() {
    // Query packet: QR=0 (flags = 0x0100 = RD=1, QR=0)
    let pkt = header(0x0001, 0x0100, 1, 0);
    let err = parse_dns_response(&pkt).unwrap_err();
    assert!(matches!(err, DnsParseError::NotResponse));
}

#[test]
fn test_parse_too_short_returns_error() {
    // Less than 12 bytes.
    let pkt = vec![0u8; 6];
    let err = parse_dns_response(&pkt).unwrap_err();
    assert!(matches!(err, DnsParseError::TooShort(6)));
}

#[test]
fn test_parse_empty_returns_error() {
    let err = parse_dns_response(&[]).unwrap_err();
    assert!(matches!(err, DnsParseError::TooShort(0)));
}

#[test]
fn test_parse_truncated_response_returns_empty() {
    // TC bit set: flags = 0x8200 (QR=1, TC=1)
    let pkt = header(0x0001, 0x8200, 0, 0);
    let resp = parse_dns_response(&pkt).expect("should parse (empty)");
    assert!(resp.answers.is_empty());
}

#[test]
fn test_parse_rcode_nonzero_returns_empty() {
    // RCODE=3 (NXDOMAIN): flags = 0x8183 (QR=1, RD=1, RA=1, RCODE=3)
    let pkt = header(0x0001, 0x8183, 0, 0);
    let resp = parse_dns_response(&pkt).expect("should parse (empty)");
    assert!(resp.answers.is_empty());
}

#[test]
fn test_parse_pointer_depth_exceeded() {
    // Construct a packet with a self-referencing pointer to trigger depth limit.
    let mut pkt = header(0x0001, RESPONSE_FLAGS, 0, 1);

    // Answer at offset 12: name is a pointer to itself (offset 12 = 0x0C)
    let self_ptr = [0xC0, 0x0C];
    // TYPE=1, CLASS=1, TTL=60, RDLENGTH=4, RDATA=1.2.3.4
    pkt.extend_from_slice(&self_ptr);
    pkt.extend_from_slice(&1u16.to_be_bytes()); // TYPE A
    pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    pkt.extend_from_slice(&60u32.to_be_bytes()); // TTL
    pkt.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
    pkt.extend_from_slice(&[1, 2, 3, 4]); // RDATA

    let err = parse_dns_response(&pkt).unwrap_err();
    assert!(matches!(err, DnsParseError::InvalidName(_)));
}

#[test]
fn test_parse_skips_unknown_record_types() {
    // One MX record (type 15) + one A record. MX should be skipped.
    let mut pkt = header(0x0002, RESPONSE_FLAGS, 1, 2);
    pkt.extend_from_slice(&question("skip.example.com", 1));

    let name_ptr = [0xC0, 0x0C];

    // MX record: preference(2) + exchange name
    let mut mx_rdata = Vec::new();
    mx_rdata.extend_from_slice(&10u16.to_be_bytes()); // preference
    mx_rdata.extend_from_slice(&encode_name("mail.example.com"));
    pkt.extend_from_slice(&answer_rr(&name_ptr, 15, 300, &mx_rdata));

    // A record
    pkt.extend_from_slice(&answer_rr(&name_ptr, 1, 120, &[11, 22, 33, 44]));

    let resp = parse_dns_response(&pkt).expect("should parse");
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(
        resp.answers[0],
        DnsAnswer::A {
            name: "skip.example.com".to_owned(),
            ip: Ipv4Addr::new(11, 22, 33, 44),
            ttl: 120,
        }
    );
}

#[test]
fn test_parse_no_questions_no_answers() {
    // Valid response with 0 questions and 0 answers.
    let pkt = header(0x0003, RESPONSE_FLAGS, 0, 0);
    let resp = parse_dns_response(&pkt).expect("should parse");
    assert!(resp.answers.is_empty());
}

#[test]
fn test_parse_inline_name_no_compression() {
    // Answer with a fully inline name (no compression pointers).
    let mut pkt = header(0x0004, RESPONSE_FLAGS, 0, 1);

    let name = encode_name("no.compress.dev");
    pkt.extend_from_slice(&answer_rr(&name, 1, 42, &[192, 168, 1, 1]));

    let resp = parse_dns_response(&pkt).expect("should parse");
    assert_eq!(resp.answers.len(), 1);
    assert_eq!(
        resp.answers[0],
        DnsAnswer::A {
            name: "no.compress.dev".to_owned(),
            ip: Ipv4Addr::new(192, 168, 1, 1),
            ttl: 42,
        }
    );
}
