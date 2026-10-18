//! Cleartext TLS **handshake** parse (spec R4).
//!
//! Given a TCP payload that begins with a TLS record, this extracts the
//! Client Hello SNI + offered version/ciphers, the Server Hello negotiated
//! version + selected cipher, and (best-effort) a leaf certificate CN. It
//! **never decrypts**: an application-data record (`content_type = 0x17`)
//! yields only its content type and length — there is structurally no field
//! for a plaintext body (the Tier-1 boundary, spec R1).
//!
//! Every path is fallible-by-`Option`: truncated, split, or garbage input
//! returns `None` rather than panicking or reading out of bounds. It walks
//! attacker-controlled bytes in a root process, so it leans on the audited
//! `tls-parser` grammar and bounds every access.

use tls_parser::{
    TlsExtension, TlsMessage, TlsMessageHandshake, TlsRecordType, parse_tls_extensions,
    parse_tls_raw_record, parse_tls_record_with_header,
};

/// Which kind of TLS record this payload began with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsRecordKind {
    /// A cleartext handshake record (`0x16`).
    Handshake,
    /// Encrypted application data (`0x17`) — opaque at Tier 1.
    ApplicationData,
    /// Change-cipher-spec (`0x14`).
    ChangeCipherSpec,
    /// An alert (`0x15`).
    Alert,
    /// Any other/unknown content type.
    Other,
}

/// Which handshake message was recognised inside a handshake record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsHandshakeKind {
    /// Client Hello — carries the SNI, offered version and ciphers.
    ClientHello,
    /// Server Hello — carries the negotiated version and chosen cipher.
    ServerHello,
    /// A certificate message (leaf CN extracted best-effort).
    Certificate,
    /// Some other handshake message.
    Other,
}

/// Handshake-only TLS metadata extracted from a record. Holds **no decrypted
/// application data** by construction.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TlsInfo {
    /// The record's content type.
    pub record_kind: Option<TlsRecordKind>,
    /// The handshake message kind, when the record is a handshake.
    pub handshake_kind: Option<TlsHandshakeKind>,
    /// The Client Hello Server Name Indication hostname.
    pub sni: Option<String>,
    /// The offered (Client Hello) or negotiated (Server Hello) version label,
    /// e.g. `"TLS 1.2"`.
    pub version: Option<String>,
    /// Ciphers offered by a Client Hello, as IANA suite IDs.
    pub offered_ciphers: Vec<u16>,
    /// The cipher a Server Hello selected, by name if known.
    pub selected_cipher: Option<String>,
    /// A best-effort leaf-certificate common name, when a cleartext
    /// Certificate message is present (absent under TLS 1.3, where it is
    /// encrypted).
    pub cert_subject: Option<String>,
    /// For an application-data record: the record length only. **Never** a
    /// decoded body (spec R1).
    pub app_data_len: Option<usize>,
}

/// Parse the first TLS record at the start of a TCP payload. Returns `None`
/// when the bytes are not a recognisable TLS record (or are truncated).
#[must_use]
pub fn parse_tls(payload: &[u8]) -> Option<TlsInfo> {
    let (rest, raw) = parse_tls_raw_record(payload).ok()?;
    let _ = rest;
    let mut info = TlsInfo::default();
    match raw.hdr.record_type {
        TlsRecordType::ApplicationData => {
            // R1: length only — the encrypted body is never decoded or stored.
            info.record_kind = Some(TlsRecordKind::ApplicationData);
            info.app_data_len = Some(raw.data.len());
        }
        TlsRecordType::Handshake => {
            info.record_kind = Some(TlsRecordKind::Handshake);
            fill_handshake(&mut info, raw.data, raw.hdr);
        }
        TlsRecordType::ChangeCipherSpec => {
            info.record_kind = Some(TlsRecordKind::ChangeCipherSpec);
        }
        TlsRecordType::Alert => info.record_kind = Some(TlsRecordKind::Alert),
        _ => info.record_kind = Some(TlsRecordKind::Other),
    }
    Some(info)
}

/// Decode the handshake messages within a handshake record and populate the
/// relevant fields. A failure to parse the messages leaves `handshake_kind`
/// unset but is not fatal — the record kind is still reported.
fn fill_handshake(info: &mut TlsInfo, data: &[u8], hdr: tls_parser::TlsRecordHeader) {
    let Ok((_, messages)) = parse_tls_record_with_header(data, &hdr) else {
        return;
    };
    for msg in messages {
        let TlsMessage::Handshake(hs) = msg else {
            continue;
        };
        match hs {
            TlsMessageHandshake::ClientHello(ch) => {
                info.handshake_kind = Some(TlsHandshakeKind::ClientHello);
                info.version = Some(version_label(ch.version.0));
                info.offered_ciphers = ch.ciphers.iter().map(|c| c.0).collect();
                info.sni = ch.ext.and_then(extract_sni);
                return;
            }
            TlsMessageHandshake::ServerHello(sh) => {
                info.handshake_kind = Some(TlsHandshakeKind::ServerHello);
                info.version = Some(version_label(sh.version.0));
                info.selected_cipher = Some(cipher_label(sh.cipher.0));
                return;
            }
            TlsMessageHandshake::Certificate(cert) => {
                info.handshake_kind = Some(TlsHandshakeKind::Certificate);
                info.cert_subject = cert
                    .cert_chain
                    .first()
                    .and_then(|leaf| extract_cert_cn(leaf.data));
                return;
            }
            _ => info.handshake_kind = Some(TlsHandshakeKind::Other),
        }
    }
}

/// Pull the first SNI hostname out of the Client Hello extension block.
fn extract_sni(ext: &[u8]) -> Option<String> {
    let (_, extensions) = parse_tls_extensions(ext).ok()?;
    for e in extensions {
        if let TlsExtension::SNI(names) = e {
            for (_ty, host) in names {
                if let Ok(s) = std::str::from_utf8(host)
                    && !s.is_empty()
                {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Human label for a TLS version wire value.
fn version_label(v: u16) -> String {
    match v {
        0x0300 => "SSL 3.0".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0304 => "TLS 1.3".to_string(),
        other => format!("0x{other:04x}"),
    }
}

/// Human label for a cipher suite, falling back to its hex ID when unknown.
fn cipher_label(id: u16) -> String {
    tls_parser::TlsCipherSuite::from_id(id)
        .map_or_else(|| format!("0x{id:04x}"), |c| c.name.to_string())
}

/// Best-effort leaf-certificate common name. Scans DER for the commonName OID
/// (`2.5.4.3` = `06 03 55 04 03`) and reads the ASN.1 string that follows.
/// Bounded and returns `None` on any mismatch — this never parses untrusted
/// DER structurally; it is a display convenience only.
fn extract_cert_cn(der: &[u8]) -> Option<String> {
    const CN_OID: [u8; 5] = [0x06, 0x03, 0x55, 0x04, 0x03];
    let pos = der.windows(CN_OID.len()).position(|w| w == CN_OID)?;
    // After the OID: [string-tag][len][bytes]. Tag 0x0c (UTF8String),
    // 0x13 (PrintableString), 0x16 (IA5String) are the common CN encodings.
    let tag = der.get(pos + 5)?;
    if !matches!(tag, 0x0c | 0x13 | 0x14 | 0x16) {
        return None;
    }
    let len = *der.get(pos + 6)? as usize;
    let start = pos + 7;
    let bytes = der.get(start..start.checked_add(len)?)?;
    std::str::from_utf8(bytes).ok().map(str::to_string)
}

#[cfg(test)]
#[path = "tls_test.rs"]
mod tls_test;
