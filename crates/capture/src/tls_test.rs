#![allow(clippy::indexing_slicing, clippy::panic)]

use super::*;
use crate::testkit::{client_hello_record, server_hello_record};

#[test]
fn test_parse_tls_client_hello_extracts_exact_sni() {
    let record = client_hello_record("example.com");
    let info = parse_tls(&record).expect("client hello parses");
    assert_eq!(info.record_kind, Some(TlsRecordKind::Handshake));
    assert_eq!(info.handshake_kind, Some(TlsHandshakeKind::ClientHello));
    assert_eq!(info.sni.as_deref(), Some("example.com"));
    assert_eq!(info.version.as_deref(), Some("TLS 1.2"));
    assert_eq!(info.offered_ciphers, vec![0x1301]);
}

#[test]
fn test_parse_tls_client_hello_other_hostname() {
    let record = client_hello_record("tracker.evil.example");
    let info = parse_tls(&record).expect("client hello parses");
    assert_eq!(info.sni.as_deref(), Some("tracker.evil.example"));
}

#[test]
fn test_parse_tls_server_hello_version_and_cipher() {
    let record = server_hello_record();
    let info = parse_tls(&record).expect("server hello parses");
    assert_eq!(info.handshake_kind, Some(TlsHandshakeKind::ServerHello));
    assert_eq!(info.version.as_deref(), Some("TLS 1.2"));
    assert!(info.selected_cipher.is_some());
    // No SNI in a server hello.
    assert_eq!(info.sni, None);
}

#[test]
fn test_parse_tls_application_data_yields_length_only_no_body() {
    // content_type = 0x17 (application_data), version, length=4, then 4 opaque bytes.
    let record = vec![0x17, 0x03, 0x03, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];
    let info = parse_tls(&record).expect("application data record parses");
    assert_eq!(info.record_kind, Some(TlsRecordKind::ApplicationData));
    assert_eq!(info.app_data_len, Some(4));
    // R1: the encrypted body is never decoded — no handshake / sni surfaces.
    assert_eq!(info.sni, None);
    assert_eq!(info.handshake_kind, None);
}

#[test]
fn test_parse_tls_truncated_client_hello_returns_none_or_no_sni() {
    let full = client_hello_record("example.com");
    // Cut off inside the extensions (SNI split across a segment boundary).
    for cut in [5usize, 10, full.len() - 4] {
        let partial = &full[..cut.min(full.len())];
        match parse_tls(partial) {
            None => {}
            Some(info) => assert_ne!(info.sni.as_deref(), Some("example.com")),
        }
    }
}

#[test]
fn test_parse_tls_garbage_returns_none_without_panic() {
    for len in 0..64usize {
        let garbage: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let _ = parse_tls(&garbage);
    }
    assert!(parse_tls(&[]).is_none());
}
