//! Test-only fixture builders — synthesize packet bytes with `etherparse`'s
//! `PacketBuilder` and hand-built TLS records, so the parse layer is proven
//! from data with **no root and no live capture** (spec R13). Kept in the crate
//! (behind `#[cfg(test)]`) so every `*_test.rs` module can share the builders.

#![cfg(test)]

use etherparse::PacketBuilder;

/// A TCP SYN over Ethernet+IPv4 with an empty payload.
pub fn eth_ipv4_tcp_syn() -> Vec<u8> {
    let mut buf = Vec::new();
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
        .ipv4([10, 0, 0, 2], [93, 184, 216, 34], 64)
        .tcp(52344, 443, 1000, 64240)
        .write(&mut buf, &[])
        .expect("build tcp syn fixture");
    buf
}

/// A UDP DNS query for `example.com` over IPv6 (raw-IP link, no Ethernet).
pub fn ipv6_udp_dns_query() -> Vec<u8> {
    let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
    let dst = [
        0x20, 0x01, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
    ];
    let mut buf = Vec::new();
    PacketBuilder::ipv6(src, dst, 64)
        .udp(51000, 53)
        .write(&mut buf, &dns_query_payload())
        .expect("build ipv6 udp dns fixture");
    buf
}

/// A minimal DNS query wire message (header + one question for example.com A).
fn dns_query_payload() -> Vec<u8> {
    let mut p = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    for label in ["example", "com"] {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0); // root label
    p.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    p
}

/// An Ethernet+IPv4+TCP:443 frame carrying a TLS Client Hello with `sni`.
pub fn eth_ipv4_tls_client_hello(sni: &str) -> Vec<u8> {
    wrap_tcp_443(&client_hello_record(sni), true)
}

/// An Ethernet+IPv4+TCP:443 frame carrying a TLS Server Hello.
pub fn eth_ipv4_tls_server_hello() -> Vec<u8> {
    wrap_tcp_443(&server_hello_record(), false)
}

/// Wrap a TLS payload in Ethernet+IPv4+TCP:443. `client` picks the port
/// direction so the client hello flows to :443 and the server hello from :443.
fn wrap_tcp_443(payload: &[u8], client: bool) -> Vec<u8> {
    let (sport, dport) = if client { (52344, 443) } else { (443, 52344) };
    let mut buf = Vec::new();
    PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [6, 5, 4, 3, 2, 1])
        .ipv4([10, 0, 0, 2], [93, 184, 216, 34], 64)
        .tcp(sport, dport, 1000, 64240)
        .write(&mut buf, payload)
        .expect("build tls frame fixture");
    buf
}

/// Build a full TLS handshake record wrapping the given handshake message body.
fn tls_record(handshake_type: u8, body: &[u8]) -> Vec<u8> {
    let mut hs = vec![handshake_type];
    hs.extend_from_slice(&u24(body.len()));
    hs.extend_from_slice(body);

    let mut record = vec![0x16, 0x03, 0x01]; // handshake, legacy version TLS 1.0
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

/// A Client Hello handshake record offering one cipher and an SNI extension.
pub fn client_hello_record(sni: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
    body.extend_from_slice(&[0x11; 32]); // random
    body.push(0x00); // session_id length
    body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites: TLS_AES_128_GCM
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    let ext = sni_extension(sni);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    tls_record(0x01, &body)
}

/// A Server Hello handshake record selecting one cipher, no extensions.
pub fn server_hello_record() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // server_version TLS 1.2
    body.extend_from_slice(&[0x22; 32]); // random
    body.push(0x00); // session_id length
    body.extend_from_slice(&[0x13, 0x01]); // selected cipher TLS_AES_128_GCM
    body.push(0x00); // compression: null
    body.extend_from_slice(&[0x00, 0x00]); // extensions length: 0
    tls_record(0x02, &body)
}

/// A single SNI (server_name) extension carrying `host`.
fn sni_extension(host: &str) -> Vec<u8> {
    let h = host.as_bytes();
    let mut server_name = vec![0x00]; // name_type = host_name
    server_name.extend_from_slice(&(h.len() as u16).to_be_bytes());
    server_name.extend_from_slice(h);

    let mut list = (server_name.len() as u16).to_be_bytes().to_vec();
    list.extend_from_slice(&server_name);

    let mut ext = vec![0x00, 0x00]; // extension_type = server_name
    ext.extend_from_slice(&(list.len() as u16).to_be_bytes());
    ext.extend_from_slice(&list);
    ext
}

/// 24-bit big-endian length, as TLS handshake headers use.
fn u24(n: usize) -> [u8; 3] {
    [(n >> 16) as u8, (n >> 8) as u8, n as u8]
}
