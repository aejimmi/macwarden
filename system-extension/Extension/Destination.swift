//
//  Destination.swift
//  macwarden NEFilterDataProvider system extension
//
//  Extract the destination (host / ip / port / proto) from a socket flow, in the
//  shape the Rust decision core expects: host and ip are separate — a literal IP
//  goes in `ip`, a DNS name in `host` (the core treats nil fields as Any).
//

import Foundation
import NetworkExtension

/// A flow's remote destination, ready for `macwarden_ne_decide`.
struct Destination {
    /// DNS hostname if the endpoint is a name, else nil.
    let host: String?
    /// Literal destination IP (v4 or v6 text) if known, else nil.
    let ip: String?
    /// Destination port; 0 means unknown.
    let port: UInt16
    /// IANA protocol number: 6 = TCP, 17 = UDP, 0 = unknown.
    let proto: UInt8

    init(socketFlow: NEFilterSocketFlow) {
        // socketProtocol is an IPPROTO_* value (Int32).
        switch socketFlow.socketProtocol {
        case IPPROTO_TCP: self.proto = 6
        case IPPROTO_UDP: self.proto = 17
        default: self.proto = 0
        }

        // remoteEndpoint is the classic NWHostEndpoint (hostname + port string).
        guard let endpoint = socketFlow.remoteEndpoint as? NWHostEndpoint else {
            self.host = nil
            self.ip = nil
            self.port = 0
            return
        }

        self.port = UInt16(endpoint.port) ?? 0

        // Classify the hostname: numeric literal -> ip, otherwise -> host.
        let name = endpoint.hostname
        if Destination.isNumericIP(name) {
            self.ip = name
            self.host = nil
        } else {
            self.host = name.isEmpty ? nil : name
            self.ip = nil
        }
    }

    /// A compact string for logging (never nil).
    var logString: String {
        let target = ip ?? host ?? "?"
        return "\(target):\(port)"
    }

    /// Whether `s` parses as a literal IPv4 or IPv6 address.
    private static func isNumericIP(_ s: String) -> Bool {
        if s.isEmpty { return false }
        var v4 = in_addr()
        if s.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return true }
        var v6 = in6_addr()
        if s.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 { return true }
        return false
    }
}
