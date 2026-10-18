//
//  CodeIdentity.swift
//  macwarden NEFilterDataProvider system extension
//
//  Resolve the SOURCE APP identity of a flow from its audit token, using the
//  exact technique the Rust daemon already uses for its IPC peer-cred check
//  (crates/ipc/src/server/codesign.rs):
//
//      audit_token bytes
//        -> CFData
//        -> CFDictionary { kSecGuestAttributeAudit: data }
//        -> SecCodeCopyGuestWithAttributes(NULL, dict, [], &code)
//        -> SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info)
//        -> info[kSecCodeInfoIdentifier]      == code_id  (the signing identifier)
//           info[kSecCodeInfoMainExecutable]  == path     (executable on disk)
//
//  This mirrors, in Swift, the primitive proven in `codesign.rs`: keyed on the
//  peer's audit token (never the racy pid), because the token carries a
//  pidversion that closes the pid-reuse race. Any failure yields (nil, nil) so
//  the caller passes "unknown" identity to the decision core, which fails open.
//

import Foundation
import Security

/// The resolved identity of the process that owns a flow.
struct SourceIdentity {
    /// The code-signing identifier (e.g. "com.apple.Safari"), or nil if unknown.
    let codeId: String?
    /// The main executable path on disk, or nil if unknown.
    let path: String?

    /// The "unknown" identity — the decision core treats nil fields as Any.
    static let unknown = SourceIdentity(codeId: nil, path: nil)
}

enum CodeIdentity {
    /// Resolve the signing identifier and executable path for the process
    /// identified by `auditToken` (32 raw bytes of `audit_token_t`).
    ///
    /// Returns `.unknown` on any failure — never throws, never blocks.
    static func resolve(auditToken: Data) -> SourceIdentity {
        guard auditToken.count == 32 else {
            return .unknown
        }

        // audit_token bytes -> CFData
        guard let tokenData = auditToken.withUnsafeBytes({ raw -> CFData? in
            guard let base = raw.baseAddress else { return nil }
            return CFDataCreate(nil, base.assumingMemoryBound(to: UInt8.self), 32)
        }) else {
            return .unknown
        }

        // { kSecGuestAttributeAudit: data }
        let attributes: CFDictionary =
            [kSecGuestAttributeAudit as String: tokenData] as CFDictionary

        // audit token -> SecCode guest
        var codeOpt: SecCode?
        let guestStatus = SecCodeCopyGuestWithAttributes(nil, attributes, [], &codeOpt)
        guard guestStatus == errSecSuccess, let code = codeOpt else {
            return .unknown
        }

        // Dynamic SecCode -> static SecStaticCode via the canonical API. Never
        // `unsafeBitCast`: SecCode and SecStaticCode are distinct CoreFoundation
        // types, and reinterpreting one as the other is undefined behavior that
        // happens to work only because they share layout today (spec 009 R7).
        var staticOpt: SecStaticCode?
        let staticStatus = SecCodeCopyStaticCode(code, [], &staticOpt)
        guard staticStatus == errSecSuccess, let staticCode = staticOpt else {
            return .unknown
        }

        // SecStaticCode -> signing information dictionary
        var infoOpt: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &infoOpt
        )
        guard infoStatus == errSecSuccess,
              let info = infoOpt as? [String: Any] else {
            return .unknown
        }

        let codeId = info[kSecCodeInfoIdentifier as String] as? String
        let path = executablePath(from: info, staticCode: staticCode)
        return SourceIdentity(codeId: codeId, path: path)
    }

    /// Extract the executable path: prefer the signing info's main-executable
    /// URL, fall back to `SecCodeCopyPath` on the static code object.
    private static func executablePath(from info: [String: Any],
                                       staticCode: SecStaticCode) -> String? {
        if let url = info[kSecCodeInfoMainExecutable as String] as? URL {
            return url.path
        }
        var urlOpt: CFURL?
        let status = SecCodeCopyPath(staticCode, [], &urlOpt)
        if status == errSecSuccess, let cfurl = urlOpt {
            return (cfurl as URL).path
        }
        return nil
    }
}
