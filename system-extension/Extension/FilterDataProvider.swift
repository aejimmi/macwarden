//
//  FilterDataProvider.swift
//  macwarden NEFilterDataProvider system extension
//
//  A thin content-filter provider. It does NOT reimplement rule matching —
//  every verdict comes from the Rust decision core (net::RuleSet) linked as
//  libenforce_ne_ffi.a over the C ABI in macwarden_ne.h. The Swift layer does
//  only three things per flow:
//    1. audit token  -> (code_id, path)        via CodeIdentity (SecCode)
//    2. flow endpoint -> (host | ip, port, proto)
//    3. macwarden_ne_decide(...) -> 0 allow / 1 deny / 2 log
//  and maps 1 -> .drop(), everything else -> .allow().
//
//  Robustness: the Rust core is fail-open (a null handle or any internal panic
//  yields ALLOW), and this provider treats a missing handle / unresolved flow as
//  ALLOW too, so a bug here can never wedge the user's network.
//

import Foundation
import NetworkExtension
import os.log

/// Verdict codes returned by `macwarden_ne_decide` (see macwarden_ne.h).
private let MW_ALLOW: Int32 = 0
private let MW_DENY: Int32 = 1
private let MW_LOG: Int32 = 2

@objc(FilterDataProvider)
final class FilterDataProvider: NEFilterDataProvider {
    private let log = Logger(subsystem: "ai.macwarden.filter", category: "provider")

    /// The Rust decision-core handle, created once in `startFilter`.
    ///
    /// Only ever touched while holding `handleLock`: `handleNewFlow` runs on
    /// concurrent worker threads while `stopFilter` frees the handle on another,
    /// so an unlocked read here would be a use-after-free of the root FFI handle
    /// if a flow arrives mid-teardown (spec 009 R4).
    private var handle: OpaquePointer?

    /// Serializes all access to `handle` so `macwarden_ne_decide` /
    /// `macwarden_ne_reload` can never run concurrently with `macwarden_ne_free`.
    private let handleLock = NSLock()

    /// Watches the shared `~/.macwarden/` tree and hot-reloads the ruleset.
    private var watcher: RuleWatcher?

    // MARK: - Lifecycle

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        let baseDir = Self.sharedBaseDir()
        if let baseDir {
            log.info("startFilter: loading decision core from \(baseDir, privacy: .public)")
            handle = baseDir.withCString { macwarden_ne_init_at($0) }
        }
        if handle == nil {
            // Fall back to the core's own default resolution ($MACWARDEN_HOME or
            // $HOME/.macwarden — note: for a root-run sysext $HOME is /var/root).
            log.info("startFilter: init_at unavailable, trying macwarden_ne_init()")
            handle = macwarden_ne_init()
        }
        if handle == nil {
            log.error("startFilter: decision core failed to load; provider will ALLOW all")
        }

        // Watch the shared dir so daemon/panel rule edits take effect live. The
        // reload goes through `reloadRuleset()` (under `handleLock`) rather than
        // capturing the raw handle, so a reload racing teardown is safe too.
        if let baseDir, handle != nil {
            watcher = RuleWatcher(path: baseDir) { [weak self] in
                self?.reloadRuleset()
            }
        }

        // Send every new flow to handleNewFlow: no static rules, default = filter.
        let settings = NEFilterSettings(rules: [], defaultAction: .filterData)
        apply(settings) { [weak self] error in
            if let error {
                self?.log.error("apply(settings) failed: \(error.localizedDescription, privacy: .public)")
            } else {
                self?.log.info("filter active (defaultAction=filterData)")
            }
            completionHandler(error)
        }
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        log.info("stopFilter: reason=\(reason.rawValue, privacy: .public)")
        watcher?.cancel()
        watcher = nil
        // Free under the lock so no in-flight `decide`/`reload` is still using
        // the handle when it is freed (spec 009 R4 use-after-free guard).
        handleLock.lock()
        if let h = handle {
            macwarden_ne_free(h)
            handle = nil
        }
        handleLock.unlock()
        completionHandler()
    }

    /// Hot-reload the ruleset under `handleLock`. A no-op once the handle is
    /// freed, so a watcher callback that fires during teardown is safe.
    private func reloadRuleset() {
        handleLock.lock()
        defer { handleLock.unlock() }
        guard let h = handle else { return }
        let ok = macwarden_ne_reload(h)
        log.info("ruleset reload: \(ok ? "ok" : "kept previous", privacy: .public)")
    }

    // MARK: - Per-flow decision

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            // Non-socket (e.g. some URL flows) — we do not filter these here.
            return .allow()
        }

        // 1. Source app identity from the audit token.
        let identity: SourceIdentity
        if let token = flow.sourceAppAuditToken {
            identity = CodeIdentity.resolve(auditToken: token)
        } else {
            identity = .unknown
        }

        // 2. Destination from the socket flow's remote (peer) endpoint. For an
        //    inbound flow the remote endpoint is the connecting peer (the
        //    attacker IP that spec 010's banwatch drops); for an outbound flow it
        //    is the app's destination. `Destination` reads `remoteEndpoint` in
        //    both cases, so the same (ip/host, port, proto) tuple reaches the core.
        let dest = Destination(socketFlow: socketFlow)

        // 3. Ask the Rust decision core (identical verdict for in and out — the
        //    core matches on the remote endpoint regardless of direction).
        let verdict = decide(identity: identity, dest: dest)

        // Direction token so the R6 proof and banwatch can distinguish in vs out.
        let direction = Self.directionToken(socketFlow.direction)
        let action = (verdict == MW_DENY) ? "DENY" : (verdict == MW_LOG ? "LOG" : "ALLOW")
        log.info("""
            flow \(identity.codeId ?? "?", privacy: .public) \
            -> \(dest.logString, privacy: .public) proto=\(dest.proto) \
            dir=\(direction, privacy: .public) => \(action, privacy: .public)
            """)

        return verdict == MW_DENY ? .drop() : .allow()
    }

    /// Bridge the resolved identity + destination across the C ABI.
    ///
    /// Holds `handleLock` across the whole `macwarden_ne_decide` call so the
    /// handle cannot be freed by `stopFilter` mid-decision (spec 009 R4).
    private func decide(identity: SourceIdentity, dest: Destination) -> Int32 {
        handleLock.lock()
        defer { handleLock.unlock() }
        guard let h = handle else { return MW_ALLOW }  // fail open
        return withOptionalCString(identity.codeId) { codeId in
            withOptionalCString(identity.path) { path in
                withOptionalCString(dest.host) { host in
                    withOptionalCString(dest.ip) { ip in
                        macwarden_ne_decide(h, codeId, path, host, ip, dest.port, dest.proto)
                    }
                }
            }
        }
    }

    /// A compact `in` / `out` / `any` token for a flow's traffic direction, used
    /// only for the os_log line (never for the decision — the core is
    /// direction-agnostic and matches on the remote endpoint either way).
    private static func directionToken(_ direction: NETrafficDirection) -> String {
        switch direction {
        case .inbound: return "in"
        case .outbound: return "out"
        default: return "any"
        }
    }

    // MARK: - Shared directory resolution

    /// The `~/.macwarden/` directory the ruleset is read from. Baked into the
    /// extension's Info.plist by build.sh (`MacwardenSharedDir`) because a
    /// root-run sysext does not inherit the console user's `$HOME`.
    private static func sharedBaseDir() -> String? {
        if let dir = Bundle.main.object(forInfoDictionaryKey: "MacwardenSharedDir") as? String,
           !dir.isEmpty {
            return (dir as NSString).expandingTildeInPath
        }
        return nil
    }
}

/// Call `body` with a C string for `s`, or with `nil` when `s` is nil.
private func withOptionalCString<R>(_ s: String?,
                                    _ body: (UnsafePointer<CChar>?) -> R) -> R {
    if let s { return s.withCString { body($0) } }
    return body(nil)
}
