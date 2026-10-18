//
//  main.swift
//  MacwardenSysextActivator — the host app that installs the system extension.
//
//  A system extension must be embedded in an app under
//    <App>.app/Contents/Library/SystemExtensions/<ext-id>.systemextension
//  and activated via OSSystemExtensionRequest from that app. The app must live in
//  /Applications (macOS refuses to load a sysext hosted elsewhere).
//
//  This is a minimal command-line-style activator: it submits an activation
//  request, drives the delegate, prints what macOS reports, and — for the
//  content filter to actually inspect traffic — enables the NEFilterManager
//  configuration once the extension is approved.
//
//  Usage:
//    MacwardenSysextActivator activate   (default) — install + enable the filter
//    MacwardenSysextActivator deactivate           — uninstall the extension
//

import Foundation
import SystemExtensions
import NetworkExtension

let extensionBundleID = "ai.macwarden.filter.extension"

final class Activator: NSObject, OSSystemExtensionRequestDelegate {
    private let mode: String

    init(mode: String) {
        self.mode = mode
    }

    func run() {
        let request: OSSystemExtensionRequest
        if mode == "deactivate" {
            print("[activator] requesting DEACTIVATION of \(extensionBundleID)")
            request = OSSystemExtensionRequest.deactivationRequest(
                forExtensionWithIdentifier: extensionBundleID,
                queue: .main
            )
        } else {
            print("[activator] requesting ACTIVATION of \(extensionBundleID)")
            request = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: extensionBundleID,
                queue: .main
            )
        }
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        // Park on the main run loop while the async delegate drives the flow.
        RunLoop.main.run()
    }

    // MARK: - OSSystemExtensionRequestDelegate

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties)
        -> OSSystemExtensionRequest.ReplacementAction {
        print("[activator] replacing existing v\(existing.bundleShortVersion) "
              + "with v\(ext.bundleShortVersion)")
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("""
            [activator] *** USER APPROVAL REQUIRED ***
            Open System Settings > General > Login Items & Extensions >
            Network Extensions (or Privacy & Security), and APPROVE
            "macwarden Network Filter". This activator will keep running.
            """)
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        print("[activator] request finished: \(result.rawValue) "
              + "(0 = completed, 1 = will complete after reboot)")
        if mode == "deactivate" {
            print("[activator] extension deactivated. Done.")
            exit(0)
        }
        enableContentFilter()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let ns = error as NSError
        print("[activator] request FAILED: \(ns.domain) code=\(ns.code): "
              + "\(ns.localizedDescription)")
        exit(1)
    }

    // MARK: - Enable the NEFilterManager configuration

    /// After the extension is approved, the content filter must be turned on via
    /// NEFilterManager (this is the "Enable" toggle for the filter). Requires the
    /// extension to be approved first.
    private func enableContentFilter() {
        let manager = NEFilterManager.shared()
        manager.loadFromPreferences { loadErr in
            if let loadErr {
                print("[activator] loadFromPreferences failed: \(loadErr.localizedDescription)")
                exit(1)
            }
            if manager.providerConfiguration == nil {
                let config = NEFilterProviderConfiguration()
                config.filterSockets = true
                config.filterPackets = false
                manager.providerConfiguration = config
                manager.localizedDescription = "macwarden"
            }
            manager.isEnabled = true
            manager.saveToPreferences { saveErr in
                if let saveErr {
                    print("[activator] saveToPreferences failed: "
                          + "\(saveErr.localizedDescription)")
                    print("[activator] (this often means the extension is not yet "
                          + "approved — approve it, then re-run 'activate')")
                    exit(1)
                }
                print("[activator] content filter ENABLED. macwarden is now filtering "
                      + "outbound flows.")
                exit(0)
            }
        }
    }
}

let mode = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : "activate"
// Bind to a top-level `let` so the delegate outlives the async activation flow
// (an anonymous temporary would be seen as deallocated -> weak captures nil).
let activator = Activator(mode: mode)
activator.run()
