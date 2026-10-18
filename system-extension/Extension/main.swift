//
//  main.swift
//  macwarden NEFilterDataProvider system extension — process entry point.
//
//  A system extension is a standalone executable. `startSystemExtensionMode()`
//  reads the bundle's Info.plist (NetworkExtension > NEProviderClasses), finds
//  the content-filter provider class, instantiates it, and hands control to the
//  NetworkExtension runtime. `dispatchMain()` parks the main thread forever.
//

import Foundation
import NetworkExtension

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
