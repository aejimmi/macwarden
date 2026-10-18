//
//  RuleWatcher.swift
//  macwarden NEFilterDataProvider system extension
//
//  Watch the shared `~/.macwarden/` directory for changes and fire a callback so
//  the provider can hot-reload its embedded ruleset (macwarden_ne_reload). This
//  is the file-watch rule-sync path from the spec (R3b): the daemon/panel writes
//  net-rules there, the provider picks it up — no per-flow daemon round-trip.
//
//  A DispatchSource vnode watch fires on writes/renames/deletes within the
//  watched directory's inode. Editors that atomically replace files also touch
//  the directory, so watching the directory fd catches rule edits in practice;
//  the reload is cheap and fail-safe (a bad reload keeps the previous ruleset).
//

import Foundation

/// Watches a directory and invokes `onChange` (debounced) when it mutates.
final class RuleWatcher {
    private let fd: Int32
    private let source: DispatchSourceFileSystemObject
    private var pending = false

    /// Start watching `path`. Returns nil-equivalent (a no-op source) if the
    /// directory cannot be opened — enforcement still works, just no live reload.
    init?(path: String, onChange: @escaping () -> Void) {
        let opened = open(path, O_EVTONLY)
        guard opened >= 0 else { return nil }
        self.fd = opened

        let queue = DispatchQueue(label: "ai.macwarden.filter.rulewatch")
        self.source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: opened,
            eventMask: [.write, .rename, .delete, .attrib],
            queue: queue
        )

        source.setEventHandler { [weak self] in
            guard let self, !self.pending else { return }
            self.pending = true
            // Debounce: rule writes often arrive as a burst.
            queue.asyncAfter(deadline: .now() + .milliseconds(250)) {
                self.pending = false
                onChange()
            }
        }
        source.setCancelHandler { [fd = self.fd] in
            close(fd)
        }
        source.resume()
    }

    /// Stop watching and release the file descriptor.
    func cancel() {
        source.cancel()
    }

    deinit {
        cancel()
    }
}
