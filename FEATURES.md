# Features

## Service Discovery

- Automatic service enumeration — discovers all launchd services across 5 plist directories and merges with runtime state from launchctl.
- State detection — identifies whether each service is running, stopped, disabled, or unknown by cross-referencing plist files with launchctl output.
- Plist parsing — reads both XML and binary plist formats, extracts label, program path, RunAtLoad, KeepAlive, and Disabled flags.
- Domain classification — categorizes services into system daemons, user agents, and global agents.

## Service Catalog

- 255 annotated macOS services — curated database with human-readable descriptions, categories, safety levels, and macOS version ranges.
- 10 service categories — Core OS, Networking, Security, Media, Cloud, Telemetry, Input, Accessibility, Developer, Third-Party.
- 4 safety levels — Critical (never disable), Important (degrades functionality), Optional (safe to disable), Telemetry (recommended to disable).
- Glob pattern matching — annotations use wildcard patterns (e.g., `com.apple.Siri.*`) to cover service families with a single entry.
- Heuristic inference — unknown services are auto-categorized by keyword analysis (e.g., "diagnostic" maps to Telemetry, "audio" maps to Media).

## Service Groups

- 32 named groups — logical bundles like Spotlight, Siri, Telemetry, iCloud Sync, AirDrop, Continuity, Apple Intelligence, each with description and safety tier.
- 3 safety tiers — Recommended (safe to disable), Optional (loses a specific feature), Keep (important for system health).
- Group commands — groups can define custom shell commands beyond launchctl (e.g., Spotlight runs `mdutil -a -i off`, Time Machine runs `tmutil disable`).
- Granular exclusions — `--except` flag lets you disable a group while keeping specific services within it.

## Profiles

- 7 built-in profiles — base, minimal, developer, privacy, airgapped, studio, paranoid.
- Profile inheritance — profiles extend other profiles (e.g., developer extends minimal extends base), up to 3 levels deep with cycle detection.
- Category-level rules — allow, deny, or log-only entire categories (e.g., `telemetry=deny`).
- Pattern-based rules — allow or deny services by exact label or glob pattern.
- Enforcement modes — disable (persistent across reboots), kill (immediate termination), or log-only (audit without action).

## Policy Engine

- 6-level decision precedence — exact deny, exact allow, glob deny, glob allow, category rule, default allow. First match wins.
- Decision transparency — every allow/deny decision includes the reason (which rule matched, from which profile).
- Diff computation — compares current system state against a profile and generates the minimal set of actions needed.
- Safe-list protection — 16 critical service patterns (WindowServer, launchd, securityd, configd, xpc, etc.) are hardcoded and cannot be disabled by any profile or command.

## Enforcement

- 3-step disable sequence — launchctl disable (persistent), bootout (unload immediately), kill (terminate process).
- Dry-run mode — preview all actions without executing, available on every destructive command.
- Per-action error handling — individual service failures don't abort the batch; each result is reported separately.
- SIP status detection — checks System Integrity Protection state via `csrutil status`.

## Monitoring

- FSEvents file watching — detects plist changes instantly across all launchd directories.
- 60-second reconciliation sweep — catches drift from services that respawn or are re-enabled externally.
- Profile hot-reload — detects when the active profile changes on disk and re-enforces automatically.
- Notification debouncing — suppresses repeated alerts for the same service within a 10-second window.
- Session statistics — reports total sweeps, drift corrections, and profile reloads on shutdown.
- Daemon installation — `watch --install` registers macwarden as a persistent launchd service with KeepAlive; `--uninstall` removes it.

## Snapshots & Rollback

- Automatic snapshots — state is captured to disk before every enforcement action.
- JSON persistence — snapshots stored as pretty-printed JSON in `~/.local/share/macwarden/snapshots/` with ISO 8601 timestamps.
- Rollback — `undo` restores the most recent snapshot or a named one, re-enabling all services that were disabled.
- Snapshot listing — view all available snapshots sorted chronologically.

## Binary Analysis

- Framework extraction — lists linked frameworks for any service binary via `otool -L`.
- Telemetry string scan — searches service binaries for 8 known telemetry keywords and Apple analytics domains.

## Network Visibility

- Active connection listing — shows all network connections (ESTABLISHED, LISTEN, UDP) by service and group.
- Service cross-referencing — maps network connections from `lsof` back to launchd services and groups.
- Deduplication — consolidates multiple connections per PID into clean output.

## CLI

- 9 commands — scan, info, use, block, allow, watch, undo, status, network.
- Scan filtering — filter services by category, show only unknown/uncategorized services, or view by group.
- Group sorting — sort groups by name, service count, running count, or safety level.
- Dual output formats — human-readable tables with rounded borders or JSON for scripting.
- Smart target resolution — `info` auto-detects whether the argument is a profile, group, or service label.
- Service detail view — shows domain, state, category, safety, PID, plist path, process CPU/memory, open files, XPC endpoints, and KeepAlive status.
