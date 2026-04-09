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

- 48 named groups — logical bundles like Spotlight, Siri, Telemetry, iCloud Sync, AirDrop, Continuity, Apple Intelligence, Safari, Quarantine, Saved State, Shell History, and more, each with description and safety tier.
- 3 safety tiers — Recommended (safe to disable), Optional (loses a specific feature), Keep (important for system health).
- Respawn awareness — groups declare respawn behavior (stays-dead, respawns-launchd, respawns-aggressive) so you know if continuous monitoring is needed.
- Group commands — groups can define custom shell commands beyond launchctl (e.g., Spotlight runs `mdutil -a -i off`, Time Machine runs `tmutil disable`).
- Granular exclusions — `--except` flag lets you disable a group while keeping specific services within it.

## Artifact Scrubbing

- 12 artifact domains, 42 named artifacts — structured catalog of privacy-relevant files and directories that accumulate on disk without any associated service.
- Targets by domain — `scrub saved-state` cleans all window snapshots, `scrub browser-traces` removes Chrome/Firefox/Opera caches, `scrub quarantine` deletes the download history database.
- Targets by name — `scrub safari-favicon-cache` cleans a single specific artifact.
- Dry-run with sizes — `scrub --dry-run` previews every path with its disk size before any deletion.
- Size-aware confirmation — non-dry-run shows total size (e.g., "Will delete ~86.5 MB") and prompts before proceeding.
- Path safety — all paths are canonicalized and verified against allowed prefixes before deletion, preventing symlink traversal attacks.
- Process warnings — warns when target applications (Chrome, Firefox, Safari, Spotify, Mail) are running before cleaning their artifacts.
- `scrub all` — wipes every artifact across all 12 domains in one command, with explicit confirmation showing total size.
- `scrub --list` — shows all available groups and artifact domains with counts and `[+services]` markers for domains that also have service groups.
- `scrub --list <target>` — detail view showing individual artifacts with paths, descriptions, and associated service patterns.
- Service + artifact combo — `scrub safari` runs both service cleanup commands and structured artifact deletion in one invocation.

## Profiles

- Privacy profile — built-in profile that blocks telemetry, Siri, AirPlay, Continuity, Sidecar, widget sync, and Universal Control.
- Profile inheritance — profiles extend other profiles, up to 3 levels deep with cycle detection.
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

## Device Privacy

- Camera & microphone audit — reads the macOS TCC database to show which apps have been granted camera and microphone access.
- Process cross-referencing — maps TCC authorizations against running processes and macwarden groups.
- Access revocation — `devices --revoke <bundle-id>` removes camera/microphone authorization for a specific app.

## Network Firewall

- 14 net subcommands — scan, shield, rules, groups, trackers, apps, explain, log, learn, block, unblock, blocklists, import, enrich.
- Five-tier rule matching — exact deny, exact allow, glob deny, glob allow, default action. First match wins with full transparency.
- Tracker shield — one-command protection against advertising, analytics, fingerprinting, and social tracking domains across 4 curated categories.
- 9 network rule groups — pre-built rule sets for browser essentials, communication, development, gaming, iCloud services, location services, macOS system services, media streaming, and productivity.
- 21 app profiles — per-app classification with expected domains, categories, and breakage risk ratings for fine-grained network policy.
- GeoIP enrichment — embedded MaxMind databases for country and ASN lookups on every connection.
- Graylist detection — identifies abusable Apple-signed binaries (shells, curl, python, scripting runtimes) that bypass naive code-signing trust.
- Essential domain safelist — OCSP, NTP, and system update domains are never blocked, preventing self-inflicted breakage.
- Domain trie matching — boundary-aware domain pattern matching (blocking `tracker.com` also blocks `sub.tracker.com` but not `mytracker.com`).
- Connection scanning — shows active network connections with firewall rule evaluation.
- Rule explanation — `net explain` shows why a specific connection would be allowed or denied.
- Rule learning — `net learn` watches live connections and suggests firewall rules from observed traffic.
- Blocklist subscriptions — import external domain blocklists in hosts format or domain-list format.
- LuLu rule import — `net import lulu` reads rules from the LuLu open-source firewall and converts them to macwarden rules, giving users an instant migration path.
- GeoIP database management — `net enrich` downloads MaxMind GeoLite2-Country and ASN databases; `--status` shows current database info; `--remove` cleans up.
- Local network detection — RFC 1918, loopback, link-local, and multicast addresses are identified and excluded from GeoIP lookups, privacy scoring, and tracker analysis.
- Quick block/unblock — `net block --app Safari --host tracker.com` creates a deny rule; `net unblock` removes it.

## Network Visibility

- Active connection listing — shows all network connections (ESTABLISHED, LISTEN, UDP) by service and group.
- Service cross-referencing — maps network connections from `lsof` back to launchd services and groups.
- Deduplication — consolidates multiple connections per PID into clean output.

## Endpoint Security

- Real-time network AUTH event interception — intercepts outbound connections via Apple's Endpoint Security framework before they leave the machine.
- Per-connection allow/deny — each connection is evaluated against the rule engine and responded with allow or deny in real-time.
- Self-exemption — macwarden automatically mutes its own process to avoid feedback loops.
- Safety-net deadline — auto-allows connections if rule evaluation takes too long, preventing system hangs.

## Process Monitor

- Code signing verification — validates Apple signatures and third-party code signing identities via Security.framework.
- Responsible process resolution — traces child processes back to their parent application (e.g., a helper binary back to Chrome).
- Socket enumeration — lists open network sockets per process for cross-referencing with firewall decisions.
- Resource usage stats — CPU time, memory footprint, and I/O counters per process via libproc.
- LRU code signing cache — avoids redundant signature checks for recently verified processes.

## DNS Cache

- Passive DNS cache — maps IP addresses to hostnames from Endpoint Security network events, no active queries needed.
- LRU eviction — bounded memory usage with configurable capacity (default 10,000 entries).
- Crash-safe persistence — etchdb WAL-backed store flushes cache to disk every 60 seconds, surviving daemon restarts and crashes.
- Warm-start loading — persisted entries are restored on startup with TTL adjusted for elapsed time since last flush.
- DNS wire parser — RFC 1035 response parser for future BPF/pcap integration on port 53.

## Metrics

- SQLite-backed event store — persists enforcement, network, and sensor events to `~/.macwarden/metrics.db`.
- 6 event types — service enforcement, network decisions, sensor activations, profile changes, scrub operations, and system events.
- Time-range queries — retrieve events by time window for dashboards and reporting.
- Per-app statistics — connection counts, blocked counts, and top domains per application.

## Privacy Score

- 0-100 composite score — weighted aggregate across 4 privacy dimensions: services, traces, devices, and network.
- Service scoring — measures how many recommended and optional service groups are disabled vs. active.
- Trace scoring — measures disk footprint of forensic artifacts across 12 artifact domains.
- Device scoring — counts camera and microphone access grants, penalizes actively running authorized apps.
- Network scoring — rewards enabled tracker shield, penalizes active tracker connections, reports total internet vs. local connections.
- Actionable recommendations — each score includes specific macwarden commands to improve it, with estimated point gains.

## Hardware Sensors

- WiFi network detection — reads current SSID, BSSID, channel, noise, and security mode via CoreWLAN.
- Screen capture monitoring — detects when screen recording is active via IOKit.
- Power state monitoring — tracks lid open/close and AC/battery transitions via IOKit.
- Network context aggregation — combines WiFi, Bluetooth, and power state into a single context snapshot.
- Event debouncing — suppresses repeated sensor alerts within configurable time windows.

## Binary Inventory

- Application and system binary discovery — scans /Applications, ~/Applications, /usr/bin, /usr/sbin, /usr/libexec, /usr/local/bin, and /opt/homebrew/bin.
- Full filesystem scan — `inventory scan --all` uses Spotlight (`mdfind`) plus targeted system directory reads for fast, comprehensive discovery without recursive filesystem walks.
- App bundle parsing — extracts name, version, identifier, and executable path from macOS `.app` bundle Info.plist files.
- SHA-256 hashing — streaming 64KB-chunk hashing for integrity checking and blocklist comparison.
- Hash blocklist — checks discovered binaries against a known-bad hash list (`knowledge/blocklists/hashes.txt`).
- Persistent inventory store — etchdb WAL-backed storage at `~/.macwarden/inventory/` preserves expensive openbinary analysis results across scans.
- Store reconciliation — each scan adds new binaries, updates changed ones, and removes stale entries while preserving accumulated analysis data.
- Batch openbinary lookup — `inventory lookup` processes all unanalyzed binaries through the openbinary API, with `--no-upload` for check-only mode.
- Inline scan + lookup — `inventory scan --lookup` discovers, hashes, and immediately analyzes unanalyzed binaries in one pass.
- Code signing verification — validates Apple and third-party signatures during scan, flags unsigned or broken-signature binaries.
- Sealed volume optimization — skips code signing checks for binaries on the macOS sealed system volume (`/usr/bin`, `/usr/sbin`, `/usr/libexec`, `/System/`) where OS guarantees integrity.
- Grouped scan output — applications shown individually with version, team ID, and hash; system binaries summarized by directory with counts; blocklisted and invalid-signature binaries promoted to a flagged section.

## Binary Analysis

- Framework extraction — lists linked frameworks for any service binary via `otool -L`.
- Telemetry string scan — searches service binaries for 8 known telemetry keywords and Apple analytics domains.
- Openbinary lookup — hashes a binary, checks the openbinary database, and auto-uploads for behavioral analysis if unknown.
- Endpoint connectivity test — `lookup` with no arguments shows the configured openbinary endpoint and tests reachability with round-trip timing.

## CLI

- 16 commands — scan, info, use, block, allow, watch, scrub, undo, network, devices, net, status, lookup, inventory scan, inventory lookup.
- Scan filtering — filter services by category, show only unknown/uncategorized services, or view by group.
- Group sorting — sort groups by name, service count, running count, or safety level.
- Dual output formats — human-readable tables with rounded borders or JSON for scripting.
- Smart target resolution — `info` auto-detects whether the argument is a profile, group, or service label.
- Service detail view — shows domain, state, category, safety, PID, plist path, process CPU/memory, open files, XPC endpoints, and KeepAlive status.
- Unified configuration — single `~/.macwarden/config.toml` for all settings (openbinary endpoint, etc.) with sensible built-in defaults.
