# macwarden

A daemon firewall for macOS. It discovers every launchd service on your system, groups them by function, and lets you disable entire categories — telemetry, Siri, Spotlight, iCloud — with a single command. 22 service groups cover 250+ annotated services out of the box, with three-layer enforcement (disable, unload, kill) and automatic snapshots so you can always roll back. Written in Rust, scans 944 services in under 200ms, ships as a 2.8 MB binary.

- **Groups** — "Disable Spotlight" means 16 services, `mdutil -a -i off`, and a snapshot. One word, not 33 launchctl commands.
- **Safety** — Critical services (launchd, WindowServer, securityd) are hardcoded as untouchable. Every enforcement writes a snapshot. `rollback` undoes it.
- **Visibility** — `ps` shows every running process tagged by group. `inspect` shows a service's binary path, XPC endpoints, KeepAlive behavior, CPU/memory, and open files.

## Quick start

```
cargo install --path crates/macwarden
macwarden groups
```

```
╭────────────────────┬──────────┬─────────┬──────────────────────────────────────────────────╮
│ Group              │ Services │ Running │ Description                                      │
├────────────────────┼──────────┼─────────┼──────────────────────────────────────────────────┤
│ spotlight          │ 16       │ 5       │ Spotlight search and metadata indexing            │
│ siri               │ 13       │ 8       │ Siri voice assistant and dictation                │
│ telemetry          │ 29       │ 5       │ Analytics, diagnostics, and crash reporting       │
│ apple-intelligence │ 7        │ 5       │ Apple Intelligence and on-device ML               │
│ icloud             │ 8        │ 5       │ iCloud sync and cloud storage services            │
│ ...                │          │         │ 22 groups total                                   │
╰────────────────────┴──────────┴─────────┴──────────────────────────────────────────────────╯
```

Disable telemetry:

```
sudo macwarden disable telemetry
```

See what's still running:

```
macwarden ps
```

Undo everything:

```
sudo macwarden rollback
```

## Service groups

Each group maps a human concept to a set of launchd service patterns. `disable spotlight` knows that Spotlight is 16 services across `com.apple.metadata.mds*`, `com.apple.corespotlight*`, `com.apple.Spotlight`, and others — plus `mdutil -a -i off` to stop indexing.

Built-in groups:

| Group | Services | What it controls |
|-------|----------|-----------------|
| `spotlight` | 16 | Search indexing, metadata, Core Spotlight |
| `siri` | 13 | Voice assistant, dictation, Parsec analytics |
| `telemetry` | 29 | Analytics, diagnostics, crash reporting, usage tracking |
| `icloud` | 8 | CloudKit, iCloud Photos, iCloud Mail, key sync |
| `airdrop` | 3 | AirDrop, Handoff, sharing daemon |
| `apple-intelligence` | 7 | Generative AI, knowledge graph, on-device ML |
| `photos` | 6 | Photo library, analysis, cloud sync |
| `location` | 6 | Location services, geofencing, routined |
| `safari` | 7 | Safari browser, bookmarks sync, password breach agent |
| `bluetooth` | 8 | Bluetooth daemon, BTLE, audio accessories |
| `screentime` | 8 | Screen Time, family controls, usage tracking |
| `maps` | 6 | Apple Maps, navigation, GeoServices |
| `fmf` | 7 | Find My device and friends |
| `updates` | 5 | Software Update, App Store |
| `backup` | 4 | Time Machine |
| `notifications` | 6 | Push notifications, user notification center |
| `messages` | 4 | iMessage, FaceTime, CommCenter |
| `gamekit` | 4 | Game Center, game controllers |
| `applemusic` | 3 | Apple Music, AMP device discovery |
| `remote-access` | 6 | Screen sharing, Remote Desktop |
| `wallet` | 3 | Apple Pay, NFC |
| `mail` | 1 | Apple Mail |

## Inspect

Deep-dive into any service or group:

```
macwarden inspect com.apple.corespotlightd
```

```
Service: com.apple.corespotlightd
  State:     running
  PID:       657
  Program:   /System/Library/Frameworks/.../corespotlightd
  KeepAlive: true (killing this service will cause launchd to restart it)
  XPC endpoints (trigger on-demand launch):
    com.apple.spotlight.SearchAgent
    com.apple.corespotlightd.cachedelete
    com.apple.spotlight.IndexAgent
  CPU:    1.4%
  Memory: 55 MB
  Member of groups: spotlight
```

The XPC endpoints matter. Any app that queries Spotlight triggers a respawn via these Mach services. That's why `disable` uses `launchctl disable` (prevents loading) rather than just killing the process.

## Enforcement

Three layers, in order:

1. **`launchctl disable`** — tells launchd to never load this service again. Survives reboot. Works with SIP enabled.
2. **`launchctl bootout`** — unloads the running service immediately. Blocked by SIP for Apple-signed system daemons.
3. **`kill -9`** — terminates the process. Also blocked by SIP for protected processes.

On SIP-enabled machines, step 1 always works. The service stays alive until the next reboot, then it's gone. On SIP-disabled machines, all three steps execute and the service dies immediately.

Every `disable` and `apply` writes a snapshot before making changes. `rollback` reads it and re-enables everything.

## Profiles

Pre-built profiles combine multiple groups. `apply minimal` disables telemetry, Siri, Spotlight, AirDrop, Game Center, and Apple Music in one command.

```
macwarden profiles
```

```
  base     — disables only telemetry-level services
  minimal  — extends base, kills Siri, Spotlight, Game Center, AirDrop
  developer — extends minimal, re-allows Xcode, USB, simulators
  airgapped — kill all networking, Bluetooth, USB, AirDrop
  studio   — kill indexing, sync, updates (prevent audio glitches)
  paranoid — deny-default, nothing runs unless listed
```

```
sudo macwarden apply minimal
```

## Process view

`ps` shows every running process on the system, grouped by service group where recognized:

```
macwarden ps
```

```
Group              PID    CPU%  Mem(MB)  User       Command
airdrop            625    0.1   15.3     kingkong   rapportd
                   660    0.1   46.2     kingkong   sharingd
apple-intelligence 67611  0.0   6.1      kingkong   intelligenceplatformd
                   88074  0.0   15.1     kingkong   knowledge-agent
siri               734    0.0   16.8     kingkong   parsecd
                   88047  0.0   18.9     kingkong   assistantd
...
```

Tree view shows parent-child hierarchy:

```
macwarden ps --tree
```

```
1 root 0.1% launchd
├── 399 _windowserver 9.6% WindowServer
├── 660 kingkong 0.1% sharingd [airdrop]
├── 67611 kingkong 0.0% intelligenceplatformd [apple-intelligence]
├── 88047 kingkong 0.0% assistantd [siri]
├── 60528 kingkong 2.7% Ghostty
│   ├── 60529 root 0.0% login
│   │   └── 60530 kingkong 0.0% fish
│   │       └── 45447 kingkong 0.0% claude
```

## Commands

| Command | What it does |
|---------|-------------|
| `macwarden groups` | List all service groups with live counts |
| `macwarden inspect <target>` | Deep-dive into a service or group |
| `macwarden disable <target>` | Disable a service or group (three-layer enforcement) |
| `macwarden enable <target>` | Re-enable a previously disabled service or group |
| `macwarden apply <profile>` | Apply a profile (disable all denied services) |
| `macwarden rollback` | Restore from the last snapshot |
| `macwarden scan` | List all 944 discovered services |
| `macwarden ps` | All running processes, grouped |
| `macwarden status` | Dashboard with group states |
| `macwarden explain <label>` | Why is this service allowed or denied |
| `macwarden doctor` | Diagnostic checks (SIP, permissions, config) |
| `macwarden profiles` | List available profiles |

All commands except `disable`, `enable`, `apply`, and `rollback` work without root.

## SIP and limitations

System Integrity Protection affects what macwarden can do immediately versus at next reboot:

| Operation | SIP enabled | SIP disabled |
|-----------|------------|-------------|
| `launchctl disable` | Works (persisted) | Works |
| `launchctl bootout` | Blocked for Apple system daemons | Works |
| `kill -9` | Blocked for Apple system daemons | Works |

With SIP enabled, disabled services keep running until reboot but won't come back after that. This is the same behavior as every macOS hardening guide — `launchctl disable` is the standard mechanism.

Recovery: if something goes wrong, boot to Recovery Mode, open Terminal, and delete `/private/var/db/com.apple.xpc.launchd/disabled.plist`. This re-enables everything.

## Building

Requires Rust 1.94+.

```
git clone https://github.com/user/macwarden
cd macwarden
cargo build --release
./target/release/macwarden groups
```

Run tests:

```
cargo test --all
```

## License

MIT
