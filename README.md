# MacWarden [experimental project]

You want to block unwanted macOS services and apps (including Spotlight, Siri, and telemetry), apply lockdown templates, and make your Mac more secure. MacWarden lets you monitor, block, and **fully disable** stubborn system processes and apps — persistently, even with SIP enabled. 

MacWarden is an app firewall for macOS. It discovers every launchd service on your system, groups them by function, and lets you block entire categories — telemetry, Siri, Spotlight, iCloud —  Written in Rust.

## Quick start

```
cargo install --path crates/macwarden
macwarden                       # see what's running
sudo macwarden use privacy      # lock it down
sudo macwarden watch --install  # keep it enforced across reboots
```

## Usage

```bash
macwarden                                     # scan all services (default)
macwarden -g                                  # show service groups
macwarden -c telemetry                        # filter by category

macwarden info siri                           # group: members, binary analysis, policy
macwarden info com.apple.Siri.agent           # service: full detail + policy decision
macwarden info privacy                        # profile: rules + what it would block

macwarden use privacy                         # enforce a profile
macwarden use privacy -n                      # dry run
macwarden use                                 # show current status

macwarden block siri                          # stop a group from running
macwarden block siri --except com.apple.parsecd   # selective
macwarden allow siri                          # let it run again

macwarden watch                               # continuous drift enforcement
macwarden watch --install                     # persistent across reboots
macwarden watch --uninstall                   # remove persistent mode

macwarden undo                                # revert last action

macwarden network                             # active connections by service
macwarden network --all                       # include LISTEN and local UDP
```

`block`, `allow`, `use`, `undo`, and `watch --install` require root. Everything else works without it.

## Service groups

Each group maps a human concept to a set of launchd service patterns. `block spotlight` knows that Spotlight is 16 services across `com.apple.metadata.mds*`, `com.apple.corespotlight*`, and others — plus `mdutil -a -i off` to stop indexing.

| Group | Services | What it controls |
|-------|----------|-----------------|
| `telemetry` | 29 | Analytics, diagnostics, crash reporting |
| `spotlight` | 16 | Search indexing, metadata, Core Spotlight |
| `siri` | 13 | Voice assistant, dictation, Parsec analytics |
| `icloud` | 8 | CloudKit, iCloud Photos, key sync |
| `bluetooth` | 8 | Bluetooth daemon, BTLE, audio accessories |
| `screentime` | 8 | Screen Time, family controls |
| `apple-intelligence` | 7 | Apple Intelligence, on-device ML |
| `location` | 6 | Location services, geofencing |

22 groups total. Run `macwarden -g` to see all with live service counts.

## Profiles

Pre-built profiles combine multiple groups into a single enforcement action.

```
base      — disables only telemetry-level services
minimal   — extends base, blocks Siri, Spotlight, Game Center, AirDrop
developer — extends minimal, re-allows Xcode, USB, simulators
airgapped — blocks all networking, Bluetooth, USB, AirDrop
studio    — blocks indexing, sync, updates (prevent audio glitches)
paranoid  — deny-default, nothing runs unless listed
```

`macwarden info <profile>` shows the full rule set and a dry-run preview of what it would block.

## Enforcement

Three layers, in order:

1. **`launchctl disable`** — prevents launchd from loading the service. Survives reboot. Works with SIP enabled.
2. **`launchctl bootout`** — unloads the service immediately. Blocked by SIP for Apple system daemons.
3. **`kill -9`** — terminates the process. Also blocked by SIP for protected processes.

On SIP-enabled machines, step 1 always works. The service stays alive until reboot, then it's gone. On SIP-disabled machines, all three execute and the service dies immediately.

Every `block` and `use` writes a snapshot before making changes. `undo` reads it and re-enables everything.

Recovery: boot to Recovery Mode, open Terminal, delete `/private/var/db/com.apple.xpc.launchd/disabled.plist`. This re-enables everything.

## Building

Requires Rust 1.94+.

```
git clone https://github.com/user/macwarden
cd macwarden
cargo build --release
./target/release/macwarden
```

## License

MIT
