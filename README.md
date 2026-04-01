# macwarden

An app firewall for macOS. Discovers every launchd service on your system, groups them by function, and lets you block what you don't need. Written in Rust.

## Why

macOS runs hundreds of background services out of the box — telemetry, profiling, ML-powered behavioral prediction. Most of it runs silently with no off switch in System Settings. macwarden gives you that switch.

See [themacfiles](https://github.com/aejimmi/themacfiles) for the research: what Apple collects, which ML models run on your data, and the full model inventory.

## Quick start

```
cargo install --path crates/macwarden
macwarden
```

See the groups, pick what to investigate:

```
macwarden info telemetry
```

Block it:

```
sudo macwarden block telemetry
```

Or apply the privacy profile to block telemetry, Siri, Spotlight, iCloud sync, Apple Intelligence, AirPlay, widgets, and more — 93 services in one command:

```
sudo macwarden use privacy
```

Undo anything:

```
sudo macwarden undo
```

## Usage

```bash
macwarden                         # show service groups (default)
macwarden info siri               # inspect a group — services, ports, what it does
macwarden info com.apple.Siri.agent   # inspect a single service — binary, XPC, frameworks

sudo macwarden block siri         # stop a group from running
sudo macwarden block siri --except com.apple.parsecd   # selective
sudo macwarden allow siri         # let it run again

sudo macwarden use privacy        # apply the privacy profile
sudo macwarden undo               # revert last action

macwarden network                 # show active network connections by service
sudo macwarden watch              # continuous enforcement — catch services that respawn
```

`block`, `allow`, `use`, `undo`, and `watch` require root. Everything else works without it.

## Groups

Each group maps a human concept to a set of launchd service patterns. `block spotlight` handles 16 services plus `mdutil -a -i off`. `block airplay` closes ports 7000 and 5000 that are open to your LAN.

Run `macwarden` to see all groups with live service counts.

## Enforcement

Three layers, in order:

1. **`launchctl disable`** — prevents loading. Survives reboot. Works with SIP enabled.
2. **`launchctl bootout`** — unloads now. Blocked by SIP for Apple system daemons.
3. **`kill -9`** — terminates. Also blocked by SIP for protected processes.

With SIP enabled, services stay alive until reboot, then they're gone. Every `block` and `use` writes a snapshot. `undo` restores it.

Recovery: boot to Recovery Mode, open Terminal, delete `/private/var/db/com.apple.xpc.launchd/disabled.plist`.

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
