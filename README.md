# macwarden (EXPERIMENTAL)

Your Mac runs 500+ silent processes — telemetry, profiling, Siri, Spotlight, iCloud sync. There's no off switch. **macwarden is the off switch.**

## Your Mac is not yours

A fresh Mac with no apps installed runs over 500 background processes. Most have no controls in System Settings. Here's what they do:

**Spotlight** sends your search queries to Apple, Microsoft Bing, and unnamed third parties — along with your location, the apps you use, and what you click. Enabled by default since 2014.

**Siri** records and sends audio to Apple servers, including accidental activations. A whistleblower revealed contractors listened to intimate conversations, medical details, and business calls. Apple admitted it. Paid $95M to settle in January 2025.

**On-device profiling** — coreduetd, suggestd, biomesyncd, routined — learns your daily patterns, app usage, movement, and habits. Feeds Apple Intelligence and Siri suggestions. Runs continuously.

**Telemetry** — analyticsd, reportingd, and 18 other services report diagnostics, usage patterns, and crash data. Always on.

**iCloud** — in February 2025, the UK government ordered Apple to backdoor iCloud under the Investigatory Powers Act. Apple complied by removing end-to-end encryption for UK users.

You can't turn most of this off. macOS gives you a few toggles in System Settings. The services keep running.

macwarden discovers all of them, groups them by function, and lets you shut them down — even the ones Apple doesn't expose. Works with SIP enabled.

## Install

```bash
cargo install --path crates/macwarden
```

Or download the notarized `.dmg` from [Releases](#).

## Lock it down

Disable telemetry, Siri, Spotlight, iCloud sync, Apple Intelligence, profiling, and 90+ other services in one command:

```bash
sudo macwarden use privacy
```

Every action is snapshotted. Undo everything:

```bash
sudo macwarden undo
```

## See what's running

```bash
macwarden                     # list all service groups
macwarden network             # active network connections by service
macwarden devices             # camera and microphone access
```

## Go deeper

Inspect a group — what services it contains, what they do, what ports they use:

```bash
macwarden info siri
macwarden info com.apple.Siri.agent   # inspect a single service
```

Block or allow individual groups:

```bash
sudo macwarden block siri
sudo macwarden block telemetry
sudo macwarden allow siri             # re-enable
```

Exclude specific services from a group block:

```bash
sudo macwarden block continuity --except com.apple.Handoff
```

Delete cached data left behind by disabled services:

```bash
sudo macwarden scrub telemetry
```

## Stay locked down

Services respawn. macwarden watches for drift and re-enforces:

```bash
sudo macwarden watch              # continuous enforcement
sudo macwarden watch --install    # run as persistent daemon
```

## Commands

```
macwarden                         list service groups (default)
macwarden info <target>           inspect a group, service, or profile
macwarden network                 active network connections by service
macwarden devices                 camera and microphone access

sudo macwarden use <profile>      apply a profile (e.g. privacy)
sudo macwarden block <target>     disable a service or group
sudo macwarden allow <target>     re-enable a service or group
sudo macwarden scrub <group>      delete cached data for a group
sudo macwarden watch              continuous enforcement
sudo macwarden undo               revert last action
```

## How it works

macwarden uses `launchctl disable` to persistently prevent services from loading — this works with SIP enabled. For immediate effect, it also runs `bootout` and `kill -9` as needed.

Blocked services stay off across reboots. Every destructive action saves a snapshot so you can `undo`.

The catalog covers 255 macOS services organized into 34 groups with safety tiers (recommended, optional, keep). 16 critical services (WindowServer, launchd, securityd) are hardcoded as undisableable.

Recovery: boot into Recovery Mode → Terminal → delete `/private/var/db/com.apple.xpc.launchd/disabled.plist`.

See [themacfiles](https://github.com/aejimmi/themacfiles) for the full research on macOS data collection and on-device ML models.

## Roadmap

- Network firewall — per-service outbound allow/block rules
- Real-time microphone and camera monitoring per service
- Graphical interface
- Additional profiles — minimal, developer, airgapped, studio, paranoid
