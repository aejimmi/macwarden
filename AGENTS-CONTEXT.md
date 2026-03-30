# Project Context

## Crates

| Crate | Purpose | Platform deps |
|-------|---------|---------------|
| `macwarden-core` | Policy engine, profile model, rule matching, decision logic, catalog schema, safe-list. Pure Rust — ZERO platform deps. Compiles and tests anywhere. | none |
| `macwarden-catalog` | Service annotation DB (embedded TOML), plist parsing, category assignment. Touches filesystem for plist reads, but no OS APIs. | `plist` crate |
| `macwarden-launchd` | `launchctl` wrapper, FSEvents directory watcher (via `notify`), process kill (via `nix`), enforcement execution, SIP detection. The only Tier 1 crate that talks to macOS. | macOS only |
| `macwarden-es` | Endpoint Security FFI — Tier 2, feature-gated behind `"es"` flag. Raw C FFI to `libEndpointSecurity.tbd`. AUTH_EXEC subscription, response with safety-net timer. | macOS + SIP disabled |
| `macwarden-snapshot` | State snapshots before enforcement, rollback logic, snapshot history management. Pure Rust + serde. | none |
| `macwarden` | CLI binary (clap). Subcommands: `scan`, `apply`, `enforce`, `relax`, `allow`, `deny`, `explain`, `log`, `snapshot`, `rollback`, `doctor`, `daemon`. Thin glue. | all crates |
| `macknows` | Apple telemetry decoder. Reads analyticsd SQLite databases, cross-references config transforms with state data, produces human-readable categorized report of what Apple collects. Standalone CLI + library. | `rusqlite` |

## Build Order

1. **Phase 1: macwarden-core + macwarden-catalog** — Core types (`ServiceInfo`, `ServiceState`, `ServiceCategory`, `Domain`), policy engine (profile resolution, rule matching, diff computation, explain logic), annotation DB schema, plist parsing, safe-list constant. Pure-function tests: given profile + service list → correct decisions.
2. **Phase 2: macwarden (bin) + macwarden-launchd (read-only)** — CLI with `scan`, `explain`, `doctor`. Read-only `launchctl list` wrapper. First user-visible output: categorized table of all services.
3. **Phase 3: macwarden-launchd (enforcement) + macwarden-snapshot** — `launchctl disable`, `bootout`, process kill. FSEvents watcher on plist directories. Snapshot write-before-mutate. `apply`, `rollback`, dry-run.
4. **Phase 4: macwarden-launchd (monitor) + daemon mode** — 60-second reconciliation sweep + FSEvents-driven drift detection. `monitor` subcommand. `daemon --install` self-installs as launchd service. Signal handling.
5. **Phase 5: macwarden-es (feature-gated)** — ES AUTH_EXEC subscription, allow/deny response, safety-net timer (auto-allow 2s before deadline), self-exemption via muting own audit token. Requires SIP disabled for testing.
6. **Phase 6: Shipping** — 300+ service annotations, built-in profiles for macOS 15/16/26, Homebrew formula, README, changelog. `/macwarden:features`, `/macwarden:changelog`, `/macwarden:readme`, `/macwarden:doc-check`, `/macwarden:release`.

Phases 1 and 2 are the MVP — ship `scan` + `explain` first.

**macknows** is independent — no phase dependencies, no other workspace crate dependencies. Can be built anytime.

## Key Decisions

- **Two-tier enforcement over pure userspace**: Tier 1 (launchctl + FSEvents) works without SIP disabled — broad audience. Tier 2 (ES AUTH_EXEC) is opt-in, feature-gated — closes the "brief execution" gap for the hardcore crowd. The audience has SIP disabled, so Apple's entitlement gatekeeping is irrelevant (ad-hoc signing works).
- **Curated annotations over hardcoded lists**: Service catalog is embedded TOML with labels, descriptions, categories, safety levels, and macOS version ranges. Community-editable. Unknown `com.apple.*` services default to allow; unknown third-party defaults to deny.
- **Six crates over fewer**: `macwarden-core` must compile cross-platform with zero deps for CI testability. `macwarden-es` must be feature-gated so Tier 1 users don't pull in ES. `macwarden-snapshot` is independent of enforcement mechanism. The catalog is separate because plist parsing is a distinct concern from policy logic.
- **FSEvents + 60s sweep over kqueue EVFILT_PROC**: FSEvents scales well (no per-file fd), detects plist changes instantly. 60s reconciliation sweep catches drift. kqueue per-PID monitoring deferred — doesn't scale to hundreds of services, and FSEvents + sweep covers the respawn case.
- **Synchronous monitor over async runtime**: No Tokio. FSEvents callbacks run on a dedicated thread (handled by `notify` crate). Reconciliation sweep is a sleep loop. `signal-hook` for clean Ctrl+C. The complexity of an async runtime is not justified.
- **`explain` as a first-class command**: Decision transparency builds trust. "DENIED by rule X in profile Y (inherited from Z), category: telemetry, safety: optional" — this is what makes users confident enough to run `enforce`.
- **Dry-run by default on first use**: First `apply` is log-only. Must explicitly `enforce` to activate. Follows the principle of least surprise.
- **ES safety-net timer (Tier 2)**: Auto-allow 2 seconds before the kernel's per-message deadline. Following Santa's pattern. Miss the deadline = kernel kills your process. Never cache interpreters.
- **No daemon mode by default**: Monitor runs foreground. `daemon --install` is explicit opt-in. We are not what we hunt — but users who want persistence can choose it.
- **`thiserror` for libraries, `anyhow` for the binary**: Per project convention in CLAUDE.md.
- **Don't target enterprise**: Explicitly a personal tool. Enterprise = commercialization gravity = the death of Santa.

## Product Domains

| Code path | Domain |
|---|---|
| `crates/macwarden-core/src/policy*` | Policy Engine |
| `crates/macwarden-core/src/profile*` | Profile System |
| `crates/macwarden-core/src/safelist*` | Safety |
| `crates/macwarden-core/src/explain*` | Decision Transparency |
| `crates/macwarden-catalog/` | Service Catalog |
| `crates/macwarden-launchd/` | Platform Integration |
| `crates/macwarden-es/` | Endpoint Security (Tier 2) |
| `crates/macwarden-snapshot/` | State Snapshots |
| `crates/macwarden/` | CLI |

## Architecture

### Two-tier enforcement

```
Tier 1 (default, no SIP requirement for user agents):
  launchctl disable/bootout + process kill
  FSEvents on plist dirs → instant detection
  60-second reconciliation sweep → catch drift

Tier 2 (opt-in, SIP disabled + root):
  ES AUTH_EXEC → synchronous block-before-execute
  Safety-net timer → auto-allow before deadline
  Self-exemption → mute own audit token
```

### Santa patterns adopted

- **Auth result cache** with short deny TTL (Santa uses 1500ms) — don't cache denies in ES framework, only locally. ES cache + DENY + rule change = stale deny.
- **Safety-net timer** — respond before the kernel's deadline. Santa's pattern: set timer to fire 2s before `msg->deadline`.
- **Self-exemption** — mute own process to avoid self-blocking.
- **Monitor vs Lockdown** — maps to our `apply` (log-only mode) vs `enforce` (active mode).

### ES gotchas (Tier 2 implementation notes)

- Variable deadlines per message (3.5s–15s). Always read `msg->deadline`.
- Never cache `/bin/bash`, `/usr/bin/python3` etc — same binary, different payloads.
- Global cache poisoning: if ANY client doesn't cache, events redeliver to ALL.
- Subscribing past `ES_EVENT_TYPE_LAST` = kernel panic. Version-check at startup.
- Mute + deny + cache expiry = bypass. Never mute what you deny.

### State storage

- Snapshots: `~/.local/share/macwarden/snapshots/<timestamp>.json`
- Active profile: `~/.config/macwarden/active-profile`
- User profiles: `~/.config/macwarden/profiles/*.toml`
- System profiles: `/etc/macwarden/profiles/*.toml` (root-managed, overrides user)
- Annotation DB: compiled into binary, overridable via `~/.config/macwarden/catalog/`
- Logs: stderr via `tracing-subscriber`, respects `RUST_LOG`

### Safety invariants

1. **Safe-list checked twice**: profile validation (reject) AND enforcement (refuse). Compiled in, not configurable.
2. **Snapshot before mutation**: written to disk before any `disable`/`kill` call. Crash-safe.
3. **Dry-run by default**: first `apply` = log-only. Must `enforce` to activate.
4. **ES watchdog (Tier 2)**: auto-allow before deadline. Never block the system.
5. **Self-exemption**: macwarden never blocks itself. PID + path + signing identity check.
6. **Recovery path documented**: Recovery Mode → Terminal → delete disabled.plist.
