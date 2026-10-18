# macwarden NetworkExtension content filter (system extension)

This tree is the **stage-2 NE path**: a macOS `NEFilterDataProvider` **content-filter
system extension** that turns macwarden into a real, per-app outbound firewall. It is a
non-cargo tree — it is **not** a workspace crate and is kept out of the cargo build.

The per-flow decision is made by the **Rust decision core** (`crates/enforce-ne-ffi`,
built as `libenforce_ne_ffi.a`), linked into the Swift extension over the C ABI in
`crates/enforce-ne-ffi/include/macwarden_ne.h`. The Swift layer does **only**:

1. resolve the flow's **source app** (audit token → `code_id` + executable path),
2. extract the **destination** (host / ip / port / proto),
3. call `macwarden_ne_decide(...)` → `0 allow / 1 deny / 2 log`,
4. map `1 → .drop()`, everything else `→ .allow()`.

No rule logic is reimplemented in Swift — `net::RuleSet` remains the single source of
truth. The provider embeds the ruleset in-process and decides sub-millisecond with **no
per-flow round-trip to the daemon**. It reads rules from `~/.macwarden/` and hot-reloads
when the daemon/panel edits them.

## No root daemon required

The system extension is **OS-managed and user-approved**. It does **not** need a root
daemon: macOS runs the sysext process itself once the user approves it once in System
Settings. The user's cost is exactly **one explicit, revocable permission** — the
extension approval (revocable any time in System Settings). This is the SIP-on, no-kext,
App-Store-philosophy path.

## Layout

```
system-extension/
├── build.sh                     transparent swiftc + codesign pipeline
├── README.md                    this file
├── Extension/                   the NEFilterDataProvider system extension (Swift)
│   ├── main.swift               NEProvider.startSystemExtensionMode() entry point
│   ├── FilterDataProvider.swift startFilter/stopFilter/handleNewFlow
│   ├── CodeIdentity.swift       audit token → SecCode → (code_id, path)
│   ├── Destination.swift        flow remote endpoint → (host|ip, port, proto)
│   ├── RuleWatcher.swift        DispatchSource watch → macwarden_ne_reload
│   ├── Bridging-Header.h        imports macwarden_ne.h (the C ABI)
│   ├── Info.plist.in            NEProviderClasses → filter-data → FilterDataProvider
│   └── Extension.entitlements   content-filter-provider
└── App/                         the host app / activator (Swift)
    ├── main.swift               OSSystemExtensionRequest activation + NEFilterManager
    ├── Info.plist.in
    └── App.entitlements         system-extension.install + content-filter-provider
```

After `build.sh` runs, `system-extension/build/MacwardenFilter.app` contains the
extension embedded at the **required** path:

```
MacwardenFilter.app/Contents/Library/SystemExtensions/
    ai.macwarden.filter.extension.systemextension
```

Bundle IDs: app `ai.macwarden.filter`, extension `ai.macwarden.filter.extension`.

## Build + sign

```bash
cd system-extension
./build.sh            # compile, assemble, ad-hoc sign into ./build
./build.sh --install  # same, then copy the app into /Applications
```

`build.sh` builds the Rust staticlib if needed (`cargo build -p enforce-ne-ffi
--release`), compiles all Swift sources as one module with the bridging header and the
crate's include dir on the clang path, links `libenforce_ne_ffi.a` plus the frameworks
the Swift side uses (`NetworkExtension`, `Security`, `CoreFoundation`,
`SystemConfiguration`), assembles the `.app` + embedded `.systemextension`, substitutes
the `Info.plist` templates, and **ad-hoc codesigns** both (`codesign -s -
--entitlements … --options runtime`).

The extension's `Info.plist` gets a `MacwardenSharedDir` key (your `~/.macwarden`),
because a system extension runs as **root** and does not inherit your `$HOME` — the
provider reads the ruleset from that baked-in path.

## Load it (interactive — this is the handoff)

The steps below are **yours to do**; they cannot be scripted (the approval is a GUI
gesture, and dev-mode toggling requires a reboot into a different SIP state).

### Option A — DEV mode (ad-hoc build, no Apple account)

An ad-hoc-signed extension only loads in **developer mode**, which **requires SIP to be
disabled**:

```bash
# 1. Reboot into Recovery (hold power on Apple silicon), open Terminal, then:
csrutil disable
#    reboot back into macOS.

# 2. Turn on system-extension developer mode:
sudo systemextensionsctl developer on

# 3. Install the host app into /Applications (sysexts must run from there):
cd system-extension && ./build.sh --install

# 4. Activate the extension:
/Applications/MacwardenFilter.app/Contents/MacOS/MacwardenFilter activate

# 5. APPROVE in the GUI when prompted:
#    System Settings > General > Login Items & Extensions > Network Extensions
#    → enable "macwarden Network Filter".
#    (The activator also enables the NEFilterManager "content filter" toggle.)
```

> **Re-enable SIP (`csrutil enable`) when you are done iterating.** Dev mode + ad-hoc
> signing is strictly for local proof.

### Option B — Developer ID (SIP stays on, no dev mode)

A **notarized** extension signed with a **Developer ID** and carrying an Apple-granted
`content-filter-provider` provisioning profile loads with **SIP enabled** and no dev
mode — this is the real distribution path. It needs two things that are **the user's to
obtain from Apple**:

- the **Network Extensions capability** (`content-filter-provider`) on your developer
  account → provisioning profile;
- a **Developer ID Application** certificate + notarization.

Swap the ad-hoc `-s -` in `build.sh` for your Developer ID identity, add the
provisioning profile, then `notarytool` staple. No code changes required.

## Verify blocking (the proof it actually drops)

The point of enforcement is that a **denied** destination fails while an **allowed** one
works, under the same provider. The provider reads `~/.macwarden/net-rules/` and reloads
on change (via `RuleWatcher`), so you can prove it with a hand-written rule — no daemon
needed, though `macwarden`'s daemon/panel writes the same files.

1. Establish a working baseline (filter active, no block):

   ```bash
   curl --max-time 5 -sSI https://example.com | head -1   # expect: HTTP/2 200
   ```

2. Write a deny rule for `curl` to that host:

   ```bash
   mkdir -p ~/.macwarden/net-rules
   cat > ~/.macwarden/net-rules/block-curl-example.toml <<'TOML'
   name    = "block curl to example.com"
   process = "/usr/bin/curl"
   dest    = "example.com"
   action  = "deny"
   TOML
   ```

   (Equivalently, use the daemon/panel — e.g. a `net block` mutation — which writes into
   the same `~/.macwarden/net-rules/` directory and hot-reloads.)

3. The `RuleWatcher` picks up the change within ~250 ms and calls `macwarden_ne_reload`.
   Now the **blocked** flow fails while an **allowed** one still works:

   ```bash
   curl --max-time 5 -sSI https://example.com   # blocked curl → times out / fails
   curl --max-time 5 -sSI https://apple.com     # allowed host → HTTP 200
   ```

   A blocked flow returns `.drop()` from `handleNewFlow`, so the connection is refused
   and `curl` reports a timeout. Watch the decisions live:

   ```bash
   log stream --predicate 'subsystem == "ai.macwarden.filter"' --info
   # → "flow com.apple.curl -> 93.184.x.x:443 proto=6 dir=out => DENY"
   ```

   The `dir=` token distinguishes **outbound** (`dir=out`, an app reaching a
   destination) from **inbound** (`dir=in`, a peer connecting to a local listening
   service) flows. Both are decided by the same `net::RuleSet` core against the
   flow's **remote** endpoint, so a rule denying a remote IP refuses an inbound
   connection from that IP exactly as it refuses an outbound one — this is the
   inbound coverage spec 010 (banwatch) rides on, at zero extra privilege.

4. Remove the rule and confirm the connection is restored:

   ```bash
   rm ~/.macwarden/net-rules/block-curl-example.toml
   curl --max-time 5 -sSI https://example.com | head -1   # back to HTTP 200
   ```

## Verify inbound blocking (spec 009 R1)

The provider filters **sockets** (`filterSockets = true`), so inbound flows to a
local listening service also reach `handleNewFlow` — decided against the flow's
**remote** (peer) endpoint. Prove it with a listener and a second machine (or a
peer on your LAN) whose IP you deny.

1. Start a local listener and note this machine's LAN IP:

   ```bash
   nc -l 9999            # a trivial TCP service on port 9999
   ```

2. From the peer at `<PEER_IP>`, confirm it connects (`nc <THIS_IP> 9999`), then
   write a rule denying that peer IP and retry — the inbound connection is now
   refused, while a connection from a *different* peer still succeeds:

   ```bash
   cat > ~/.macwarden/net-rules/block-peer.toml <<'TOML'
   name    = "block inbound scanner"
   process = "*"
   dest    = "<PEER_IP>"
   action  = "deny"
   TOML
   ```

3. Watch the direction token flip to `in` for the refused flow:

   ```bash
   log stream --predicate 'subsystem == "ai.macwarden.filter"' --info
   # → "flow ? -> <PEER_IP>:xxxxx proto=6 dir=in => DENY"
   ```

   This is exactly the mechanism spec 010 (banwatch) uses to drop a
   scanning/bruteforcing IP from a *listening* service — no extra privilege, same
   `net::RuleSet` core.

## Remove the extension

```bash
systemextensionsctl uninstall - ai.macwarden.filter.extension
# then optionally:
rm -rf /Applications/MacwardenFilter.app
```

Turn dev mode off and re-enable SIP if you used Option A:

```bash
sudo systemextensionsctl developer off
# reboot to Recovery → csrutil enable → reboot
```

## Honest status

- **Builds + ad-hoc signs cleanly today** (Swift 6, `swiftc` + `codesign`). The Rust
  decision core links in statically; `SecCode*` resolve against Security.framework;
  `codesign --verify --deep --strict` passes and the bundle satisfies its designated
  requirement.
- **Loading is the handoff.** On a SIP-enabled machine, `systemextensionsctl developer
  on` refuses ("cannot be used if System Integrity Protection is enabled"), so an
  ad-hoc build cannot load until SIP is disabled (Option A) **or** the extension is
  Developer-ID-signed + notarized + provisioned with the Apple NE entitlement (Option
  B). The final approval is always a **GUI gesture** in System Settings and cannot be
  scripted.
- **Production distribution** needs the NE `content-filter-provider` entitlement (an
  Apple request on your developer account) **and** a Developer ID certificate +
  notarization — both the user's to provide. Dev-mode + ad-hoc signing is for local
  proof only.
