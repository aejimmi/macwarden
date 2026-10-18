//! Honest enforcement-state probe (spec 009 R2).
//!
//! The daemon must not claim it is enforcing network policy unless the
//! NetworkExtension content filter is *actually* activated **and** enabled. This
//! module answers that question by shelling `systemextensionsctl list` — the same
//! "ask the platform's own tool" pattern the future `pf` backend uses for
//! `pfctl` — and looking for the macwarden filter extension in an
//! `[activated enabled]` state.
//!
//! The probe is **total and fail-safe**: a missing tool, a non-zero exit,
//! malformed output, or any ambiguity yields "not enforcing". It must never
//! report a false "live", because the panel drops its "preview only" honesty hint
//! on this signal alone (spec 009 threat model: the tool must not imply protection
//! it does not have).

use std::process::Command;

use tracing::debug;

/// Absolute path to the platform tool (spec 009 R5). Resolving
/// `systemextensionsctl` via `PATH` would let a binary planted earlier in `PATH`
/// spoof a false "enforcing" verdict and strip the panel's "preview only" hint;
/// the absolute path is not attacker-controllable.
const SYSTEMEXTENSIONSCTL: &str = "/usr/bin/systemextensionsctl";

/// Bundle identifier of the macwarden content-filter system extension, as embedded
/// in `system-extension/Extension/Info.plist.in` and registered with
/// `OSSystemExtensionRequest`.
const NE_EXTENSION_ID: &str = "ai.macwarden.filter.extension";

/// The state token `systemextensionsctl list` prints for a sysext that is both
/// activated and enabled (i.e. genuinely running and filtering).
const ACTIVE_STATE: &str = "[activated enabled]";

/// Zero-based index of the bundle-id column in a `systemextensionsctl list` data
/// row. Rows are tab-separated:
///
/// ```text
/// enabled  active  teamID  bundleID (version)  name  [state]
///    0       1       2            3              4      5
/// ```
///
/// The bundle id is the first whitespace-separated token of column 3 (the
/// trailing `(version)` is dropped). Matching there — rather than anywhere on the
/// line — stops an unrelated extension whose *name* column happens to equal our
/// bundle id from reading as "enforcing" (spec 009 R2 column bug).
const BUNDLE_ID_COLUMN: usize = 3;

/// Whether the macwarden NetworkExtension content filter is activated and enabled
/// on this machine.
///
/// Shells `systemextensionsctl list` and parses its output. Any failure (tool
/// absent, non-macOS host, non-zero exit, unreadable output) fails safe to
/// `false` — the daemon then withholds [`ipc::protocol::Capability::NetworkEnforcement`]
/// and the panel keeps its preview hint.
#[must_use]
pub fn network_enforcement_active() -> bool {
    let output = match Command::new(SYSTEMEXTENSIONSCTL).arg("list").output() {
        Ok(output) if output.status.success() => output.stdout,
        Ok(output) => {
            debug!(
                code = output.status.code(),
                "systemextensionsctl list exited non-zero; treating as not enforcing"
            );
            return false;
        }
        Err(e) => {
            debug!(error = %e, "systemextensionsctl unavailable; treating as not enforcing");
            return false;
        }
    };

    let text = String::from_utf8_lossy(&output);
    parse_enforcement_active(&text)
}

/// Pure parse of `systemextensionsctl list` output: `true` only when a data row
/// carries the macwarden bundle id **in its bundle-id column** (not merely
/// anywhere on the line) **and** the `[activated enabled]` state token in a
/// column to the right of it.
///
/// Kept separate from the shell-out so it is unit-testable over fixture strings on
/// any host (Linux CI included).
#[must_use]
fn parse_enforcement_active(output: &str) -> bool {
    output.lines().any(is_enforcing_row)
}

/// Whether one `systemextensionsctl list` line is the macwarden extension in the
/// activated-and-enabled state, parsed by tab-separated column position.
///
/// Fail-safe by construction: a line without at least a bundle-id column and a
/// distinct state column to its right returns `false`, as does any bundle id that
/// is not exactly [`NE_EXTENSION_ID`] in [`BUNDLE_ID_COLUMN`].
fn is_enforcing_row(line: &str) -> bool {
    let fields: Vec<&str> = line.split('\t').collect();

    // The state must live in a column strictly right of the bundle-id column;
    // a shorter row is a header/separator/garbage line, never an active row.
    if fields.len() <= BUNDLE_ID_COLUMN + 1 {
        return false;
    }

    let bundle_id = fields
        .get(BUNDLE_ID_COLUMN)
        .and_then(|col| col.split_whitespace().next());
    if bundle_id != Some(NE_EXTENSION_ID) {
        return false;
    }

    // State is the rightmost column. `contains` (not `==`) tolerates a trailing
    // annotation after the token; `[activated]`/`[enabled]` alone do not match.
    fields
        .last()
        .is_some_and(|state| state.contains(ACTIVE_STATE))
}

#[cfg(test)]
#[path = "enforcement_test.rs"]
mod enforcement_test;
