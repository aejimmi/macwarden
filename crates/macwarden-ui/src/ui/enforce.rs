//! The panel's **enforcement posture** — the single honest answer to "are
//! block/allow toggles actually in effect?" (spec 009 R4).
//!
//! Every enforcement-implying control in the panel — the app/domain block
//! switches, the per-destination verdict dot, and the header mode pill — reads
//! its truth from one [`EnforceMode`], derived once per render from the active
//! source via [`Panel::enforce_mode`]. This is the fix for the systemic honesty
//! defect where the UI presented the daemon's *belief* as enforced reality: a
//! monitor-only daemon (Policy but no `NetworkEnforcement` — today's default)
//! rendered as a fully "live, enforcing" firewall, and a dead daemon's last
//! capabilities kept the controls green indefinitely.
//!
//! The rule, per the monochrome brand (grayscale chrome, colour = meaning): only
//! [`EnforceMode::Enforcing`] may paint an active block (a red "Blocked" verdict
//! dot, a red "Block" mode pill). When policy exists but the network filter is
//! not active we render an explicit [`EnforceMode::Preview`] state — the toggle
//! stages a rule that "will apply when enforcement is on", never a live block —
//! mirroring the honest live-vs-demo disclosure the trace view already does.

use ipc::protocol::WireMode;

use super::panel::Panel;
use crate::data::model::Verdict;

/// The panel's enforcement posture, derived from the active source. Ordered from
/// strongest to weakest guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EnforceMode {
    /// A **live** daemon advertising `NetworkEnforcement`: the NetworkExtension
    /// content filter is active, so block/allow toggles enforce immediately. The
    /// only state that may render an active block (red verdict dot / mode pill).
    Enforcing,
    /// Policy can be staged (a live daemon/policy backend, or a live monitor)
    /// but the network filter is **not** active — a monitor-only daemon, or a
    /// daemon that has gone stale. Toggles preview a rule; nothing is blocked
    /// yet. Honest grayscale — never a green "enforcing" affordance or a
    /// fabricated red "Blocked" dot.
    Preview,
    /// No live source and no policy backend (demo). Toggles are illustrative
    /// local previews only.
    Inactive,
}

impl EnforceMode {
    /// Derive the posture from the three source signals the panel already
    /// exposes. Pure so the mapping is unit-tested rather than depending on a
    /// GPUI render:
    /// - `enforcing`: [`crate::data::source::PanelSource::enforcement_active`] —
    ///   a live daemon with the `NetworkEnforcement` capability.
    /// - `live`: [`crate::data::source::PanelSource::is_live`] — a real source
    ///   whose worker is currently connected (false once a daemon goes stale).
    /// - `policy_available`: the source exposes a policy backend, so rules can be
    ///   staged even while the filter is off.
    #[must_use]
    pub(super) fn derive(enforcing: bool, live: bool, policy_available: bool) -> Self {
        if enforcing {
            Self::Enforcing
        } else if live || policy_available {
            Self::Preview
        } else {
            Self::Inactive
        }
    }

    /// Whether a block/allow toggle renders as a **real, in-effect** block. Only
    /// [`Self::Enforcing`] does — in every other state a "blocked" toggle is
    /// staged, not live, so the row must never fabricate a red "Blocked" verdict.
    #[must_use]
    pub(super) fn shows_live_verdict(self) -> bool {
        matches!(self, Self::Enforcing)
    }

    /// Whether to surface the explicit "Preview" affordance — a staging daemon
    /// whose filter is off. Distinguishes today's monitor-only default from both
    /// a truly enforcing firewall and the inert demo stream.
    #[must_use]
    pub(super) fn is_preview(self) -> bool {
        matches!(self, Self::Preview)
    }
}

/// The semantic tone of the header mode-pill dot. Kept abstract (not a
/// [`super::theme::Palette`] colour) so the pill decision is a pure, unit-tested
/// mapping; [`super::policy`] resolves the tone to a colour at render time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PillTone {
    /// An active Block-All that is genuinely enforcing — the only red state.
    Block,
    /// Allow-All: traffic flows, which is accurate in every posture.
    Allow,
    /// A staged-but-not-live mode (Block-All while previewing) or no profile yet
    /// — grayscale, so the pill never claims a block that isn't in effect.
    Neutral,
}

/// The mode pill's dot tone and label for the current posture and staged mode.
/// A `BlockAll` is red **only** while enforcing; staged in preview it reads as a
/// neutral (grayscale) "Block" so the header never claims global blocking that
/// isn't live. Pure, so the honesty invariant is unit-tested.
#[must_use]
pub(super) fn mode_pill_tone(
    mode: EnforceMode,
    wire: Option<WireMode>,
) -> (PillTone, &'static str) {
    match wire {
        Some(WireMode::BlockAll) if mode.shows_live_verdict() => (PillTone::Block, "Block"),
        Some(WireMode::BlockAll) => (PillTone::Neutral, "Block"),
        Some(WireMode::AllowAll) => (PillTone::Allow, "Allow"),
        None => (PillTone::Neutral, "Rules"),
    }
}

/// The verdict dot to render for a destination given the toggle's effective
/// `allowed` state and the observed `real` verdict. A blocked toggle paints the
/// red "Blocked" dot **only** while enforcing; in every other posture the row
/// shows the real observed verdict (traffic is still flowing — nothing is
/// actually blocked), so the UI never fabricates a block. Pure and unit-tested.
#[must_use]
pub(super) fn shown_verdict(mode: EnforceMode, allowed: bool, real: Verdict) -> Verdict {
    if !allowed && mode.shows_live_verdict() {
        Verdict::Blocked
    } else {
        real
    }
}

impl Panel {
    /// The single shared enforcement predicate (spec 009 R4). Derived from the
    /// active source and threaded into every block/allow control, verdict dot,
    /// and the mode pill so the panel never claims a block is in effect when it
    /// isn't. Degrades correctly off a dead daemon: once the source is stale
    /// both `enforcement_active` and `is_live` read false, dropping the posture
    /// from `Enforcing` to `Preview`.
    #[must_use]
    pub(super) fn enforce_mode(&self) -> EnforceMode {
        EnforceMode::derive(
            self.source.enforcement_active(),
            self.source.is_live(),
            self.policy_available,
        )
    }
}

#[cfg(test)]
#[path = "enforce_test.rs"]
mod enforce_test;
