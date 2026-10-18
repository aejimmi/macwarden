//! The Rules / Policy layer (R8): the header mode pill + `⋯` app-menu, the
//! popover overlay scaffolding, and the optimistic profile mutation plumbing.
//!
//! All state comes from the daemon's [`WireProfile`] (cached on [`Panel`]); all
//! edits go through the granular `Policy` requests over the [`PolicyBackend`],
//! run on the background executor so nothing blocks the render thread. Every
//! mutation applies optimistically to the cached profile, then reconciles
//! against the echoed `ProfileAck` (or re-fetches on rejection). The quick
//! popover + app menu content lives in [`super::policy_menu`]; the full Rules &
//! Settings view (groups, allow list, block list) lives in
//! [`super::rules_view`]. This module owns the trigger controls, the dismiss/Esc
//! overlay, and the async commit helpers shared by both.

use std::sync::Arc;

use gpui::prelude::FluentBuilder as _;
use gpui::{
    AnyElement, Context, InteractiveElement as _, IntoElement, KeyDownEvent, ParentElement as _,
    StatefulInteractiveElement as _, Styled as _, Window, deferred, div, px,
};
use ipc::protocol::{RuleTarget, WireAllowEntry, WireMode, WireProfile};

use super::panel::Panel;
use super::theme::{FONT_CAPTION, Palette, RADIUS, RADIUS_SM, RADIUS_XS, palette};
use super::widgets::tip;
use crate::data::source::PolicyBackend;
use crate::state::{Popover, Route};

impl Panel {
    /// Fetch the current policy profile off the render thread and cache it. A
    /// no-op when the source has no policy backend (demo / `nettop` live).
    pub(super) fn load_profile(&mut self, cx: &mut Context<Self>) {
        let Some(backend) = self.source.policy_backend() else {
            return;
        };
        self.profile_loading = true;
        self._policy_task = cx.spawn(async move |this, cx| {
            let profile = cx
                .background_executor()
                .spawn(async move { backend.get_profile() })
                .await;
            let _ = this.update(cx, |panel, cx| {
                panel.profile_loading = false;
                if let Some(profile) = profile {
                    panel.profile = Some(profile);
                    cx.notify();
                }
            });
        });
    }

    /// Retry the initial profile fetch on the refresh tick while it is still
    /// unloaded. The first `GetProfile` can lose the race against the daemon's
    /// cold snapshot scan (which warms the code-signing cache and can outlast the
    /// query timeout); without this, the header would stay stuck on "Rules". The
    /// guard on `profile_loading` avoids cancelling an in-flight fetch, and it
    /// self-stops as soon as a profile lands.
    pub(super) fn maybe_load_profile(&mut self, cx: &mut Context<Self>) {
        if self.profile.is_none() && self.policy_available && !self.profile_loading {
            self.load_profile(cx);
        }
    }

    /// Run a profile mutation off the render thread and reconcile the cached
    /// profile with the daemon's echoed truth. On success the echoed
    /// [`WireProfile`] replaces the optimistic edit; on rejection/disconnect the
    /// profile is re-fetched so the controls never drift from ground truth.
    fn run_mutation<F>(&mut self, op: F, cx: &mut Context<Self>)
    where
        F: FnOnce(Arc<dyn PolicyBackend>) -> Option<WireProfile> + Send + 'static,
    {
        let Some(backend) = self.source.policy_backend() else {
            return;
        };
        self._policy_task = cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { op(backend) })
                .await;
            let _ = this.update(cx, |panel, cx| match result {
                Some(profile) => {
                    panel.profile = Some(profile);
                    cx.notify();
                }
                None => panel.load_profile(cx),
            });
        });
    }

    /// Flip the global Allow-All / Block-All mode. Applies optimistically and
    /// drops local block/unblock overrides so the daemon's recomputed verdicts
    /// show through cleanly after the flip.
    pub(super) fn commit_mode(&mut self, mode: WireMode, cx: &mut Context<Self>) {
        if let Some(profile) = self.profile.as_mut() {
            profile.mode = mode;
        }
        self.state.clear_local_allows();
        self.run_mutation(move |b| b.set_mode(mode), cx);
    }

    /// Toggle "Allow Apple programs".
    pub(super) fn commit_apple(&mut self, allow: bool, cx: &mut Context<Self>) {
        if let Some(profile) = self.profile.as_mut() {
            profile.allow_apple_programs = allow;
        }
        self.run_mutation(move |b| b.set_apple_allow(allow), cx);
    }

    /// Toggle "Allow DNS traffic".
    pub(super) fn commit_dns(&mut self, allow: bool, cx: &mut Context<Self>) {
        if let Some(profile) = self.profile.as_mut() {
            profile.allow_dns_traffic = allow;
        }
        self.run_mutation(move |b| b.set_dns_allow(allow), cx);
    }

    /// Enable/disable a built-in network group.
    pub(super) fn commit_group(&mut self, group: String, enabled: bool, cx: &mut Context<Self>) {
        if let Some(profile) = self.profile.as_mut()
            && let Some(state) = profile.groups.iter_mut().find(|g| g.name == group)
        {
            state.enabled = enabled;
        }
        self.run_mutation(move |b| b.set_group_enabled(group, enabled), cx);
    }

    /// Add an allow-list exception. Not applied optimistically — the daemon
    /// validates and normalizes the entry, so the panel renders from the echoed
    /// profile (a rejected entry leaves the list unchanged and clears nothing).
    pub(super) fn commit_add_entry(&mut self, entry: WireAllowEntry, cx: &mut Context<Self>) {
        self.state.clear_allow_draft();
        self.run_mutation(move |b| b.add_allow_entry(entry), cx);
    }

    /// Remove an allow-list exception by value.
    pub(super) fn commit_remove_entry(&mut self, entry: WireAllowEntry, cx: &mut Context<Self>) {
        if let Some(profile) = self.profile.as_mut() {
            profile.allowlist.retain(|e| e != &entry);
        }
        self.run_mutation(move |b| b.remove_allow_entry(entry), cx);
    }

    /// Block (or unblock) a domain globally via the `SetRule` path
    /// (`RuleTarget::Domain`). The daemon has no profile field for these, so the
    /// panel tracks them locally: the row appears optimistically, then reverts
    /// with an inline error if the daemon rejects the host (e.g. a wildcard,
    /// which the current validator refuses). Runs off the render thread.
    pub(super) fn commit_block_domain(
        &mut self,
        host: String,
        block: bool,
        cx: &mut Context<Self>,
    ) {
        if block {
            self.state.add_blocked_domain(host.clone());
        } else {
            self.state.remove_blocked_domain(&host);
        }
        self.state.clear_block_error();
        let Some(backend) = self.source.detail_backend() else {
            return;
        };
        cx.spawn(async move |this, cx| {
            let target = RuleTarget::Domain { host: host.clone() };
            let applied = cx
                .background_executor()
                .spawn(async move { backend.set_rule(&target, !block) })
                .await;
            if applied {
                return;
            }
            let _ = this.update(cx, |panel, cx| {
                if block {
                    panel.state.remove_blocked_domain(&host);
                    panel.state.set_block_error(format!("couldn't add {host}"));
                } else {
                    panel.state.add_blocked_domain(host.clone());
                }
                cx.notify();
            });
        })
        .detach();
    }

    /// Open the full-panel Rules & Settings view (from the quick popover's
    /// footer link and the `⋯` menu). Closes any open popover, pushes the
    /// [`Route::Settings`] view onto the same nav stack the inspector uses, and
    /// gives it focus so Esc backs out and the add-fields receive typed keys.
    pub(super) fn open_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.state.close_popover();
        self.state.push(Route::Settings);
        self.state
            .set_settings_field(crate::state::SettingsField::None);
        window.focus(&self.rules_focus);
        cx.notify();
    }

    /// The header scope-row right control: the mode pill. Disabled (with a
    /// "requires daemon" hint) when no policy backend is live. The `⋯` app menu
    /// now lives on the titlebar row (see [`Panel::render_titlebar`]), so this
    /// row carries the mode pill alone.
    pub(super) fn render_policy_controls(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let p = palette(cx);
        self.render_mode_pill(p, cx)
    }

    /// The Tiny-Shield-style mode pill: a green "Allow" or red "Block" dot+label
    /// with a chevron, opening the quick-settings popover. Grayscale chrome — the
    /// only colour is the semantic mode dot.
    ///
    /// Honesty (spec 009 R4): the dot's colour is driven by
    /// [`Panel::enforce_mode`], not merely by whether a policy backend exists. A
    /// staged Block-All on a monitor-only daemon reads as a *neutral* "Block"
    /// with an explicit "Preview" tag — never the red "in effect" dot — so the
    /// header never claims global blocking that isn't live.
    fn render_mode_pill(&self, p: Palette, cx: &mut Context<Self>) -> impl IntoElement {
        let enabled = self.policy_available;
        let mode = self.enforce_mode();
        let (tone, label) =
            super::enforce::mode_pill_tone(mode, self.profile.as_ref().map(|pr| pr.mode));
        let dot_color = match tone {
            super::enforce::PillTone::Block => p.red,
            super::enforce::PillTone::Allow => p.accent,
            super::enforce::PillTone::Neutral => p.text_faint,
        };
        let open = self.state.popover() == Popover::Quick;
        let on_click = cx.listener(|panel, _ev, window: &mut Window, cx| {
            panel.open_popover(Popover::Quick, window, cx);
        });
        div()
            .id("mode-pill")
            .flex()
            .flex_row()
            .items_center()
            .gap(px(5.0))
            .px(px(8.0))
            .py(px(3.0))
            .rounded(RADIUS_SM)
            .bg(if open { p.sel } else { p.trough })
            .when(enabled, |el| el.cursor_pointer().on_click(on_click))
            .when(!enabled, |el| {
                el.tooltip(tip("Rules require the macwarden daemon"))
            })
            .child(div().w(px(6.0)).h(px(6.0)).rounded(RADIUS_XS).bg(dot_color))
            .child(
                div()
                    .text_size(FONT_CAPTION)
                    .text_color(if enabled { p.text } else { p.text_faint })
                    .child(label),
            )
            .when(mode.is_preview(), |el| el.child(preview_tag(p)))
            .child(div().text_size(px(8.0)).text_color(p.text_dim).child("⌄"))
    }

    /// The `⋯` app-menu glyph, opening the small app menu (Rules & Settings, Quit).
    /// Always enabled — the menu's Rules & Settings destination works whether or
    /// not a policy backend is live (the Rules view degrades gracefully). Rendered
    /// on the titlebar row's right edge by [`Panel::render_titlebar`].
    pub(super) fn render_menu_glyph(&self, p: Palette, cx: &mut Context<Self>) -> impl IntoElement {
        let open = self.state.popover() == Popover::Menu;
        let on_click = cx.listener(|panel, _ev, window: &mut Window, cx| {
            panel.open_popover(Popover::Menu, window, cx);
        });
        div()
            .id("app-menu")
            .flex()
            .items_center()
            .justify_center()
            .w(px(22.0))
            .h(px(22.0))
            .rounded(RADIUS_SM)
            .text_size(px(14.0))
            .text_color(if open { p.text } else { p.text_dim })
            .cursor_pointer()
            .hover(|s| s.bg(p.hover))
            .tooltip(tip("Menu"))
            .on_click(on_click)
            .child("⋯")
    }

    /// Open (or re-open) a header popover and give the overlay keyboard focus so
    /// Esc reaches it.
    fn open_popover(&mut self, kind: Popover, window: &mut Window, cx: &mut Context<Self>) {
        self.state.toggle_popover(kind);
        if self.state.popover() != Popover::None {
            window.focus(&self.policy_focus);
        }
        cx.notify();
    }

    /// The deferred, dismiss-on-outside-click overlay hosting whichever popover
    /// is open. `None` when nothing is open or no policy backend is live.
    pub(super) fn render_policy_overlay(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let popover = self.state.popover();
        let content = match popover {
            Popover::Quick if self.policy_available => {
                self.render_quick_popover(cx).into_any_element()
            }
            Popover::Menu => Self::render_menu_popover(cx).into_any_element(),
            _ => return None,
        };
        let on_dismiss = cx.listener(|panel, _ev, _win, cx| {
            panel.state.close_popover();
            cx.notify();
        });
        let on_key = cx.listener(Self::on_policy_key);
        // Anchor each popover just under its trigger: the `⋯` menu hangs off the
        // 36px titlebar (top ~40), the quick popover off the mode pill on the
        // scope row below (top ~74). Both right-aligned to the window edge.
        let top = match popover {
            Popover::Menu => px(40.0),
            _ => px(74.0),
        };
        let overlay = div()
            .absolute()
            .inset_0()
            .track_focus(&self.policy_focus)
            .on_key_down(on_key)
            .child(
                div()
                    .id("policy-backdrop")
                    .absolute()
                    .inset_0()
                    .on_click(on_dismiss),
            )
            .child(
                div()
                    .absolute()
                    .top(top)
                    .right(px(8.0))
                    .occlude()
                    .child(content),
            );
        Some(deferred(overlay).with_priority(1).into_any_element())
    }

    /// Route key presses while a header popover is open: Esc closes it. The
    /// popovers carry no text input (the add-fields moved to the Rules view), so
    /// nothing else is captured here.
    fn on_policy_key(
        &mut self,
        event: &KeyDownEvent,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if event.keystroke.key.as_str() == "escape" {
            self.state.close_popover();
            cx.notify();
        }
    }
}

/// A shared translucent popover card: a raised, near-opaque dark surface with a
/// hairline border, matching the panel's material treatment (the vibrant
/// desktop reads faintly through the window behind it).
pub(super) fn popover_card(p: Palette) -> gpui::Div {
    div()
        .flex()
        .flex_col()
        .w(px(248.0))
        .p(px(10.0))
        .gap(px(8.0))
        .rounded(RADIUS)
        .bg(p.bg.opacity(0.97))
        .border_1()
        .border_color(p.hairline)
}

/// The explicit "Preview" tag beside the mode pill when a daemon is attached but
/// not enforcing (monitor-only — today's default, or a stale daemon). Grayscale
/// micro-caps in a faint trough, so the header honestly discloses that staged
/// rules are not live — mirroring the trace view's live-vs-demo disclosure.
fn preview_tag(p: Palette) -> impl IntoElement {
    div()
        .px(px(4.0))
        .py(px(1.0))
        .rounded(RADIUS_XS)
        .bg(p.trough)
        .text_size(px(8.0))
        .text_color(p.text_faint)
        .child("PREVIEW")
}

/// A popover section heading — the same faint micro-caps used by the inspector.
pub(super) fn popover_title(p: Palette, label: &'static str) -> impl IntoElement {
    div()
        .text_size(px(10.0))
        .text_color(p.text_faint)
        .child(label)
}

/// Extract a single printable character from a keystroke, or `None` for control
/// keys. Uses the platform-resolved `key_char` so shifted symbols type correctly.
pub(super) fn printable_char(event: &KeyDownEvent) -> Option<String> {
    let ch = event.keystroke.key_char.as_ref()?;
    if ch.chars().count() != 1 {
        return None;
    }
    let c = ch.chars().next()?;
    (!c.is_control()).then(|| ch.clone())
}
