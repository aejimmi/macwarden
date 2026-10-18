//! macOS menu-bar status item (`NSStatusItem`).
//!
//! Puts a monochrome shield in the system menu bar — like Little Snitch or
//! FireWally — so the panel is reachable even when its window is hidden. The
//! icon is an SF Symbol set as a *template* image, so AppKit tints it for the
//! menu bar's light/dark appearance automatically (the native look).
//!
//! Clicking the item toggles the panel: the header ✕ and [`crate::state`]-level
//! hide route through gpui's `App::hide` (which calls `-[NSApplication hide:]`),
//! so a click here queries `-isHidden` and flips it — unhide + activate to show,
//! hide to dismiss. That keeps the two affordances consistent without needing a
//! gpui handle: the whole toggle is expressed in AppKit against the shared
//! `NSApplication`, on the main thread where the action fires.
//!
//! All FFI lives here behind the crate's macOS-only build; `unsafe` blocks carry
//! `SAFETY` notes (see the sibling `icons` module for the same pattern).
#![allow(unsafe_code)]

use std::cell::RefCell;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject};
use objc2::{MainThreadMarker, MainThreadOnly, define_class, msg_send, sel};
use objc2_app_kit::{
    NSApplication, NSImage, NSStatusBar, NSStatusBarButton, NSStatusItem,
    NSVariableStatusItemLength,
};
use objc2_foundation::NSString;

/// The SF Symbol drawn in the menu bar. A half-filled shield reads clearly as a
/// firewall/guard glyph and renders crisply as a template image.
const SHIELD_SYMBOL: &str = "shield.lefthalf.filled";

thread_local! {
    /// Retains the status item and its action target for the process lifetime.
    /// AppKit holds the target *unowned*, and a released `NSStatusItem` is
    /// removed from the menu bar — so both must outlive `install`. The item is
    /// only ever touched on the main thread, so a `thread_local` is sufficient
    /// and avoids the `Send`/`Sync` bounds a `static` would demand of `Retained`.
    static STATUS_ITEM: RefCell<Option<(Retained<NSStatusItem>, Retained<StatusTarget>)>> =
        const { RefCell::new(None) };
}

define_class!(
    // SAFETY: `StatusTarget` is a plain `NSObject` subclass with no ivars and no
    // `Drop`, used only as a target/action sink on the main thread.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "MacwardenStatusTarget"]
    struct StatusTarget;

    impl StatusTarget {
        /// Menu-bar click handler wired via `-setAction:`. Toggles the panel.
        #[unsafe(method(statusItemClicked:))]
        fn status_item_clicked(&self, _sender: Option<&AnyObject>) {
            toggle_window(self.mtm());
        }
    }
);

impl StatusTarget {
    /// Allocate and initialise a target on the main thread.
    fn new(mtm: MainThreadMarker) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(());
        // SAFETY: `NSObject`'s designated initialiser applied to a freshly
        // allocated `StatusTarget` whose (empty) ivars are set.
        unsafe { msg_send![super(this), init] }
    }
}

/// Install the menu-bar status item. Best-effort: on any missing affordance it
/// logs a warning and returns, so a failure here never stops the panel running.
pub(super) fn install(mtm: MainThreadMarker) {
    let bar = NSStatusBar::systemStatusBar();
    let item = bar.statusItemWithLength(NSVariableStatusItemLength);
    let Some(button) = item.button(mtm) else {
        tracing::warn!("status item has no button; menu-bar icon unavailable");
        return;
    };
    apply_icon(&button);
    let tooltip = NSString::from_str("macwarden");
    button.setToolTip(Some(&tooltip));

    let target = StatusTarget::new(mtm);
    // SAFETY: `target` is retained for the process lifetime in `STATUS_ITEM`
    // below, so the button's unowned target reference stays valid.
    unsafe { button.setTarget(Some(&target)) };
    // SAFETY: `statusItemClicked:` is implemented on `StatusTarget` with the one
    // sender argument AppKit's target/action convention supplies.
    unsafe { button.setAction(Some(sel!(statusItemClicked:))) };

    STATUS_ITEM.with(|cell| {
        cell.borrow_mut().replace((item, target));
    });
    tracing::info!("menu-bar status item installed");
}

/// Set the button's image to the shield SF Symbol as a template image so AppKit
/// tints it for the menu bar. No-op (with a warning) if the symbol is absent.
fn apply_icon(button: &NSStatusBarButton) {
    let name = NSString::from_str(SHIELD_SYMBOL);
    let description = NSString::from_str("macwarden");
    let Some(image) =
        NSImage::imageWithSystemSymbolName_accessibilityDescription(&name, Some(&description))
    else {
        tracing::warn!(
            symbol = SHIELD_SYMBOL,
            "SF Symbol unavailable; status item has no icon"
        );
        return;
    };
    image.setTemplate(true);
    button.setImage(Some(&image));
}

/// Toggle the panel: unhide + activate when the app is hidden (the ✕ / status
/// click path calls `-hide:`), otherwise hide it.
fn toggle_window(mtm: MainThreadMarker) {
    let app = NSApplication::sharedApplication(mtm);
    if app.isHidden() {
        app.unhide(None);
        app.activate();
    } else {
        app.hide(None);
    }
}
