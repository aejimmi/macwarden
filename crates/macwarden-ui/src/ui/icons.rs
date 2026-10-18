//! Real application icons via `NSWorkspace`, cached by path.
//!
//! `NSWorkspace iconForFile:` yields the Finder icon for any bundle or
//! executable. We draw it into a fixed-size, non-premultiplied RGBA bitmap,
//! swap to BGRA (the byte order `gpui::RenderImage` expects), and wrap it as a
//! render image. Extraction is an AppKit main-thread call, so it happens lazily
//! during render and every result — hit or miss — is memoised by path.
//!
//! This module is inherently an FFI boundary, so `unsafe` is expected; blocks
//! carry `SAFETY` notes and the pixel copy performs several raw-pointer ops per
//! block by nature.
#![allow(unsafe_code)]
#![allow(clippy::multiple_unsafe_ops_per_block)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gpui::RenderImage;
use image::{Frame, RgbaImage};
use objc2::AllocAnyThread;
use objc2_app_kit::{
    NSBitmapFormat, NSBitmapImageRep, NSCalibratedRGBColorSpace, NSCompositingOperation,
    NSGraphicsContext, NSImage, NSWorkspace,
};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};
use smallvec::SmallVec;

/// Device-pixel side length of the rasterised icon. Rendered oversized so the
/// 22px row tile and 40px inspector tile both stay crisp on Retina.
const RASTER_SIDE: u32 = 64;

/// A per-panel cache mapping an icon-source path to its render image.
///
/// A `None` value memoises a failed extraction so we do not re-hit AppKit for a
/// path that has no icon.
pub struct IconCache {
    entries: RefCell<HashMap<PathBuf, Option<Arc<RenderImage>>>>,
}

impl Default for IconCache {
    fn default() -> Self {
        Self::new()
    }
}

impl IconCache {
    /// Build an empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: RefCell::new(HashMap::new()),
        }
    }

    /// Resolve the icon for `path`, loading and caching on first request.
    ///
    /// The lookup key is first upgraded to the enclosing `.app` bundle root (see
    /// [`resolve_app_bundle`]) so a binary buried inside a bundle — the daemon's
    /// per-connection executable path — still renders the real app icon rather
    /// than the generic executable glyph, exactly as the list rows do.
    #[must_use]
    pub fn get(&self, path: &Path) -> Option<Arc<RenderImage>> {
        let resolved = resolve_app_bundle(path);
        let key: &Path = resolved.as_deref().unwrap_or(path);
        if let Some(hit) = self.entries.borrow().get(key) {
            return hit.clone();
        }
        let icon = load_icon(key);
        self.entries
            .borrow_mut()
            .insert(key.to_path_buf(), icon.clone());
        icon
    }
}

/// Upgrade an executable path to the root of its enclosing `.app` bundle so the
/// panel renders the real app icon for a binary buried inside the bundle
/// (`…/Spotify.app/Contents/MacOS/Spotify` → `…/Spotify.app`). Mirrors the
/// daemon-side resolver and is idempotent for a path that is already an `.app`
/// root. Returns `None` when no path component ends in `.app` — a bare Unix
/// daemon or CLI keeps its honest generic executable icon.
fn resolve_app_bundle(path: &Path) -> Option<PathBuf> {
    let s = path.to_str()?;
    let marker = s.find(".app/")?;
    Some(PathBuf::from(&s[..marker + ".app".len()]))
}

#[cfg(test)]
#[path = "icons_test.rs"]
mod icons_test;

fn load_icon(path: &Path) -> Option<Arc<RenderImage>> {
    let path_str = path.to_str()?;
    // SAFETY: AppKit calls on the main thread; the render loop is main-thread.
    unsafe {
        let ns_path = NSString::from_str(path_str);
        let workspace = NSWorkspace::sharedWorkspace();
        let image = workspace.iconForFile(&ns_path);
        rasterize(&image)
    }
}

/// Draw `image` into a known-format RGBA bitmap and convert to a render image.
///
/// # Safety
///
/// Must be called on the AppKit main thread. Mutates the process-global
/// graphics context between save/restore.
unsafe fn rasterize(image: &NSImage) -> Option<Arc<RenderImage>> {
    let side = RASTER_SIDE as isize;
    // SAFETY: all scalar arguments describe a well-formed 32-bit RGBA bitmap and
    // `planes` is null, asking AppKit to allocate its own backing store.
    let rep = unsafe {
        NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bitmapFormat_bytesPerRow_bitsPerPixel(
            NSBitmapImageRep::alloc(),
            std::ptr::null_mut(),
            side,
            side,
            8,
            4,
            true,
            false,
            NSCalibratedRGBColorSpace,
            // Premultiplied alpha (format 0): CoreGraphics bitmap contexts
            // reject non-premultiplied reps, returning a nil context.
            NSBitmapFormat(0),
            side * 4,
            32,
        )
    }?;

    let context = NSGraphicsContext::graphicsContextWithBitmapImageRep(&rep)?;
    NSGraphicsContext::saveGraphicsState_class();
    NSGraphicsContext::setCurrentContext(Some(&context));
    let dest = NSRect::new(
        NSPoint::new(0.0, 0.0),
        NSSize::new(f64::from(RASTER_SIDE), f64::from(RASTER_SIDE)),
    );
    let zero = NSRect::new(NSPoint::new(0.0, 0.0), NSSize::new(0.0, 0.0));
    image.drawInRect_fromRect_operation_fraction(
        dest,
        zero,
        NSCompositingOperation::SourceOver,
        1.0,
    );
    NSGraphicsContext::restoreGraphicsState_class();

    // SAFETY: `rep` was just initialised as an RGBA bitmap of side RASTER_SIDE.
    let buffer = unsafe { copy_bgra(&rep) }?;
    let rgba = RgbaImage::from_raw(RASTER_SIDE, RASTER_SIDE, buffer)?;
    let frames: SmallVec<[Frame; 1]> = SmallVec::from_elem(Frame::new(rgba), 1);
    Some(Arc::new(RenderImage::new(frames)))
}

/// Convert a premultiplied RGBA pixel back to straight alpha in place.
fn unpremultiply(pixel: &mut [u8]) {
    let [r, g, b, a] = pixel else { return };
    let alpha = u32::from(*a);
    if alpha == 0 || alpha == 255 {
        return;
    }
    for channel in [r, g, b] {
        *channel = ((u32::from(*channel) * 255 + alpha / 2) / alpha).min(255) as u8;
    }
}

/// Copy the rep's rows into a tightly packed buffer and swap R/B to BGRA.
///
/// # Safety
///
/// `rep` must own a valid RGBA bitmap of side [`RASTER_SIDE`].
unsafe fn copy_bgra(rep: &NSBitmapImageRep) -> Option<Vec<u8>> {
    let data = rep.bitmapData();
    if data.is_null() {
        return None;
    }
    let width = RASTER_SIDE as usize;
    let row_bytes = rep.bytesPerRow() as usize;
    if row_bytes < width * 4 {
        return None;
    }
    let mut buffer = vec![0u8; width * width * 4];
    for (y, dst) in buffer.chunks_exact_mut(width * 4).enumerate() {
        // SAFETY: `y` is bounded by the row count and each row holds
        // `width * 4` bytes within the rep's `row_bytes` stride.
        let src = unsafe { std::slice::from_raw_parts(data.add(y * row_bytes), width * 4) };
        dst.copy_from_slice(src);
    }
    for pixel in buffer.chunks_exact_mut(4) {
        unpremultiply(pixel);
        pixel.swap(0, 2);
    }
    Some(buffer)
}
