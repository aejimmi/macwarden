#!/usr/bin/env bash
#
# build.sh — compile, assemble, and ad-hoc-sign the macwarden content-filter
# system extension and its host/activator app.
#
# This is a transparent swiftc + codesign pipeline (no Xcode project) so every
# step is reviewable. It does NOT touch the Rust workspace beyond building the
# already-existing staticlib target `enforce-ne-ffi`.
#
# Output:
#   system-extension/build/MacwardenFilter.app
#     Contents/MacOS/MacwardenFilter                              (activator)
#     Contents/Library/SystemExtensions/
#       ai.macwarden.filter.extension.systemextension            (the sysext)
#
# Usage:
#   ./build.sh            build + ad-hoc sign into ./build
#   ./build.sh --install  also copy the app to /Applications (may prompt sudo)
#
set -euo pipefail

# --- Layout -----------------------------------------------------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$HERE/.." && pwd)"
BUILD="$HERE/build"

APP_ID="ai.macwarden.filter"
EXT_ID="ai.macwarden.filter.extension"
APP_NAME="MacwardenFilter"
APP_BUNDLE="$BUILD/$APP_NAME.app"
EXT_BUNDLE="$APP_BUNDLE/Contents/Library/SystemExtensions/$EXT_ID.systemextension"

VERSION="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$REPO_ROOT/Cargo.toml" | head -1)"
VERSION="${VERSION:-0.1.0}"
SHARED_DIR="${MACWARDEN_HOME:-$HOME/.macwarden}"

# Prefer release staticlib; fall back to debug; build release if neither exists.
LIB_DIR="$REPO_ROOT/target/release"
if [[ ! -f "$LIB_DIR/libenforce_ne_ffi.a" ]]; then
    if [[ -f "$REPO_ROOT/target/debug/libenforce_ne_ffi.a" ]]; then
        LIB_DIR="$REPO_ROOT/target/debug"
    else
        echo "==> building enforce-ne-ffi staticlib (release)"
        (cd "$REPO_ROOT" && cargo build -p enforce-ne-ffi --release)
        LIB_DIR="$REPO_ROOT/target/release"
    fi
fi
INCLUDE_DIR="$REPO_ROOT/crates/enforce-ne-ffi/include"
SDK="$(xcrun --show-sdk-path)"

echo "==> repo:      $REPO_ROOT"
echo "==> staticlib: $LIB_DIR/libenforce_ne_ffi.a"
echo "==> shared:    $SHARED_DIR"
echo "==> version:   $VERSION"

rm -rf "$BUILD"
mkdir -p "$APP_BUNDLE/Contents/MacOS"
mkdir -p "$EXT_BUNDLE/Contents/MacOS"

# --- Compile the system extension -------------------------------------------
# Thin Swift provider; links the Rust decision core + the frameworks the Swift
# side uses. The Rust staticlib itself only needs libSystem (verified via nm:
# its sole non-Rust undefined symbol is _rust_eh_personality).
echo "==> compiling system extension"
swiftc \
    -sdk "$SDK" \
    -target "arm64-apple-macosx11.0" \
    -O -whole-module-optimization \
    -import-objc-header "$HERE/Extension/Bridging-Header.h" \
    -Xcc -I"$INCLUDE_DIR" \
    -o "$EXT_BUNDLE/Contents/MacOS/$EXT_ID" \
    "$HERE/Extension/main.swift" \
    "$HERE/Extension/FilterDataProvider.swift" \
    "$HERE/Extension/CodeIdentity.swift" \
    "$HERE/Extension/Destination.swift" \
    "$HERE/Extension/RuleWatcher.swift" \
    -L "$LIB_DIR" -lenforce_ne_ffi \
    -framework NetworkExtension \
    -framework Security \
    -framework CoreFoundation \
    -framework SystemConfiguration

# --- Compile the host app / activator ---------------------------------------
echo "==> compiling activator app"
swiftc \
    -sdk "$SDK" \
    -target "arm64-apple-macosx11.0" \
    -O \
    -o "$APP_BUNDLE/Contents/MacOS/$APP_NAME" \
    "$HERE/App/main.swift" \
    -framework SystemExtensions \
    -framework NetworkExtension

# --- Info.plists (substitute placeholders) ----------------------------------
echo "==> writing Info.plists"
sed -e "s|@@VERSION@@|$VERSION|g" \
    -e "s|@@SHARED_DIR@@|$SHARED_DIR|g" \
    "$HERE/Extension/Info.plist.in" > "$EXT_BUNDLE/Contents/Info.plist"
sed -e "s|@@VERSION@@|$VERSION|g" \
    "$HERE/App/Info.plist.in" > "$APP_BUNDLE/Contents/Info.plist"

# --- Ad-hoc codesign (inside-out: extension first, then the app) ------------
# `-s -` is the ad-hoc identity. --options runtime enables the hardened runtime.
# The entitlements are embedded so the OS sees the NE + install capabilities.
echo "==> ad-hoc signing extension"
codesign --force -s - \
    --entitlements "$HERE/Extension/Extension.entitlements" \
    --options runtime \
    --timestamp=none \
    "$EXT_BUNDLE"

echo "==> ad-hoc signing app"
codesign --force -s - \
    --entitlements "$HERE/App/App.entitlements" \
    --options runtime \
    --timestamp=none \
    "$APP_BUNDLE"

echo "==> verifying signatures"
codesign -dv --entitlements - "$EXT_BUNDLE" 2>&1 | sed 's/^/    ext: /' || true
codesign -dv --entitlements - "$APP_BUNDLE" 2>&1 | sed 's/^/    app: /' || true

# --- Optional install into /Applications ------------------------------------
if [[ "${1:-}" == "--install" ]]; then
    echo "==> installing to /Applications (system extensions must run from there)"
    DEST="/Applications/$APP_NAME.app"
    if [[ -w /Applications ]]; then
        rm -rf "$DEST"
        cp -R "$APP_BUNDLE" "$DEST"
    else
        sudo rm -rf "$DEST"
        sudo cp -R "$APP_BUNDLE" "$DEST"
    fi
    echo "    installed: $DEST"
fi

cat <<EOF

==> BUILD COMPLETE
    app bundle:     $APP_BUNDLE
    extension:      $EXT_BUNDLE

Next steps (these are MANUAL / interactive — see system-extension/README.md):
  1. sudo systemextensionsctl developer on     # requires SIP DISABLED
  2. cp -R "$APP_BUNDLE" /Applications/         # or re-run: ./build.sh --install
  3. /Applications/$APP_NAME.app/Contents/MacOS/$APP_NAME activate
  4. Approve "macwarden Network Filter" in System Settings > General >
     Login Items & Extensions > Network Extensions.
  5. Verify: write a block rule (daemon/panel -> ~/.macwarden/net-rules),
     then confirm a blocked app's connection fails while allowed ones work.

Remove with:
  systemextensionsctl uninstall - $EXT_ID
EOF
