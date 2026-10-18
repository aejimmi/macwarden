#!/usr/bin/env bash
#
# Assemble a minimal, double-clickable macwarden.app bundle (dev, UNSIGNED).
#
# Layout:
#   macwarden.app/Contents/Info.plist
#   macwarden.app/Contents/MacOS/macwarden   (CFBundleExecutable — one binary)
#
# `macwarden` is a single binary: launched with no args it opens the panel, which
# auto-starts the daemon by re-invoking itself with `serve` (see
# crates/macwarden-ui ui::ensure), so "open macwarden.app" is all it takes.
# This bundle is NOT signed or notarized:
# Gatekeeper will require a one-time right-click -> Open. A signed/notarized build
# with an SMAppService privileged daemon is the real distribution path (later,
# gated on a Developer ID cert and the Endpoint Security entitlement approval).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Resolve the cargo target directory (honors CARGO_TARGET_DIR / .cargo config).
TARGET_DIR="$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
RELEASE_DIR="$TARGET_DIR/release"

VERSION="$(cargo metadata --no-deps --format-version 1 \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')"

APP="$TARGET_DIR/macwarden.app"
MACOS_DIR="$APP/Contents/MacOS"

echo "==> Building release binary (macwarden)"
cargo build --release -p macwarden

MACWARDEN_BIN="$RELEASE_DIR/macwarden"
if [[ ! -x "$MACWARDEN_BIN" ]]; then
  echo "error: expected binary not found: $MACWARDEN_BIN" >&2
  exit 1
fi

echo "==> Assembling $APP"
rm -rf "$APP"
mkdir -p "$MACOS_DIR"
cp "$MACWARDEN_BIN" "$MACOS_DIR/macwarden"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>macwarden</string>
    <key>CFBundleDisplayName</key>
    <string>macwarden</string>
    <key>CFBundleIdentifier</key>
    <string>com.macwarden.panel</string>
    <key>CFBundleExecutable</key>
    <string>macwarden</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundleVersion</key>
    <string>${VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${VERSION}</string>
    <key>LSMinimumSystemVersion</key>
    <string>13.0</string>
    <key>LSUIElement</key>
    <true/>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

echo "==> Done: $APP"
echo
echo "Launch it with:  open \"$APP\""
echo
echo "NOTE: this bundle is UNSIGNED (dev). The first launch, Gatekeeper will"
echo "block it — right-click the .app in Finder and choose Open, then Open again."
echo "Opening the app launches the panel, which auto-starts the daemon by"
echo "re-invoking 'macwarden serve'; the daemon persists after you quit the"
echo "panel, as a firewall should."
