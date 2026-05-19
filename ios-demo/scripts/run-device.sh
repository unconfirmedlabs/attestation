#!/usr/bin/env bash
# Build, install, and launch AttestKitDemo on a paired iOS device.
#
# Usage:
#   ./scripts/run-device.sh                # picks the first paired device
#   ./scripts/run-device.sh <udid>         # targets a specific device
#
# Lists paired devices with: xcrun devicectl list devices
#
# Requirements:
#   - xcodegen (one-time): brew install xcodegen
#   - Xcode signed in to your Apple Developer team
#   - Phone paired in Xcode (Window → Devices and Simulators)

set -euo pipefail
cd "$(dirname "$0")/.."

PROJECT="AttestKitDemo.xcodeproj"
SCHEME="AttestKitDemo"
BUNDLE_ID="com.unconfirmedlabs.attestkitdemo"
DERIVED="build"

if [[ ! -d "$PROJECT" ]]; then
  echo "==> generating $PROJECT from project.yml"
  xcodegen generate
fi

# Pick the device UDID.
if [[ $# -ge 1 ]]; then
  UDID="$1"
else
  UDID=$(
    xcrun devicectl list devices 2>/dev/null \
      | awk '/available \(paired\)/ {print $(NF-2); exit}'
  )
  if [[ -z "${UDID:-}" ]]; then
    echo "no paired iOS device found. Plug in your phone and pair via Xcode."
    exit 1
  fi
fi
echo "==> target device: $UDID"

echo "==> xcodebuild build (Debug / iphoneos)"
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Debug \
  -destination "generic/platform=iOS" \
  -derivedDataPath "$DERIVED" \
  -allowProvisioningUpdates \
  build \
  CODE_SIGN_STYLE=Automatic \
  >/tmp/attestkitdemo_build.log 2>&1 \
  || { tail -40 /tmp/attestkitdemo_build.log; exit 1; }

APP="$DERIVED/Build/Products/Debug-iphoneos/AttestKitDemo.app"
[[ -d "$APP" ]] || { echo "build succeeded but $APP missing"; exit 1; }
echo "==> built $APP"

echo "==> installing on device"
xcrun devicectl device install app --device "$UDID" "$APP"

echo "==> launching"
xcrun devicectl device process launch \
  --device "$UDID" \
  --terminate-existing \
  "$BUNDLE_ID"

echo "==> done. Tap 'Attest new key' on the phone."
