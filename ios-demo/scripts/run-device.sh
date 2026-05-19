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

# Pick the device's modern Core Device UUID (for install/launch).
if [[ $# -ge 1 ]]; then
  CORE_UDID="$1"
else
  CORE_UDID=$(
    xcrun devicectl list devices 2>/dev/null \
      | grep "available (paired)" \
      | grep -oE "[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" \
      | head -1
  )
  if [[ -z "${CORE_UDID:-}" ]]; then
    echo "no paired iOS device found. Plug in your phone and pair via Xcode."
    exit 1
  fi
fi
echo "==> target device (Core UDID): $CORE_UDID"

# The legacy 40-char UDID is what provisioning profiles use. xctrace knows it.
# The first online iPhone entry maps to whichever phone is connected; for
# multi-device setups, pass the legacy UDID via env LEGACY_UDID instead.
LEGACY_UDID="${LEGACY_UDID:-$(
  # Prefer the online block, then fall back to the offline block — xctrace's
  # online/offline tracking lags behind reality. devicectl is authoritative
  # for "is the device reachable now?" but xctrace is the only place that
  # exposes the legacy UDID that provisioning profiles use.
  xcrun xctrace list devices 2>&1 \
    | awk '/^== Devices ==/{section="online"} /^== Devices Offline ==/{section="offline"} /^== Simulators ==/{section=""} section=="online" || section=="offline" {print}' \
    | grep -E "^iPhone " \
    | head -1 \
    | grep -oE "\([0-9A-Fa-f-]+\)[[:space:]]*$" \
    | tr -d '()' \
    || true
)}"
if [[ -z "${LEGACY_UDID:-}" ]]; then
  echo "could not detect legacy UDID via xctrace; pass it as: LEGACY_UDID=... ./scripts/run-device.sh"
  exit 1
fi
echo "==> target device (legacy UDID): $LEGACY_UDID"

echo "==> xcodebuild build (Debug / iphoneos, device-targeted for auto-provisioning)"
xcodebuild \
  -project "$PROJECT" \
  -scheme "$SCHEME" \
  -configuration Debug \
  -destination "platform=iOS,id=$LEGACY_UDID" \
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
xcrun devicectl device install app --device "$CORE_UDID" "$APP"

echo "==> launching"
xcrun devicectl device process launch \
  --device "$CORE_UDID" \
  --terminate-existing \
  "$BUNDLE_ID"

echo "==> done. Tap 'Attest new key' on the phone."
