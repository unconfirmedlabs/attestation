#!/usr/bin/env bash
# Pull every dev_iphone_*.json fixture out of the AttestKitDemo app sandbox
# and copy into the attest-apple integration test fixtures directory.
#
# Usage:
#   ./scripts/pull-fixtures.sh                # picks the first paired device
#   ./scripts/pull-fixtures.sh <Core-UDID>    # targets a specific device

set -euo pipefail
cd "$(dirname "$0")/.."

BUNDLE_ID="com.unconfirmedlabs.attestkitdemo"
DEST_DIR="../rust/attest-apple/tests/fixtures"
mkdir -p "$DEST_DIR"

if [[ $# -ge 1 ]]; then
  UDID="$1"
else
  UDID=$(
    xcrun devicectl list devices 2>/dev/null \
      | grep "available (paired)" \
      | grep -oE "[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}" \
      | head -1
  )
fi
if [[ -z "${UDID:-}" ]]; then
  echo "no paired iOS device found"
  exit 1
fi
echo "==> device: $UDID"

# Pull the entire Documents directory out of the app sandbox.
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "==> copying Documents/ from sandbox"
xcrun devicectl device copy from \
  --device "$UDID" \
  --user mobile \
  --domain-type appDataContainer \
  --domain-identifier "$BUNDLE_ID" \
  --source Documents \
  --destination "$STAGE" \
  2>&1 | tail -5

# Move fixture JSONs into the test fixtures directory.
shopt -s nullglob
moved=0
for f in "$STAGE"/dev_iphone_*.json "$STAGE"/Documents/dev_iphone_*.json; do
  cp "$f" "$DEST_DIR/$(basename "$f")"
  echo "  pulled $(basename "$f")"
  moved=$((moved+1))
done

if [[ $moved -eq 0 ]]; then
  echo "no fixtures found in app sandbox. Tap 'Attest new key' on the device first."
  exit 1
fi

echo "==> $moved fixture(s) → $DEST_DIR"
