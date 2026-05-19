# AttestKitDemo

A tiny SwiftUI app for exercising both Apple App Attest verbs from a physical iOS device:

1. **Attestation** — `DCAppAttestService.attestKey`. One-time hardware proof, signed by Apple's PKI.
2. **Assertion** — `DCAppAttestService.generateAssertion`. Per-payload signature by the previously-attested Secure Enclave key.

Captures land in the app's `Documents/` sandbox as JSON fixtures the host pulls via `xcrun devicectl`. The fixtures feed `rust/attest-apple/tests/fixtures/` and drive end-to-end verification of the `attest-apple` crate (and, ultimately, the on-chain `attest_apple::attestation` / `attest_apple::assertion` Move modules).

App Attest is **not** available in the iOS Simulator. You must run on a real device. A paid Apple Developer Program membership is required — App Attest's entitlement is gated behind it. The entitlement file requests the `development` environment so attestations carry `aaguid = "appattestdevelop"`.

## Project setup

```sh
brew install xcodegen           # one-time
cd ios-demo
xcodegen generate               # creates AttestKitDemo.xcodeproj
```

Then either:

- Open in Xcode, set your Team in Signing & Capabilities, plug in an iPhone, Cmd-R.
- Or use the headless script — see "Running on device" below.

The hardcoded team ID in `AttestKitDemo/ContentView.swift` (`AttestViewModel.teamId`) is the original author's. Change it to your own 10-character Apple Developer Team ID; otherwise the `app_id` in your fixtures won't match what your phone actually signed.

## Running on device

The repo includes two scripts:

```sh
./scripts/run-device.sh         # build + install + launch on first paired iPhone
./scripts/pull-fixtures.sh      # pull *.json captures out of the app sandbox
```

`run-device.sh` finds the device's Core UDID via `xcrun devicectl` (used for install/launch) and its legacy UDID via `xcrun xctrace` (used for codesigning), then runs `xcodebuild` with auto-provisioning. Pass a Core UDID as `$1` to target a specific phone in a multi-device setup; override the legacy UDID via env `LEGACY_UDID=...`.

`pull-fixtures.sh` copies `Documents/attestation_*.json` and `Documents/assertion_*.json` out of the app sandbox into `rust/attest-apple/tests/fixtures/`.

## Capturing fixtures

1. Launch the app on the phone.
2. Tap **Attest New Key**. The Secure Enclave generates a fresh P-256 key and Apple's PKI attests it against a 32-byte random challenge. The app writes `Documents/attestation_NNN.json` and remembers `(keyId, attested_pk, app_id)` in `UserDefaults` so step 3 works across launches.
3. Tap **Generate Assertion**. The SE signs a small JSON `clientData` blob (`{"demo":"AttestKitDemo","timestamp":"…","nonce":"…"}`) with the active key. The app writes `Documents/assertion_NNN.json`.
4. On your Mac, run `./scripts/pull-fixtures.sh` to copy both into the Rust test fixture directory.

Each fixture also lands on the iOS pasteboard via **Copy fixture JSON** so you can grab a single one without pulling the whole sandbox.

The **Forget this key** button clears the persisted active key — useful if you want to attest a fresh key without uninstalling the app.

## Fixture shapes

`attestation_NNN.json`:

```json
{
  "attestation_object_hex": "a363666d746f6170706c652d…",
  "attested_value_hex":     "04d8e0…",                                // 65-byte X9.63 pk extracted from the CBOR
  "key_id_hex":             "9bda7c…",                                // SHA-256(pk), == base64-decoded Apple keyId
  "challenge_hex":          "a5e1ff…",                                // the 32-byte challenge attestKey was bound to
  "app_id":                 "TEAM10CHAR.com.unconfirmedlabs.attestkitdemo",
  "production":             false
}
```

`assertion_NNN.json`:

```json
{
  "assertion_object_hex": "a26161…",                                  // Apple's CBOR { signature, authenticatorData }
  "client_data_hex":      "7b226465…",                                // the exact bytes the SE signed (UTF-8 JSON in this demo)
  "attested_key_hex":     "04d8e0…",                                  // the X9.63 pk from the prior attestation
  "app_id":               "TEAM10CHAR.com.unconfirmedlabs.attestkitdemo"
}
```

Apple's API only ever exposes `SHA-256(clientData)` to its servers, but we keep the raw `clientData` in the fixture so the host-side verifier can recompute the hash and confirm the signature is over the payload we asked for.

## Notes

- The app makes no network calls. Fixtures stay on the device until you pull them out. Privacy-by-construction.
- After a few hundred attestations Apple's anti-abuse limits kick in. For fixture capture you'll never hit them.
- Each tap of **Attest New Key** generates a brand-new SE key. Old keys remain on the device but are harmless.
- If `attestKey` fails with `2 / DCErrorInvalidInput`, confirm the App Attest entitlement is present (Capabilities pane) and the device clock is reasonable.
- The CBOR parser in `AppAttestCBOR.swift` is ~100 lines of hand-written code that handles only the subset App Attest emits. It extracts the X9.63 public key from the `authData → credentialPublicKey` COSE_Key so the host doesn't have to re-parse the attestation when verifying assertions.
