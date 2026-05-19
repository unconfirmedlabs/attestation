# AttestKitDemo

A tiny SwiftUI app for capturing real Apple App Attest attestation objects from a physical iOS device. The captured fixtures feed `rust/attest-apple/tests/fixtures/` and unblock end-to-end verification of the `attest-apple` crate.

## What it does

1. Generates a fresh P-256 key inside the device's Secure Enclave (`DCAppAttestService.generateKey`).
2. Computes a SHA-256 client data hash over a fresh 32-byte challenge.
3. Calls `attestKey` to produce Apple's CBOR `attestationObject`.
4. Displays the result and copies a Rust-fixture-shaped JSON to the clipboard.

App Attest is **not** available in the iOS Simulator. You must run on a real device. Development-mode signing (a free Apple ID, no paid Developer Program membership) is sufficient — the entitlement file requests the `development` environment so the resulting attestation has `aaguid = "appattestdevelop"`.

## Project setup

Two options:

### Option A — XcodeGen (recommended; reproducible from the YAML)

```sh
brew install xcodegen     # one-time
cd ios-demo
xcodegen generate         # generates AttestKitDemo.xcodeproj
open AttestKitDemo.xcodeproj
```

Then in Xcode:

1. Select the `AttestKitDemo` target → Signing & Capabilities → set your Team.
2. Open `AttestKitDemo/ContentView.swift` and replace `REPLACE_WITH_YOUR_TEAM_ID` in `AttestViewModel.teamId` with your actual Apple Developer Team ID (10-character alphanumeric, visible in Xcode's Signing screen).
3. Plug in an iPhone, select it as the run destination, and Cmd-R.

### Option B — Manual Xcode project

If you'd rather not install XcodeGen:

1. In Xcode: File → New → Project → iOS → App.
2. Product Name: `AttestKitDemo`. Interface: SwiftUI. Language: Swift. Minimum: iOS 17.
3. Choose the `ios-demo/` directory as the location, so the generated `.xcodeproj` lives alongside `AttestKitDemo/`.
4. Delete the default `ContentView.swift` and `AttestKitDemoApp.swift` Xcode created; drag the ones from `ios-demo/AttestKitDemo/` into the project (use "Create folder references" / target membership = AttestKitDemo).
5. Drag `AttestKitDemo.entitlements` into the project the same way.
6. Target → Signing & Capabilities → Code Signing Entitlements should auto-populate to `AttestKitDemo/AttestKitDemo.entitlements`.
7. Click "+ Capability" and add **App Attest** (this confirms the entitlement is wired).
8. Replace `REPLACE_WITH_YOUR_TEAM_ID` in `ContentView.swift`.
9. Run on a physical device.

## Capturing a fixture

1. Launch the app on the device.
2. Tap **Attest new key**. The Secure Enclave generates a new key and attests it against a fresh challenge.
3. Tap **Copy as Rust fixture JSON**.
4. On your Mac: paste into `rust/attest-apple/tests/fixtures/dev_iphone_001.json` (or any name; update the integration test reference).
5. `cd rust/attest-apple && cargo test -- --ignored fixture_dev_iphone_001` should now drive the full verifier end-to-end.

## What the fixture JSON looks like

```json
{
  "attestation_object_hex": "a363666d746f6170706c652d6170706174746573…",
  "key_id_hex": "9bda7c…",
  "challenge_hex": "a5e1ff…",
  "app_id": "TEAM10CHAR.com.unconfirmedlabs.attestkitdemo",
  "production": false
}
```

Each tap produces a fresh key + fresh challenge — collect several fixtures to broaden test coverage (different challenge lengths, different sessions, etc.).

## Notes

- The app deliberately uses no network. Fixtures stay on the device until you paste them out. Privacy-by-construction.
- After a few hundred attestations Apple's anti-abuse limits kick in — for dev you'll never hit them.
- Each call to `generateKey` produces a fresh keyId. The Secure Enclave persists keys, but for fixture capture we just keep generating new ones; the old keys remain harmless on the device.
- If `attestKey` fails with an unexpected error code (notably `2 / DCErrorInvalidInput`), confirm the App Attest entitlement is present and the device clock is correct.

## Once we have fixtures

Before the integration test passes:

1. Pin Apple's App Attestation Root CA into `rust/attest-apple/src/roots.rs` (replace the empty placeholder `APPLE_APP_ATTEST_ROOT_DER`). Conversion:
   ```sh
   curl -L -o root.pem https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
   openssl x509 -in root.pem -outform DER -out rust/attest-apple/src/assets/apple_app_attest_root.der
   ```
   Then in `roots.rs`:
   ```rust
   pub const APPLE_APP_ATTEST_ROOT_DER: &[u8] =
       include_bytes!("assets/apple_app_attest_root.der");
   ```
2. Flip the integration test in `rust/attest-apple/tests/verify.rs` from `#[ignore]` to enabled.
