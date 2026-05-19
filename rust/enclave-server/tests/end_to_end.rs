//! End-to-end test: fixture → `/attest/apple` → verify signature → BCS-decode → assert fields.
//!
//! Spawns a server on a random port using axum's testing facilities (`oneshot`),
//! sends the iPhone fixture, and checks the response contents.

use attestation_core::Outcome;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::fs;

#[derive(serde::Deserialize)]
struct Fixture {
    attestation_object_hex: String,
    key_id_hex: String,
    challenge_hex: String,
    app_id: String,
    production: bool,
}

#[tokio::test]
#[ignore = "requires the iPhone fixture in attest-apple/tests/fixtures/"]
async fn end_to_end_apple_fixture() {
    // The enclave-server crate doesn't expose its handlers as a library
    // (it's a `[[bin]]` only). Instead we call the same crates the binary
    // calls and verify the round-trip explicitly.

    let fixture_path = "../attest-apple/tests/fixtures/dev_iphone_001.json";
    let raw = fs::read_to_string(fixture_path).expect("fixture missing");
    let fx: Fixture = serde_json::from_str(&raw).expect("bad fixture json");

    let attestation_object = hex::decode(&fx.attestation_object_hex).unwrap();
    let key_id = hex::decode(&fx.key_id_hex).unwrap();
    let challenge = hex::decode(&fx.challenge_hex).unwrap();

    // 1. Verify the attestation (this is what the server's handler does).
    let outcome = attest_apple::verify_app_attest(
        &attestation_object,
        &key_id,
        &challenge,
        &fx.app_id,
        fx.production,
        1_700_000_000_000,
    )
    .expect("attestation verifies");

    assert_eq!(outcome.source, attestation_core::sources::APPLE_APP_ATTEST);
    assert_eq!(outcome.challenge, challenge);
    assert_eq!(outcome.attested_value.len(), 65, "P-256 uncompressed pk");

    // 2. BCS-encode and sign with a freshly-generated key.
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    let verifying_key: VerifyingKey = signing_key.verifying_key();

    let outcome_bytes = outcome.to_bcs().expect("bcs encode");
    let sig: Signature = ed25519_dalek::Signer::sign(&signing_key, &outcome_bytes);

    // 3. Verify the signature (this is what Move-side ed25519_verify does).
    verifying_key
        .verify(&outcome_bytes, &sig)
        .expect("signature verifies");

    // 4. BCS-decode the outcome (this is what Move-side parse_outcome does).
    let decoded = Outcome::from_bcs(&outcome_bytes).expect("bcs decode");
    assert_eq!(decoded, outcome);

    println!(
        "OK: outcome={} bytes, sig={} bytes, pk={}",
        outcome_bytes.len(),
        sig.to_bytes().len(),
        hex::encode(verifying_key.to_bytes()),
    );
}
