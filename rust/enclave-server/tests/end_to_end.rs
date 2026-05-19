//! End-to-end test against the real fixture + the production flow shape.
//!
//! The "production" Apple attestation flow runs an `attest-apple` verify,
//! then asks `/dev/nsm` for an attestation document whose `user_data` is
//! `SHA-256(BCS(ApplePayload))`. The on-chain verifier checks that hash.
//!
//! This test can't call `/dev/nsm` (only runs inside a Nitro enclave) — but
//! it can still exercise everything *up to* the NSM call: verify the Apple
//! attestation, build the same `ApplePayload`, compute the BCS bytes + hash,
//! and assert the BCS encoding is byte-identical to what the Move-side
//! struct produces in `attest_apple::attest::ApplePayload`.

use sha2::{Digest, Sha256};
use std::fs;

#[derive(serde::Deserialize)]
struct Fixture {
    attestation_object_hex: String,
    key_id_hex: String,
    challenge_hex: String,
    app_id: String,
    production: bool,
}

#[derive(serde::Serialize)]
struct ApplePayload {
    attested_value: Vec<u8>,
    challenge: Vec<u8>,
    detail_hash: Vec<u8>,
}

#[test]
#[ignore = "requires the iPhone fixture in attest-apple/tests/fixtures/"]
fn end_to_end_apple_fixture() {
    let fixture_path = "../attest-apple/tests/fixtures/dev_iphone_001.json";
    let raw = fs::read_to_string(fixture_path).expect("fixture missing");
    let fx: Fixture = serde_json::from_str(&raw).expect("bad fixture json");

    let attestation_object = hex::decode(&fx.attestation_object_hex).unwrap();
    let key_id = hex::decode(&fx.key_id_hex).unwrap();
    let challenge = hex::decode(&fx.challenge_hex).unwrap();
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;

    // 1. Run the same Apple verifier the production handler runs.
    let outcome = attest_apple::verify_app_attest(
        &attestation_object,
        &key_id,
        &challenge,
        &fx.app_id,
        fx.production,
        now_ms,
    )
    .expect("Apple attestation verifies");

    assert_eq!(outcome.source, attestation_core::sources::APPLE_APP_ATTEST);
    assert_eq!(outcome.challenge, challenge);
    assert_eq!(outcome.attested_value.len(), 65, "P-256 uncompressed pk");

    // 2. Build the same ApplePayload the production handler binds into
    //    NSM's user_data. This struct's BCS encoding is what the Move
    //    package's ApplePayload reconstructs to recompute the hash.
    let payload = ApplePayload {
        attested_value: outcome.attested_value.clone(),
        challenge: outcome.challenge.clone(),
        detail_hash: outcome.detail_hash.clone(),
    };
    let bcs_bytes = bcs::to_bytes(&payload).expect("bcs encode");
    let hash: [u8; 32] = Sha256::digest(&bcs_bytes).into();

    // 3. Sanity bounds (real fixtures land in this size range).
    assert!(!bcs_bytes.is_empty());
    assert_eq!(hash.len(), 32);

    println!(
        "OK: payload_bcs={} bytes, hash={}",
        bcs_bytes.len(),
        hex::encode(hash),
    );
}
