/// Apple App Attest verification.
///
/// Consumes an enclave-signed [`Outcome`] produced by the off-chain Rust
/// verifier (`attest-apple` crate) and emits a typed
/// `attestation::witness::Witness<AppleAppAttest>`.
///
/// The actual cryptographic verification of Apple's attestation — X.509
/// chain to Apple's root CA, nonce extension parsing, COSE key extraction,
/// aaguid / rpIdHash / signCount checks — happens off-chain inside a trusted
/// verifier (typically a Nautilus enclave). The verifier signs the canonical
/// outcome with an Ed25519 key and this Move function verifies that
/// signature against a caller-supplied public key.
///
/// The caller (e.g., a ticketing or identity package) is responsible for
/// binding `verifier_pk` to a trusted verifier registration — for instance,
/// by reading the public key off of a Nautilus enclave object with known
/// PCRs. This package treats `verifier_pk` as opaque.
module attest_apple::attest;

use std::string::{Self, String};
use sui::bcs;
use sui::clock::Clock;
use sui::ed25519;

use attestation::witness::{Self, Witness};
use attest_apple::source::{Self, AppleAppAttest};

// === Errors ===

const EInvalidSignature: u64 = 1;
const EWrongSource: u64 = 2;
const EStaleOutcome: u64 = 3;
const EFutureOutcome: u64 = 4;

// === Constants ===

/// Source identifier this package accepts. Must match
/// `attestation_core::sources::APPLE_APP_ATTEST` in the Rust workspace.
const SOURCE_ID: vector<u8> = b"apple-app-attest";

/// Maximum age of a verifier outcome, in milliseconds. Outcomes older than
/// this are rejected to bound replay windows in case an enclave signature
/// leaks.
const MAX_OUTCOME_AGE_MS: u64 = 5 * 60 * 1000; // 5 minutes

/// Maximum clock skew tolerance, in milliseconds. Outcomes whose timestamp
/// is more than this far in the future are rejected.
const MAX_CLOCK_SKEW_MS: u64 = 30 * 1000; // 30 seconds

/// Verify an enclave-signed Apple App Attest outcome and produce a
/// `Witness<AppleAppAttest>`.
///
/// * `outcome_bytes` — BCS-encoded `attestation_core::Outcome`.
/// * `sig`           — Ed25519 signature over `outcome_bytes`.
/// * `verifier_pk`   — Ed25519 public key the caller trusts for this kind of
///                     attestation (e.g., a Nautilus enclave's key).
/// * `clock`         — for staleness checks.
public fun verify(
    outcome_bytes: vector<u8>,
    sig: vector<u8>,
    verifier_pk: vector<u8>,
    clock: &Clock,
): Witness<AppleAppAttest> {
    // 1. Verify the signature.
    assert!(
        ed25519::ed25519_verify(&sig, &verifier_pk, &outcome_bytes),
        EInvalidSignature,
    );

    // 2. Parse the BCS outcome.
    let Outcome {
        source: outcome_source,
        attested_value,
        challenge,
        timestamp_ms,
        detail_hash,
    } = parse_outcome(outcome_bytes);

    // 3. Source guard.
    assert!(outcome_source.into_bytes() == SOURCE_ID, EWrongSource);

    // 4. Freshness.
    let now = clock.timestamp_ms();
    assert!(timestamp_ms + MAX_OUTCOME_AGE_MS >= now, EStaleOutcome);
    assert!(timestamp_ms <= now + MAX_CLOCK_SKEW_MS, EFutureOutcome);

    // 5. Emit the typed witness.
    witness::new(
        source::new(),
        attested_value,
        challenge,
        timestamp_ms,
        detail_hash,
    )
}

// === Outcome decoding ===

/// Mirror of the Rust `attestation_core::Outcome` struct. BCS layout must
/// stay in sync: length-prefixed source, attested_value, challenge; u64
/// timestamp_ms; length-prefixed detail_hash.
public struct Outcome has copy, drop {
    source: String,
    attested_value: vector<u8>,
    challenge: vector<u8>,
    timestamp_ms: u64,
    detail_hash: vector<u8>,
}

fun parse_outcome(bytes: vector<u8>): Outcome {
    let mut reader = bcs::new(bytes);
    let source = string::utf8(reader.peel_vec_u8());
    let attested_value = reader.peel_vec_u8();
    let challenge = reader.peel_vec_u8();
    let timestamp_ms = reader.peel_u64();
    let detail_hash = reader.peel_vec_u8();
    Outcome {
        source,
        attested_value,
        challenge,
        timestamp_ms,
        detail_hash,
    }
}
