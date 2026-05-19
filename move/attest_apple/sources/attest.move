/// Apple App Attest verification — kagi-integrated.
///
/// Consumes a kagi `Enclave<ATTESTATION>` and a signed payload produced
/// by the off-chain Rust verifier (`attest-apple` crate + `enclave-server`).
/// Emits a typed `Witness<AppleAppAttest>` on success.
///
/// The actual cryptographic verification of Apple's attestation — X.509
/// chain to Apple's root CA, nonce extension parsing, COSE key extraction,
/// aaguid / rpIdHash / signCount checks — happens off-chain inside the
/// attested Nitro enclave (`Enclave<ATTESTATION>`). The enclave signs an
/// `IntentMessage<ApplePayload>` with its registered Ed25519 key, and
/// this Move function verifies that signature via `kagi::enclave`.
module attest_apple::attest;

use sui::clock::Clock;

use attestation::attestation::ATTESTATION;
use attestation::witness::{Self, Witness};
use attest_apple::source::{Self, AppleAppAttest};
use kagi::enclave::Enclave;

// === Errors ===

const EStaleOutcome: u64 = 1;
const EFutureOutcome: u64 = 2;

// === Constants ===

/// Intent scope byte signed by the enclave for Apple App Attest outcomes.
/// Mirror of the Rust `INTENT_APPLE_APP_ATTEST` constant.
const INTENT_APPLE_APP_ATTEST: u8 = 0;

/// Maximum age of a verifier outcome, in milliseconds. Outcomes older
/// than this are rejected to bound replay windows.
const MAX_OUTCOME_AGE_MS: u64 = 5 * 60 * 1000; // 5 minutes

/// Maximum clock skew tolerance, in milliseconds.
const MAX_CLOCK_SKEW_MS: u64 = 30 * 1000; // 30 seconds

/// Mirror of the Rust `ApplePayload` struct. Field order must match for
/// BCS compatibility.
public struct ApplePayload has copy, drop {
    attested_value: vector<u8>,
    challenge: vector<u8>,
    detail_hash: vector<u8>,
}

/// Verify an enclave-signed Apple App Attest outcome and produce a
/// `Witness<AppleAppAttest>`.
///
/// * `enclave`        — the registered `Enclave<ATTESTATION>` (shared object).
/// * `attested_value` — the P-256 public key attested by Apple (65 B, X9.63).
/// * `challenge`      — the challenge that bound the attestation.
/// * `detail_hash`    — SHA-256 of the raw Apple attestationObject.
/// * `timestamp_ms`   — the timestamp the enclave stamped into the outcome.
/// * `sig`            — Ed25519 signature over the kagi IntentMessage.
/// * `clock`          — for freshness checks.
public fun verify(
    enclave: &Enclave<ATTESTATION>,
    attested_value: vector<u8>,
    challenge: vector<u8>,
    detail_hash: vector<u8>,
    timestamp_ms: u64,
    sig: vector<u8>,
    clock: &Clock,
): Witness<AppleAppAttest> {
    // 1. Freshness.
    let now = clock.timestamp_ms();
    assert!(timestamp_ms + MAX_OUTCOME_AGE_MS >= now, EStaleOutcome);
    assert!(timestamp_ms <= now + MAX_CLOCK_SKEW_MS, EFutureOutcome);

    // 2. Reconstruct the payload and verify the enclave's signature.
    //    Aborts with EInvalidSignature (from kagi::enclave) if it fails.
    let payload = ApplePayload {
        attested_value,
        challenge,
        detail_hash,
    };
    enclave.verify_signature(INTENT_APPLE_APP_ATTEST, timestamp_ms, payload, &sig);

    // 3. Emit the typed witness. Holding the AppleAppAttest marker proves
    //    we're inside the attest_apple package; the witness body carries
    //    the verified fields.
    witness::new(
        source::new(),
        payload.attested_value,
        payload.challenge,
        timestamp_ms,
        payload.detail_hash,
    )
}
