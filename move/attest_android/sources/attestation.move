/// Android Key Attestation verification.
///
/// An *attestation* in the Android Keystore world is the X.509 chain
/// produced by the device for a hardware-backed key. The leaf certificate
/// carries Google's custom extension at OID 1.3.6.1.4.1.11129.2.1.17
/// (KeyDescription) which binds the attested key to a caller-supplied
/// challenge and reports the security level + verified boot state.
///
/// The actual chain parsing, X.509 validation against Google's pinned
/// roots (RSA-2048 and ECDSA P-384), and policy enforcement
/// (security level, verifiedBootState, deviceLocked, optional revocation
/// status list) happen off-chain inside the pinned Nitro enclave image
/// (`rust/attest-android`). The on-chain verifier here checks the AWS
/// Nitro attestation document — its PCRs (proving the enclave is our
/// image), its user_data (binding to this specific payload), and its
/// timestamp (signed by AWS Nitro, unspoofable).
///
/// On success this module emits a typed `Witness<AndroidKeyAttestation>`.
module attest_android::attestation;

use std::bcs;
use std::hash;
use sui::clock::Clock;
use sui::nitro_attestation::{Self, NitroAttestationDocument, PCREntry};

use attestation::attestation::ATTESTATION;
use attestation::witness::{Self, Witness};
use attest_android::source::{Self, AndroidKeyAttestation};
use kagi::enclave_policy::{Self, EnclavePolicy};

// === Errors ===

const EStaleOutcome: u64 = 1;
const EFutureOutcome: u64 = 2;
const EWrongPcr: u64 = 3;
const EMissingUserData: u64 = 4;
const EPayloadMismatch: u64 = 5;
const EMissingPublicKey: u64 = 6;

// === Constants ===

const MAX_OUTCOME_AGE_MS: u64 = 5 * 60 * 1000;
const MAX_CLOCK_SKEW_MS:  u64 = 30 * 1000;

// === Payload ===

/// Mirror of the Rust `AndroidPayload` struct. BCS field order must
/// match — change here only in lockstep with the verifier crate.
public struct AndroidPayload has copy, drop {
    /// The attested key, encoded as DER `subjectPublicKeyInfo`. KeyMint
    /// can attest P-256, P-384, RSA, and Ed25519, so the SPKI is the
    /// only universal carrier.
    attested_value: vector<u8>,
    /// Caller-supplied challenge bytes the leaf's `attestationChallenge`
    /// equaled exactly.
    challenge: vector<u8>,
    /// SHA-256 of the canonicalized chain bytes (length-prefixed concat).
    detail_hash: vector<u8>,
}

/// Verify a fresh Nitro-signed Android Key Attestation outcome from the
/// pinned enclave.
///
/// The caller must produce the `NitroAttestationDocument` via
/// `0x2::nitro_attestation::load_nitro_attestation` in the same PTB.
///
/// * `policy`         — the `EnclavePolicy<ATTESTATION>` whose PCRs must match.
/// * `doc`            — verified Nitro attestation document.
/// * `attested_value` — the Android-attested public key SPKI (DER bytes).
/// * `challenge`      — the challenge bound to the Android attestation.
/// * `detail_hash`    — SHA-256 of the canonicalized chain blob.
/// * `clock`          — for freshness check against the Nitro timestamp.
public fun verify(
    policy: &EnclavePolicy<ATTESTATION>,
    doc: NitroAttestationDocument,
    attested_value: vector<u8>,
    challenge: vector<u8>,
    detail_hash: vector<u8>,
    clock: &Clock,
): Witness<AndroidKeyAttestation> {
    assert_pcrs_match(policy, &doc);

    let payload = AndroidPayload { attested_value, challenge, detail_hash };
    let payload_bcs = bcs::to_bytes(&payload);
    let expected_hash = hash::sha2_256(payload_bcs);
    let user_data = nitro_attestation::user_data(&doc);
    assert!(user_data.is_some(), EMissingUserData);
    assert!(user_data.borrow() == &expected_hash, EPayloadMismatch);

    let nsm_ts = *nitro_attestation::timestamp(&doc);
    let now = clock.timestamp_ms();
    assert!(nsm_ts + MAX_OUTCOME_AGE_MS >= now, EStaleOutcome);
    assert!(nsm_ts <= now + MAX_CLOCK_SKEW_MS, EFutureOutcome);

    let pk = nitro_attestation::public_key(&doc);
    assert!(pk.is_some(), EMissingPublicKey);

    witness::new(
        source::new_android_key_attestation(),
        payload.attested_value,
        payload.challenge,
        nsm_ts,
        payload.detail_hash,
    )
}

fun assert_pcrs_match(
    policy: &EnclavePolicy<ATTESTATION>,
    doc: &NitroAttestationDocument,
) {
    let pcrs = nitro_attestation::pcrs(doc);
    let mut i = 0;
    let mut found_0 = false;
    let mut found_1 = false;
    let mut found_2 = false;
    while (i < pcrs.length()) {
        let entry: &PCREntry = &pcrs[i];
        let idx = nitro_attestation::index(entry);
        let value = nitro_attestation::value(entry);
        if (idx == 0) {
            assert!(value == enclave_policy::pcr0(policy), EWrongPcr);
            found_0 = true;
        } else if (idx == 1) {
            assert!(value == enclave_policy::pcr1(policy), EWrongPcr);
            found_1 = true;
        } else if (idx == 2) {
            assert!(value == enclave_policy::pcr2(policy), EWrongPcr);
            found_2 = true;
        };
        i = i + 1;
    };
    assert!(found_0 && found_1 && found_2, EWrongPcr);
}

// No Move unit tests. `verify` / `assert_pcrs_match` consume a
// `NitroAttestationDocument`, unconstructible under `sui move test` (only the
// `load_nitro_attestation` native mints one, from a real AWS-signed blob). The
// Android Key Attestation crypto is tested in the Rust `attest-android` crate;
// end-to-end `verify` is covered by an integration test against a real fixture. No
// tautological payload/BCS tests are added.
