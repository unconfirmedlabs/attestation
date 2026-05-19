/// Apple App Attest verification — Nitro-attested per request.
///
/// Each call carries a fresh AWS Nitro attestation document. The on-chain
/// verifier:
///
///   1. Loads + verifies the Nitro attestation doc (AWS root → COSE_Sign1).
///   2. Confirms the doc's PCRs match the policy — i.e., it's our pinned
///      enclave image, not some attacker's image.
///   3. Confirms the doc's `user_data` equals `sha256(BCS(ApplePayload))` —
///      this binds the doc to a specific payload, so old docs can't be
///      paired with new payloads.
///   4. Confirms the Nitro-signed `timestamp` is fresh against `sui::clock`
///      — unspoofable, because the timestamp is signed by AWS Nitro, not
///      by the parent EC2 host.
///
/// The actual Apple chain validation happens off-chain inside the pinned
/// enclave image (`rust/attest-apple`). The PCR check proves the verifier
/// code is what we built; the on-chain Nitro check proves the result.
module attest_apple::attest;

use std::bcs;
use std::hash;
use sui::clock::Clock;
use sui::nitro_attestation::{Self, NitroAttestationDocument, PCREntry};

use attestation::attestation::ATTESTATION;
use attestation::witness::{Self, Witness};
use attest_apple::source::{Self, AppleAppAttest};
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

/// Mirror of the Rust `ApplePayload` struct. BCS field order must match.
public struct ApplePayload has copy, drop {
    attested_value: vector<u8>,
    challenge: vector<u8>,
    detail_hash: vector<u8>,
}

/// Verify a fresh Nitro-signed attestation outcome from the pinned enclave.
///
/// The caller must produce the `NitroAttestationDocument` via
/// `0x2::nitro_attestation::load_nitro_attestation` in the same PTB — that
/// function is `entry`-only and verifies the AWS Nitro signature.
///
/// * `policy`         — the `EnclavePolicy<ATTESTATION>` whose PCRs must match.
/// * `doc`            — verified Nitro attestation document.
/// * `attested_value` — the Apple-attested P-256 public key (65 B, X9.63).
/// * `challenge`      — the challenge that bound the Apple attestation.
/// * `detail_hash`    — SHA-256 of the raw Apple attestationObject.
/// * `clock`          — for freshness check against the Nitro timestamp.
public fun verify(
    policy: &EnclavePolicy<ATTESTATION>,
    doc: NitroAttestationDocument,
    attested_value: vector<u8>,
    challenge: vector<u8>,
    detail_hash: vector<u8>,
    clock: &Clock,
): Witness<AppleAppAttest> {
    // 1. PCRs must match the policy. This is what proves the document came
    //    from our pinned enclave image, not an attacker's image.
    assert_pcrs_match(policy, &doc);

    // 2. The doc's user_data must bind to this exact payload. Otherwise
    //    a stale doc could be paired with a fresh payload.
    let payload = ApplePayload { attested_value, challenge, detail_hash };
    let payload_bcs = bcs::to_bytes(&payload);
    let expected_hash = hash::sha2_256(payload_bcs);
    let user_data = nitro_attestation::user_data(&doc);
    assert!(user_data.is_some(), EMissingUserData);
    assert!(user_data.borrow() == &expected_hash, EPayloadMismatch);

    // 3. The Nitro-signed timestamp is the freshness anchor. Unlike the
    //    enclave's wall clock, the Nitro timestamp is signed by AWS and
    //    cannot be spoofed by the parent EC2 host.
    let nsm_ts = *nitro_attestation::timestamp(&doc);
    let now = clock.timestamp_ms();
    assert!(nsm_ts + MAX_OUTCOME_AGE_MS >= now, EStaleOutcome);
    assert!(nsm_ts <= now + MAX_CLOCK_SKEW_MS, EFutureOutcome);

    // 4. Sanity-check that the doc has a public key (i.e., the enclave
    //    embedded an Ed25519 pk). We don't verify any signature with it
    //    on this path — the NSM signature already covers everything —
    //    but downstream consumers may want it for their own protocols.
    let pk = nitro_attestation::public_key(&doc);
    assert!(pk.is_some(), EMissingPublicKey);

    // 5. Emit the typed witness with the Nitro timestamp.
    witness::new(
        source::new(),
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
    // Required PCRs (0/1/2) per kagi convention. Higher PCRs are allowed
    // but not checked here.
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
