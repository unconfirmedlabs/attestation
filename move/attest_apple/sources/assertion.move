/// Apple App **assertion** verification.
///
/// An *assertion* (Apple's per-call output from
/// `DCAppAttestService.generateAssertion(...)`) proves that an Apple
/// Secure Enclave key — previously attested via this package's
/// [`attest_apple::attestation`] — signed a specific `client_data` blob.
/// Use this for per-action authenticity: every time the iOS app submits
/// a payload it wants the chain to trust, call generateAssertion over
/// SHA-256(payload) and ship the assertion alongside.
///
/// Each call carries a fresh AWS Nitro attestation document produced by
/// the pinned enclave image. The on-chain verifier:
///
///   1. Loads + verifies the Nitro attestation doc.
///   2. Confirms PCRs match the policy — proves the enclave image.
///   3. Confirms the Nitro doc's `user_data` equals
///      `sha256(BCS(AssertionPayload))` — binds the doc to this
///      specific (attested_key, client_data) tuple.
///   4. Confirms the Nitro-signed `timestamp` is fresh against Clock.
///
/// The actual Apple assertion verification (parsing the CBOR assertion,
/// re-deriving the signed message, ECDSA-P256-verifying against the
/// attested pk) happens off-chain inside the pinned enclave image
/// (`rust/attest-apple`). The PCR check proves the verifier code is
/// ours; the on-chain Nitro check anchors the result.
///
/// # Composing with `attest_apple::attestation`
///
/// The assertion module does **not** require a fresh `Witness<AppleAppAttest>`
/// to be passed in — that would force consumers to re-attest on every
/// action, which Apple's API rate-limits and which the design doesn't
/// need. Instead the consumer is responsible for sourcing
/// `attested_key` from a trusted location (an on-chain object minted
/// from a prior attestation, or an inline `Witness<AppleAppAttest>` in
/// the same PTB if they want type-system enforcement).
module attest_apple::assertion;

use std::bcs;
use std::hash;
use sui::clock::Clock;
use sui::nitro_attestation::{Self, NitroAttestationDocument, PCREntry};

use attestation::attestation::ATTESTATION;
use attestation::witness::{Self, Witness};
use attest_apple::source::{Self, AppleAssertion};
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

/// Mirror of the Rust `AssertionPayload` struct. BCS field order must
/// match the Rust side exactly.
public struct AssertionPayload has copy, drop {
    /// The previously-attested SE public key that produced the assertion
    /// (P-256 X9.63 uncompressed, 65 B).
    attested_key: vector<u8>,
    /// The exact bytes the SE key signed over (consumer-defined).
    client_data: vector<u8>,
}

/// Verify a fresh Nitro-signed assertion outcome from the pinned enclave.
///
/// * `policy`        — `EnclavePolicy<ATTESTATION>` whose PCRs must match.
/// * `doc`           — verified Nitro attestation document.
/// * `attested_key`  — the SE pk that signed `client_data`.
/// * `client_data`   — the exact bytes that were signed.
/// * `clock`         — for freshness check against the Nitro timestamp.
public fun verify(
    policy: &EnclavePolicy<ATTESTATION>,
    doc: NitroAttestationDocument,
    attested_key: vector<u8>,
    client_data: vector<u8>,
    clock: &Clock,
): Witness<AppleAssertion> {
    // 1. PCRs match the policy → proves the enclave image is ours.
    assert_pcrs_match(policy, &doc);

    // 2. user_data binds the Nitro doc to this exact (key, client_data).
    let payload = AssertionPayload { attested_key, client_data };
    let payload_bcs = bcs::to_bytes(&payload);
    let expected_hash = hash::sha2_256(payload_bcs);
    let user_data = nitro_attestation::user_data(&doc);
    assert!(user_data.is_some(), EMissingUserData);
    assert!(user_data.borrow() == &expected_hash, EPayloadMismatch);

    // 3. Nitro-signed timestamp is fresh.
    let nsm_ts = *nitro_attestation::timestamp(&doc);
    let now = clock.timestamp_ms();
    assert!(nsm_ts + MAX_OUTCOME_AGE_MS >= now, EStaleOutcome);
    assert!(nsm_ts <= now + MAX_CLOCK_SKEW_MS, EFutureOutcome);

    // 4. Sanity: doc has the enclave's pk embedded.
    let pk = nitro_attestation::public_key(&doc);
    assert!(pk.is_some(), EMissingPublicKey);

    // 5. Emit the typed witness. Field convention for AppleAssertion:
    //    attested_value = SE pk
    //    challenge      = client_data (what was signed)
    //    timestamp_ms   = Nitro time
    //    detail_hash    = SHA-256(BCS(payload)) for downstream audit
    witness::new(
        source::new_assertion(),
        payload.attested_key,
        payload.client_data,
        nsm_ts,
        *user_data.borrow(),
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

// No Move unit tests — same reason as `attest_apple::attestation`: `verify` needs a
// real `NitroAttestationDocument` + `EnclavePolicy`, unconstructible under
// `sui move test`. Covered by the Rust `attest-apple` crate + an integration test.
