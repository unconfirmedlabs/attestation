//! Apple App **assertion** verification.
//!
//! An assertion is what `DCAppAttestService.generateAssertion(_, clientDataHash:)`
//! returns on iOS. It's a CBOR map:
//!
//! ```text
//! {
//!   "signature":         <bytes>,       // ECDSA-P256 DER
//!   "authenticatorData": <bytes>        // 37 bytes: rpIdHash(32) | flags(1) | signCount(4)
//! }
//! ```
//!
//! The signature is over `SHA-256(authenticatorData || clientDataHash)` where
//! `clientDataHash = SHA-256(client_data)` — caller-supplied bytes.
//!
//! This module does NOT re-validate Apple's certificate chain — that's a
//! one-time job done by [`verify_app_attest`](crate::verify_app_attest).
//! It assumes the caller has previously attested the public key being
//! verified against and is now using it to authenticate a per-call payload.
//!
//! See [`verify_assertion`] for the entry point and the
//! [`AssertionOutcome`] for the field meanings.

use crate::cbor;
use crate::errors::{Error, Result};
use attestation_core::{sources, Outcome};
use ciborium::value::Value;
use p256::ecdsa::{DerSignature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::io::Cursor;

/// Verify an Apple App Attest assertion against a previously-attested key.
///
/// # Arguments
/// * `assertion_object` — raw CBOR bytes returned by `generateAssertion`.
/// * `client_data`      — the exact bytes that the iOS app fed to
///   `clientDataHash`. The signature is over `SHA-256(authData || SHA-256(client_data))`.
/// * `attested_key`     — the P-256 public key (65 B SEC1 uncompressed)
///   that the caller previously attested. The signature must verify under
///   this key for the assertion to be accepted.
/// * `app_id`           — `"<teamID>.<bundleID>"`. The assertion's
///   `authenticatorData.rpIdHash` must equal `SHA-256(app_id)`.
/// * `clock_ms`         — verifier wall-clock timestamp; stamped into the
///   returned [`Outcome`].
///
/// # Returns
/// An [`Outcome`] with `source = "apple-app-attest-assertion"`,
/// `attested_value = attested_key`, `challenge = client_data`,
/// `detail_hash = SHA-256(assertion_object)`.
pub fn verify_assertion(
    assertion_object: &[u8],
    client_data: &[u8],
    attested_key: &[u8],
    app_id: &str,
    clock_ms: u64,
) -> Result<Outcome> {
    // 1. CBOR decode the assertion.
    let (signature, auth_data) = decode_assertion(assertion_object)?;

    // 2. authData layout: rpIdHash(32) | flags(1) | signCount(4) — minimum 37 bytes.
    if auth_data.len() < 37 {
        return Err(Error::Cbor(format!(
            "authenticatorData too short: {} bytes",
            auth_data.len()
        )));
    }
    let rp_id_hash = &auth_data[0..32];

    // 3. rpIdHash must match SHA-256(app_id) — proves the assertion was
    //    produced by the same Apple app the attestation belonged to.
    let expected_rp: [u8; 32] = Sha256::digest(app_id.as_bytes()).into();
    if rp_id_hash != expected_rp.as_slice() {
        return Err(Error::RpIdHashMismatch);
    }

    // 4. The signed message is SHA-256(authData || clientDataHash) where
    //    clientDataHash = SHA-256(client_data).
    let client_data_hash: [u8; 32] = Sha256::digest(client_data).into();
    let mut hasher = Sha256::new();
    hasher.update(&auth_data);
    hasher.update(client_data_hash);
    let signed_digest: [u8; 32] = hasher.finalize().into();

    // 5. ECDSA-P256 verify with the previously-attested public key.
    let key = VerifyingKey::from_sec1_bytes(attested_key)
        .map_err(|e| Error::Der(format!("attested key parse: {e}")))?;
    let sig = DerSignature::try_from(signature.as_slice())
        .map_err(|e| Error::Der(format!("assertion signature parse: {e}")))?;
    use p256::ecdsa::signature::hazmat::PrehashVerifier as _;
    key.verify_prehash(&signed_digest, &sig)
        .map_err(|_| Error::UntrustedChain)?;

    // 6. Build the outcome.
    let detail_hash: Vec<u8> = Sha256::digest(assertion_object).to_vec();
    Ok(Outcome {
        source: sources::APPLE_APP_ATTEST_ASSERTION.to_string(),
        attested_value: attested_key.to_vec(),
        challenge: client_data.to_vec(),
        timestamp_ms: clock_ms,
        detail_hash,
    })
}

/// Parse the assertion CBOR into `(signature, authData)`.
fn decode_assertion(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let value: Value = ciborium::from_reader(Cursor::new(bytes))
        .map_err(|e| Error::Cbor(format!("assertion decode: {e}")))?;

    let map = value
        .as_map()
        .ok_or_else(|| Error::Cbor("assertion not a map".into()))?;

    let mut signature = None;
    let mut auth_data = None;
    for (k, v) in map {
        let key = k
            .as_text()
            .ok_or_else(|| Error::Cbor("non-text key in assertion".into()))?;
        match key {
            "signature" => signature = v.as_bytes().cloned(),
            "authenticatorData" => auth_data = v.as_bytes().cloned(),
            _ => {}
        }
    }

    let signature = signature.ok_or_else(|| Error::Cbor("missing signature".into()))?;
    let auth_data = auth_data.ok_or_else(|| Error::Cbor("missing authenticatorData".into()))?;
    Ok((signature, auth_data))
}

// Silence the unused-import warning when `cbor` isn't actually used here.
#[allow(dead_code)]
fn _touch_cbor() {
    let _ = cbor::decode_attestation_object;
}
