//! Apple App Attest verifier.
//!
//! Verifies that an `attestationObject` produced by `DCAppAttestService` was:
//!
//! - issued by Apple's App Attestation infrastructure (chain to the pinned
//!   Apple App Attestation Root CA),
//! - bound to a specific challenge supplied by the caller,
//! - for a specific app (teamID.bundleID),
//! - on a real device (production aaguid) or in dev mode (sandbox aaguid),
//!
//! and on success produces a canonical [`Outcome`](attestation_core::Outcome)
//! suitable for enclave-signing and on-chain consumption by the
//! `attest_apple` Move package.
//!
//! See Apple's "Validating Apps That Connect to Your Server" for the
//! authoritative verification algorithm:
//! <https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server>

pub mod authdata;
pub mod cbor;
pub mod cose;
mod errors;
pub mod oids;
pub mod roots;

pub use attestation_core::{sources, Outcome};
pub use errors::{Error, Result};

use sha2::{Digest, Sha256};

/// AAGUID for production App Attest (`"appattest" + 7 null bytes`).
pub const AAGUID_PRODUCTION: [u8; 16] = *b"appattest\x00\x00\x00\x00\x00\x00\x00";

/// AAGUID for development App Attest sandbox.
pub const AAGUID_DEVELOPMENT: [u8; 16] = *b"appattestdevelop";

/// Verify an Apple App Attest `attestationObject`.
///
/// # Arguments
/// * `attestation_object` — raw CBOR bytes returned by
///   `DCAppAttestService.attestKey(_:clientDataHash:completionHandler:)`.
/// * `key_id` — the keyId returned alongside the attestation. Apple defines
///   this as `SHA-256(public_key_in_X9.63_form)`.
/// * `challenge` — the caller-supplied challenge bytes the attestation must
///   bind to. The caller is responsible for constructing the challenge in a
///   way that ties this attestation to its application context.
/// * `app_id` — `"<teamID>.<bundleID>"` of the app that produced the
///   attestation. Apple's documentation hashes this with SHA-256 to form
///   the `rpIdHash` field of `authData`.
/// * `production` — true if the attestation is expected to be from a
///   production-provisioned app (TestFlight / App Store), false for
///   `aaguid = "appattestdevelop"` from Xcode-signed builds.
/// * `clock_ms` — current verifier timestamp, milliseconds since Unix
///   epoch. Stamped into the outcome.
///
/// # Returns
/// An [`Outcome`] on success. The outcome's `attested_value` is the
/// 65-byte X9.63 uncompressed P-256 public key.
pub fn verify_app_attest(
    attestation_object: &[u8],
    key_id: &[u8],
    challenge: &[u8],
    app_id: &str,
    production: bool,
    clock_ms: u64,
) -> Result<Outcome> {
    // 1. CBOR decode.
    let stmt = cbor::decode_attestation_object(attestation_object)?;
    if stmt.fmt != "apple-appattest" {
        return Err(Error::WrongFormat(stmt.fmt));
    }

    // 2. Parse authData.
    let auth = authdata::parse(&stmt.auth_data)?;

    // 3. Validate the x5c chain (will warn but pass if root is not yet pinned).
    let leaf = roots::validate_x5c_chain(&stmt.x5c)?;

    // 4. Compute the expected nonce and compare to the cert extension.
    let mut hasher = Sha256::new();
    hasher.update(&stmt.auth_data);
    hasher.update(Sha256::digest(challenge));
    let expected_nonce: [u8; 32] = hasher.finalize().into();

    let cert_nonce = oids::extract_nonce_extension(&leaf)?;
    if cert_nonce != expected_nonce {
        return Err(Error::NonceMismatch);
    }

    // 5. Extract the attested public key and verify keyId.
    let pk = cose::extract_p256_pk(&auth.credential_public_key)?;
    let computed_key_id: [u8; 32] = Sha256::digest(cose::key_id_input(&pk)).into();
    if computed_key_id.as_slice() != key_id {
        return Err(Error::KeyIdMismatch);
    }

    // 6. Verify aaguid.
    let expected_aaguid = if production {
        AAGUID_PRODUCTION
    } else {
        AAGUID_DEVELOPMENT
    };
    if auth.aaguid != expected_aaguid {
        return Err(Error::AaguidMismatch {
            expected: if production { "appattest" } else { "appattestdevelop" },
            got: auth.aaguid.to_vec(),
        });
    }

    // 7. Verify rpIdHash == SHA256(app_id).
    let expected_rp: [u8; 32] = Sha256::digest(app_id.as_bytes()).into();
    if auth.rp_id_hash != expected_rp {
        return Err(Error::RpIdHashMismatch);
    }

    // 8. Sign count must be 0 on initial attestation.
    if auth.sign_count != 0 {
        return Err(Error::SignCountNotZero(auth.sign_count));
    }

    // Outcome.
    let detail_hash: Vec<u8> = Sha256::digest(attestation_object).to_vec();
    Ok(Outcome {
        source: sources::APPLE_APP_ATTEST.to_string(),
        attested_value: pk.to_vec(),
        challenge: challenge.to_vec(),
        timestamp_ms: clock_ms,
        detail_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_format_is_rejected() {
        // Build a minimal CBOR map with fmt = "wrong", empty authData, empty attStmt.
        let map = vec![
            (
                ciborium::value::Value::Text("fmt".to_string()),
                ciborium::value::Value::Text("wrong".to_string()),
            ),
            (
                ciborium::value::Value::Text("authData".to_string()),
                ciborium::value::Value::Bytes(vec![]),
            ),
            (
                ciborium::value::Value::Text("attStmt".to_string()),
                ciborium::value::Value::Map(vec![(
                    ciborium::value::Value::Text("x5c".to_string()),
                    ciborium::value::Value::Array(vec![]),
                )]),
            ),
        ];
        let val = ciborium::value::Value::Map(map);
        let mut bytes = Vec::new();
        ciborium::into_writer(&val, &mut bytes).unwrap();

        let r = verify_app_attest(&bytes, &[], &[], "team.bundle", false, 0);
        assert!(matches!(r, Err(Error::WrongFormat(_))));
    }
}
