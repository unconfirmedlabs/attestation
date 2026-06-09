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

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::hazmat::PrehashSigner as _, DerSignature, SigningKey};
    use sha2::{Digest, Sha256};

    const APP_ID: &str = "5354N269JS.com.unconfirmedlabs.attestkitdemo";
    const CLOCK: u64 = 1_779_200_000_000;

    /// Build a 37-byte minimal `authenticatorData`: rpIdHash(32) | flags(1) | signCount(4).
    fn auth_data_for(app_id: &str, sign_count: u32) -> Vec<u8> {
        let rp: [u8; 32] = Sha256::digest(app_id.as_bytes()).into();
        let mut buf = Vec::with_capacity(37);
        buf.extend_from_slice(&rp);
        buf.push(0x00); // flags
        buf.extend_from_slice(&sign_count.to_be_bytes());
        buf
    }

    /// Encode a `{signature, authenticatorData}` CBOR assertion blob.
    fn encode_assertion(signature: &[u8], auth_data: &[u8]) -> Vec<u8> {
        let map = Value::Map(vec![
            (
                Value::Text("signature".into()),
                Value::Bytes(signature.to_vec()),
            ),
            (
                Value::Text("authenticatorData".into()),
                Value::Bytes(auth_data.to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&map, &mut out).unwrap();
        out
    }

    /// Sign the digest the verifier expects: SHA256(authData || SHA256(client_data)).
    fn sign(key: &SigningKey, auth_data: &[u8], client_data: &[u8]) -> Vec<u8> {
        let client_data_hash: [u8; 32] = Sha256::digest(client_data).into();
        let mut hasher = Sha256::new();
        hasher.update(auth_data);
        hasher.update(client_data_hash);
        let digest: [u8; 32] = hasher.finalize().into();
        let sig: DerSignature = key.sign_prehash(&digest).unwrap();
        sig.as_bytes().to_vec()
    }

    /// Deterministic signing key + its SEC1 uncompressed (65-byte) public key.
    fn keypair() -> (SigningKey, Vec<u8>) {
        // Fixed scalar so the test is reproducible.
        let sk = SigningKey::from_bytes(&[0x42u8; 32].into()).unwrap();
        let pk = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(pk.len(), 65);
        assert_eq!(pk[0], 0x04);
        (sk, pk)
    }

    #[test]
    fn happy_path_valid_assertion_verifies() {
        let (sk, pk) = keypair();
        let client_data = b"per-action payload for this assertion";
        let auth_data = auth_data_for(APP_ID, 1);
        let sig = sign(&sk, &auth_data, client_data);
        let blob = encode_assertion(&sig, &auth_data);

        let outcome = verify_assertion(&blob, client_data, &pk, APP_ID, CLOCK).unwrap();
        assert_eq!(outcome.source, sources::APPLE_APP_ATTEST_ASSERTION);
        assert_eq!(outcome.attested_value, pk);
        assert_eq!(outcome.challenge, client_data.to_vec());
        assert_eq!(outcome.timestamp_ms, CLOCK);
        // detail_hash commits to the raw blob.
        assert_eq!(outcome.detail_hash, Sha256::digest(&blob).to_vec());
    }

    #[test]
    fn wrong_attested_key_rejected() {
        // Sign with `sk`, but present a DIFFERENT key as the attested key.
        let (sk, _pk) = keypair();
        let other = SigningKey::from_bytes(&[0x07u8; 32].into()).unwrap();
        let other_pk = other
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let client_data = b"payload";
        let auth_data = auth_data_for(APP_ID, 1);
        let sig = sign(&sk, &auth_data, client_data);
        let blob = encode_assertion(&sig, &auth_data);

        let err = verify_assertion(&blob, client_data, &other_pk, APP_ID, CLOCK).unwrap_err();
        assert!(matches!(err, Error::UntrustedChain), "got {err:?}");
    }

    #[test]
    fn tampered_signature_rejected() {
        let (sk, pk) = keypair();
        let client_data = b"payload";
        let auth_data = auth_data_for(APP_ID, 1);
        let mut sig = sign(&sk, &auth_data, client_data);
        // Flip a byte deep in the DER signature so it still parses but won't verify.
        let last = sig.len() - 1;
        sig[last] ^= 0x01;
        let blob = encode_assertion(&sig, &auth_data);

        let err = verify_assertion(&blob, client_data, &pk, APP_ID, CLOCK).unwrap_err();
        // Either it parses-but-fails-to-verify (UntrustedChain) or the DER is
        // rejected outright (Der). Both are correct rejections.
        assert!(
            matches!(err, Error::UntrustedChain | Error::Der(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn wrong_client_data_rejected() {
        // Signature is over `client_data`, but we verify against `other` bytes.
        let (sk, pk) = keypair();
        let auth_data = auth_data_for(APP_ID, 1);
        let sig = sign(&sk, &auth_data, b"the real payload");
        let blob = encode_assertion(&sig, &auth_data);

        let err = verify_assertion(&blob, b"a different payload", &pk, APP_ID, CLOCK).unwrap_err();
        assert!(matches!(err, Error::UntrustedChain), "got {err:?}");
    }

    #[test]
    fn tampered_auth_data_breaks_signature() {
        // Mutating signCount in authData after signing invalidates the signature,
        // because the signed digest covers the full authData.
        let (sk, pk) = keypair();
        let client_data = b"payload";
        let auth_data = auth_data_for(APP_ID, 1);
        let sig = sign(&sk, &auth_data, client_data);
        let mut tampered = auth_data.clone();
        tampered[36] ^= 0xFF; // last byte of signCount
        let blob = encode_assertion(&sig, &tampered);

        let err = verify_assertion(&blob, client_data, &pk, APP_ID, CLOCK).unwrap_err();
        assert!(matches!(err, Error::UntrustedChain), "got {err:?}");
    }

    #[test]
    fn wrong_app_id_rejected_before_signature_check() {
        // rpIdHash mismatch must short-circuit (RpIdHashMismatch), even with a
        // perfectly valid signature for the *signed* app_id.
        let (sk, pk) = keypair();
        let client_data = b"payload";
        let auth_data = auth_data_for(APP_ID, 1);
        let sig = sign(&sk, &auth_data, client_data);
        let blob = encode_assertion(&sig, &auth_data);

        let err =
            verify_assertion(&blob, client_data, &pk, "OTHER.app.id", CLOCK).unwrap_err();
        assert!(matches!(err, Error::RpIdHashMismatch), "got {err:?}");
    }

    #[test]
    fn auth_data_too_short_rejected() {
        let (sk, pk) = keypair();
        // 36-byte authData (one short of the 37-byte minimum).
        let short = vec![0u8; 36];
        let sig = sign(&sk, &short, b"x");
        let blob = encode_assertion(&sig, &short);

        let err = verify_assertion(&blob, b"x", &pk, APP_ID, CLOCK).unwrap_err();
        assert!(matches!(err, Error::Cbor(_)), "got {err:?}");
    }

    #[test]
    fn assertion_not_cbor_map_rejected() {
        // A bare CBOR array, not a map.
        let mut blob = Vec::new();
        ciborium::into_writer(&Value::Array(vec![Value::Integer(1.into())]), &mut blob).unwrap();
        let err = verify_assertion(&blob, b"x", &[0u8; 65], APP_ID, CLOCK).unwrap_err();
        assert!(matches!(err, Error::Cbor(_)), "got {err:?}");
    }

    #[test]
    fn assertion_missing_signature_field_rejected() {
        let auth_data = auth_data_for(APP_ID, 1);
        let map = Value::Map(vec![(
            Value::Text("authenticatorData".into()),
            Value::Bytes(auth_data),
        )]);
        let mut blob = Vec::new();
        ciborium::into_writer(&map, &mut blob).unwrap();
        let err = verify_assertion(&blob, b"x", &[0u8; 65], APP_ID, CLOCK).unwrap_err();
        assert!(matches!(err, Error::Cbor(_)), "got {err:?}");
    }

    #[test]
    fn assertion_missing_auth_data_field_rejected() {
        let map = Value::Map(vec![(
            Value::Text("signature".into()),
            Value::Bytes(vec![0x30, 0x06]),
        )]);
        let mut blob = Vec::new();
        ciborium::into_writer(&map, &mut blob).unwrap();
        let err = verify_assertion(&blob, b"x", &[0u8; 65], APP_ID, CLOCK).unwrap_err();
        assert!(matches!(err, Error::Cbor(_)), "got {err:?}");
    }

    #[test]
    fn truncated_cbor_rejected() {
        let (sk, pk) = keypair();
        let client_data = b"payload";
        let auth_data = auth_data_for(APP_ID, 1);
        let sig = sign(&sk, &auth_data, client_data);
        let blob = encode_assertion(&sig, &auth_data);
        // Truncate to half — decoder must error, not panic.
        let truncated = &blob[..blob.len() / 2];
        let err = verify_assertion(truncated, client_data, &pk, APP_ID, CLOCK).unwrap_err();
        assert!(matches!(err, Error::Cbor(_)), "got {err:?}");
    }

    #[test]
    fn unparseable_attested_key_rejected() {
        // Valid blob shape, but the attested key is not a valid SEC1 point.
        let (sk, _pk) = keypair();
        let client_data = b"payload";
        let auth_data = auth_data_for(APP_ID, 1);
        let sig = sign(&sk, &auth_data, client_data);
        let blob = encode_assertion(&sig, &auth_data);
        let bad_key = [0u8; 65]; // 0x00 prefix is not a valid uncompressed point
        let err = verify_assertion(&blob, client_data, &bad_key, APP_ID, CLOCK).unwrap_err();
        assert!(matches!(err, Error::Der(_)), "got {err:?}");
    }
}
