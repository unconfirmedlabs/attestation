//! Trust root and chain validation for Apple App Attest x5c chains.
//!
//! Apple publishes the **Apple App Attestation Root CA** at
//! <https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem>.
//!
//! The root signs an intermediate **Apple App Attestation CA 1**, which signs
//! the leaf certificate included in each attestation's `x5c` chain. The chain
//! sent in the attestation typically contains [leaf, intermediate] — the root
//! is not transmitted and must be pinned locally.

use crate::errors::{Error, Result};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::Certificate;

/// secp256r1 / NIST P-256 named-curve OID.
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// secp384r1 / NIST P-384 named-curve OID.
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// ecdsa-with-SHA256 signature-algorithm OID.
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// ecdsa-with-SHA384 signature-algorithm OID.
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

/// Apple App Attestation Root CA in DER form.
///
/// Source: <https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem>
///
/// Subject: CN=Apple App Attestation Root CA, O=Apple Inc., ST=California
/// Self-signed, P-384 + SHA-384.
pub const APPLE_APP_ATTEST_ROOT_DER: &[u8] =
    include_bytes!("assets/apple_app_attest_root.der");

/// Validate an x5c chain (leaf first, intermediate(s) after).
///
/// Each cert is verified against the next-up cert's public key, and the
/// top-most cert is verified against the pinned root. Returns the parsed
/// leaf certificate on success.
///
/// **Note**: until [`APPLE_APP_ATTEST_ROOT_DER`] is populated, the root
/// anchor check is skipped and a [`Error::UntrustedChain`] is logged. Chain
/// validation between intermediates is still performed.
pub fn validate_x5c_chain(x5c: &[Vec<u8>]) -> Result<Certificate> {
    if x5c.is_empty() {
        return Err(Error::EmptyX5c);
    }

    let certs: Vec<Certificate> = x5c
        .iter()
        .map(|c| Certificate::from_der(c).map_err(|e| Error::Der(format!("cert parse: {e}"))))
        .collect::<Result<_>>()?;

    // Inner chain: each cert must be signed by the next.
    for i in 0..certs.len().saturating_sub(1) {
        verify_signature(&certs[i], &certs[i + 1])?;
    }

    // Root anchor — the top of the supplied chain must be signed by the
    // pinned Apple App Attestation Root CA.
    let root = Certificate::from_der(APPLE_APP_ATTEST_ROOT_DER)
        .map_err(|e| Error::Der(format!("pinned root parse: {e}")))?;
    let top = certs.last().expect("non-empty");
    verify_signature(top, &root)?;

    Ok(certs.into_iter().next().expect("non-empty"))
}

/// Verify that `cert.signature` over `cert.tbsCertificate` is valid under
/// `issuer`'s public key.
///
/// Dispatches on:
///   * Issuer named curve — P-256 (secp256r1) or P-384 (secp384r1).
///     Apple's App Attest chain uses P-256 for device-attested leaf keys
///     and P-384 for "Apple App Attestation CA 1" and the root.
///   * Cert signature algorithm — ecdsa-with-SHA256 or ecdsa-with-SHA384.
fn verify_signature(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;
    let issuer_pk_bytes = issuer_spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::Der("issuer public key not byte-aligned".into()))?;

    // Read the named-curve parameter from the issuer SPKI.
    let curve_oid = issuer_spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|any| any.decode_as::<ObjectIdentifier>().ok())
        .ok_or_else(|| Error::Der("issuer SPKI missing named-curve parameter".into()))?;

    let sig_alg_oid = cert.signature_algorithm.oid;

    let tbs_bytes = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::Der(format!("tbs encode: {e}")))?;

    let sig_bytes = cert
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Der("signature not byte-aligned".into()))?;

    match (curve_oid, sig_alg_oid) {
        (OID_SECP256R1, OID_ECDSA_SHA256) => verify_p256(issuer_pk_bytes, &tbs_bytes, sig_bytes),
        (OID_SECP384R1, OID_ECDSA_SHA384) => verify_p384(issuer_pk_bytes, &tbs_bytes, sig_bytes),
        (OID_SECP384R1, OID_ECDSA_SHA256) => verify_p384_sha256(issuer_pk_bytes, &tbs_bytes, sig_bytes),
        (curve, sig) => Err(Error::Der(format!(
            "unsupported curve/sig combination: curve={curve} sig={sig}"
        ))),
    }
}

/// P-384 key verifying a SHA-256 prehash. Used by Apple's App Attest
/// intermediate ("Apple App Attestation CA 1") when it signs the leaf cert.
fn verify_p384_sha256(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    use p384::ecdsa::{signature::hazmat::PrehashVerifier as _, DerSignature, VerifyingKey};
    use sha2::{Digest, Sha256};
    let key = VerifyingKey::from_sec1_bytes(pk)
        .map_err(|e| Error::Der(format!("p384 verifying key: {e}")))?;
    let signature = DerSignature::try_from(sig)
        .map_err(|e| Error::Der(format!("p384 sig decode: {e}")))?;
    let digest = Sha256::digest(msg);
    key.verify_prehash(&digest, &signature).map_err(|_| Error::UntrustedChain)?;
    Ok(())
}

fn verify_p256(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    use p256::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};
    let key = VerifyingKey::from_sec1_bytes(pk)
        .map_err(|e| Error::Der(format!("p256 verifying key: {e}")))?;
    let signature = DerSignature::try_from(sig)
        .map_err(|e| Error::Der(format!("p256 sig decode: {e}")))?;
    key.verify(msg, &signature).map_err(|_| Error::UntrustedChain)?;
    Ok(())
}

fn verify_p384(pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    use p384::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};
    let key = VerifyingKey::from_sec1_bytes(pk)
        .map_err(|e| Error::Der(format!("p384 verifying key: {e}")))?;
    let signature = DerSignature::try_from(sig)
        .map_err(|e| Error::Der(format!("p384 sig decode: {e}")))?;
    key.verify(msg, &signature).map_err(|_| Error::UntrustedChain)?;
    Ok(())
}
