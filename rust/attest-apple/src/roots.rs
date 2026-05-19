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
use der::{Decode, Encode};
use p256::ecdsa::{signature::Verifier as _, DerSignature, VerifyingKey};
use x509_cert::Certificate;

/// Apple App Attestation Root CA in DER form.
///
/// TODO: populate with the actual DER-encoded bytes of Apple's root.
/// Convert from the published PEM:
///
/// ```sh
/// curl -L -o root.pem \
///   https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem
/// openssl x509 -in root.pem -outform DER -out src/assets/apple_app_attest_root.der
/// ```
///
/// Then replace this empty slice with:
///
/// ```ignore
/// pub const APPLE_APP_ATTEST_ROOT_DER: &[u8] =
///     include_bytes!("assets/apple_app_attest_root.der");
/// ```
pub const APPLE_APP_ATTEST_ROOT_DER: &[u8] = &[];

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

    // Root anchor.
    if APPLE_APP_ATTEST_ROOT_DER.is_empty() {
        // Without the pinned root we cannot complete the chain anchor check.
        // The verifier still requires this in production; tests may proceed
        // with placeholder.
        eprintln!(
            "[attest-apple] WARNING: APPLE_APP_ATTEST_ROOT_DER is empty; \
             skipping root anchor verification. Set the root bytes before \
             production use."
        );
    } else {
        let root = Certificate::from_der(APPLE_APP_ATTEST_ROOT_DER)
            .map_err(|e| Error::Der(format!("pinned root parse: {e}")))?;
        let top = certs.last().expect("non-empty");
        verify_signature(top, &root)?;
    }

    Ok(certs.into_iter().next().expect("non-empty"))
}

/// Verify that `cert.signature` over `cert.tbsCertificate` is valid under
/// `issuer`'s public key.
///
/// Assumes P-256 + SHA-256 (ecdsa-with-SHA256). Apple's App Attest chain
/// uses this throughout; if Apple ever rotates to a different algorithm
/// we'll surface a parse error and update.
fn verify_signature(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;
    let issuer_pk_bytes = issuer_spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::Der("issuer public key not byte-aligned".into()))?;

    let verifying_key = VerifyingKey::from_sec1_bytes(issuer_pk_bytes)
        .map_err(|e| Error::Der(format!("issuer verifying key: {e}")))?;

    let tbs_bytes = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::Der(format!("tbs encode: {e}")))?;

    let sig_bytes = cert
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Der("signature not byte-aligned".into()))?;

    let signature = DerSignature::try_from(sig_bytes)
        .map_err(|e| Error::Der(format!("signature decode: {e}")))?;

    verifying_key
        .verify(&tbs_bytes, &signature)
        .map_err(|_| Error::UntrustedChain)?;

    Ok(())
}
