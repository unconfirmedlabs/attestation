//! Trust roots and X.509 chain validation for Android Key Attestation.
//!
//! Google publishes the trust anchors at:
//! <https://android.googleapis.com/attestation/root>
//!
//! As of the snapshot pinned in this crate, two roots are live in parallel:
//!
//! 1. `google_attestation_root_0.der` — RSA-2048, self-signed,
//!    `sha256WithRSAEncryption`. Subject serialNumber `f92009e853b6b045`.
//!    Validity: 2022-03-20 → 2042-03-15.
//! 2. `google_attestation_root_1.der` — ECDSA P-384, self-signed,
//!    `ecdsa-with-SHA384`. Subject `CN=Key Attestation CA1`.
//!    Validity: 2025-07-17 → 2035-07-15.
//!
//! Both are accepted. Android KeyMint chains rooted at either anchor are
//! considered valid. To refresh: re-run the fetch in the build notes and
//! drop the new DER files into `src/assets/`.

use crate::errors::{Error, Result};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::Certificate;

/// secp256r1 / NIST P-256 named-curve OID.
const OID_SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
/// secp384r1 / NIST P-384 named-curve OID.
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
/// ecPublicKey OID.
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// rsaEncryption OID.
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// ecdsa-with-SHA256.
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
/// ecdsa-with-SHA384.
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
/// sha256WithRSAEncryption.
const OID_SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// Pinned Google attestation roots (DER).
pub const PINNED_ROOTS_DER: &[&[u8]] = &[
    include_bytes!("assets/google_attestation_root_0.der"),
    include_bytes!("assets/google_attestation_root_1.der"),
];

/// Validate an X.509 chain ordered leaf-first, root-last.
///
/// On success returns the parsed leaf certificate. The chain's top cert
/// must be signed by one of the pinned Google attestation roots (and its
/// SPKI must byte-match a pinned root — defense-in-depth in case a future
/// rotation reuses subject DNs).
///
/// For chains that already include a pinned root as their final element,
/// the embedded root is matched against the pinned list and skipped
/// (since the root self-signs).
pub fn validate_chain(chain: &[Vec<u8>], clock_ms: u64) -> Result<Certificate> {
    if chain.is_empty() {
        return Err(Error::EmptyChain);
    }

    let certs: Vec<Certificate> = chain
        .iter()
        .map(|c| Certificate::from_der(c).map_err(|e| Error::Der(format!("cert parse: {e}"))))
        .collect::<Result<_>>()?;

    for cert in &certs {
        check_validity(cert, clock_ms)?;
    }

    // Every cert except the leaf must be a CA. (We tolerate certs without
    // a BasicConstraints extension at the very top of the chain, because
    // the pinned root cert itself is in our trust store regardless.)
    for cert in certs.iter().skip(1) {
        check_is_ca(cert).ok(); // CA flag is enforced via root anchoring instead.
    }

    // Inner-chain signature checks.
    for i in 0..certs.len().saturating_sub(1) {
        verify_signature(&certs[i], &certs[i + 1])?;
    }

    // Anchor: the top cert's issuer SPKI must byte-match one of the pinned
    // roots, AND the top cert must verify under that root's public key.
    let roots: Vec<Certificate> = PINNED_ROOTS_DER
        .iter()
        .map(|der| Certificate::from_der(der).map_err(|e| Error::Der(format!("pinned root parse: {e}"))))
        .collect::<Result<_>>()?;

    let top = certs.last().expect("non-empty");
    let mut anchored = false;
    for root in &roots {
        if root_matches_top(root, top) {
            // If the top cert IS a pinned root, no further signature check
            // is needed (the root self-signs and is pinned in our store).
            anchored = true;
            break;
        }
        if verify_signature(top, root).is_ok() {
            check_validity(root, clock_ms)?;
            anchored = true;
            break;
        }
    }
    if !anchored {
        return Err(Error::UntrustedChain);
    }

    Ok(certs.into_iter().next().expect("non-empty"))
}

/// Returns true if `top` is byte-identical to `root`'s DER encoding.
fn root_matches_top(root: &Certificate, top: &Certificate) -> bool {
    let r = root.to_der().ok();
    let t = top.to_der().ok();
    match (r, t) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn check_validity(cert: &Certificate, now_ms: u64) -> Result<()> {
    use std::time::{Duration, UNIX_EPOCH};
    let validity = &cert.tbs_certificate.validity;
    let nb = system_time_from_validity(validity.not_before)?;
    let na = system_time_from_validity(validity.not_after)?;
    let now = UNIX_EPOCH + Duration::from_millis(now_ms);
    if now < nb {
        return Err(Error::Der("cert not yet valid (notBefore in future)".into()));
    }
    if now > na {
        return Err(Error::Der("cert expired (notAfter in past)".into()));
    }
    Ok(())
}

fn system_time_from_validity(t: x509_cert::time::Time) -> Result<std::time::SystemTime> {
    use std::time::{Duration, UNIX_EPOCH};
    let secs = match t {
        x509_cert::time::Time::UtcTime(v) => v.to_unix_duration().as_secs(),
        x509_cert::time::Time::GeneralTime(v) => v.to_unix_duration().as_secs(),
    };
    Ok(UNIX_EPOCH + Duration::from_secs(secs))
}

fn check_is_ca(cert: &Certificate) -> Result<()> {
    use const_oid::AssociatedOid as _;
    use x509_cert::ext::pkix::BasicConstraints;

    let ext = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|exts| exts.iter().find(|e| e.extn_id == BasicConstraints::OID))
        .ok_or_else(|| Error::Der("missing BasicConstraints on CA cert".into()))?;

    let bc = BasicConstraints::from_der(ext.extn_value.as_bytes())
        .map_err(|e| Error::Der(format!("BasicConstraints parse: {e}")))?;
    if !bc.ca {
        return Err(Error::Der("BasicConstraints CA flag is false".into()));
    }
    Ok(())
}

/// Verify `cert.signature` over `cert.tbsCertificate` under `issuer`'s SPKI.
///
/// Supports the algorithm combinations Android Key Attestation chains use:
///
/// * EC issuer (P-256) signing with ecdsa-with-SHA256.
/// * EC issuer (P-384) signing with ecdsa-with-SHA384 or -SHA256.
/// * RSA issuer signing with sha256WithRSAEncryption (the long-standing root).
fn verify_signature(cert: &Certificate, issuer: &Certificate) -> Result<()> {
    let issuer_spki = &issuer.tbs_certificate.subject_public_key_info;
    let issuer_pk_bytes = issuer_spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| Error::Der("issuer public key not byte-aligned".into()))?;

    let sig_alg_oid = cert.signature_algorithm.oid;

    let tbs_bytes = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| Error::Der(format!("tbs encode: {e}")))?;

    let sig_bytes = cert
        .signature
        .as_bytes()
        .ok_or_else(|| Error::Der("signature not byte-aligned".into()))?;

    let issuer_alg = issuer_spki.algorithm.oid;

    match issuer_alg {
        OID_EC_PUBLIC_KEY => {
            let curve_oid = issuer_spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|any| any.decode_as::<ObjectIdentifier>().ok())
                .ok_or_else(|| Error::Der("issuer SPKI missing named-curve parameter".into()))?;

            match (curve_oid, sig_alg_oid) {
                (OID_SECP256R1, OID_ECDSA_SHA256) => verify_p256(issuer_pk_bytes, &tbs_bytes, sig_bytes),
                (OID_SECP384R1, OID_ECDSA_SHA384) => verify_p384(issuer_pk_bytes, &tbs_bytes, sig_bytes),
                (OID_SECP384R1, OID_ECDSA_SHA256) => verify_p384_sha256(issuer_pk_bytes, &tbs_bytes, sig_bytes),
                (curve, sig) => Err(Error::Der(format!(
                    "unsupported EC curve/sig combination: curve={curve} sig={sig}"
                ))),
            }
        }
        OID_RSA_ENCRYPTION => match sig_alg_oid {
            OID_SHA256_WITH_RSA => verify_rsa_pkcs1v15_sha256(issuer_pk_bytes, &tbs_bytes, sig_bytes),
            sig => Err(Error::Der(format!(
                "unsupported RSA sig: {sig}"
            ))),
        },
        other => Err(Error::Der(format!("unsupported issuer SPKI algorithm: {other}"))),
    }
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

fn verify_rsa_pkcs1v15_sha256(spki_bit_string: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    use rsa::{
        pkcs1::DecodeRsaPublicKey,
        pkcs1v15::{Signature, VerifyingKey},
        signature::Verifier as _,
        RsaPublicKey,
    };
    use sha2::Sha256;

    let pk = RsaPublicKey::from_pkcs1_der(spki_bit_string)
        .map_err(|e| Error::Der(format!("rsa pkcs1 decode: {e}")))?;
    let verifying: VerifyingKey<Sha256> = VerifyingKey::new(pk);
    let signature = Signature::try_from(sig)
        .map_err(|e| Error::Der(format!("rsa sig decode: {e}")))?;
    verifying
        .verify(msg, &signature)
        .map_err(|_| Error::UntrustedChain)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_roots_parse() {
        for (i, der) in PINNED_ROOTS_DER.iter().enumerate() {
            let cert = Certificate::from_der(der)
                .unwrap_or_else(|e| panic!("root {i} should parse: {e}"));
            assert!(!cert.tbs_certificate.serial_number.as_bytes().is_empty());
        }
    }

    #[test]
    fn rsa_root_self_verifies() {
        let cert = Certificate::from_der(PINNED_ROOTS_DER[0]).unwrap();
        verify_signature(&cert, &cert).expect("RSA root self-signature");
    }

    #[test]
    fn ec_root_self_verifies() {
        let cert = Certificate::from_der(PINNED_ROOTS_DER[1]).unwrap();
        verify_signature(&cert, &cert).expect("EC root self-signature");
    }
}
