//! OID definitions and helpers for Apple's attestation extensions.

use crate::errors::{Error, Result};
use const_oid::ObjectIdentifier;
use der::{Decode, Sequence};
use x509_cert::Certificate;

/// Apple App Attest nonce extension.
///
/// The extension is non-critical and its value is a DER-encoded SEQUENCE:
///
/// ```text
/// SEQUENCE {
///     [1] EXPLICIT OCTET STRING (32 bytes)
/// }
/// ```
pub const APPLE_NONCE_EXTENSION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113635.100.8.2");

#[derive(Debug, Sequence)]
struct AppleNonceExtension {
    #[asn1(context_specific = "1", tag_mode = "EXPLICIT")]
    nonce: der::asn1::OctetString,
}

pub fn extract_nonce_extension(cert: &Certificate) -> Result<[u8; 32]> {
    let extensions = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(Error::MissingNonceExtension)?;

    let ext = extensions
        .iter()
        .find(|e| e.extn_id == APPLE_NONCE_EXTENSION)
        .ok_or(Error::MissingNonceExtension)?;

    let parsed = AppleNonceExtension::from_der(ext.extn_value.as_bytes())
        .map_err(|e| Error::Der(format!("nonce extension: {e}")))?;

    let bytes = parsed.nonce.as_bytes();
    if bytes.len() != 32 {
        return Err(Error::Der(format!(
            "nonce must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
