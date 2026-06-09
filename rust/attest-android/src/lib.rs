//! Android Key Attestation verifier.
//!
//! Verifies that a hardware-backed Android Keystore key was attested by an
//! X.509 chain rooted at one of Google's pinned attestation roots, that the
//! attestation extension on the leaf binds the key to a caller-supplied
//! challenge, and that the security level + boot state meet a configurable
//! policy.
//!
//! On success, produces a canonical [`Outcome`](attestation_core::Outcome)
//! suitable for enclave-signing and on-chain consumption by the
//! `attest_android` Move package.
//!
//! References:
//!
//! - <https://source.android.com/docs/security/features/keystore/attestation>
//! - <https://developer.android.com/privacy-and-security/security-key-attestation>
//! - <https://android.googleapis.com/attestation/root> (trust anchors)
//! - <https://android.googleapis.com/attestation/status> (revocation list)

mod errors;
pub mod key_description;
pub mod roots;
pub mod status_list;

pub use attestation_core::{sources, Outcome};
pub use errors::{Error, Result};
pub use key_description::{
    attestation_application_id, AttestationApplicationId, AuthorizationList, KeyDescription,
    PackageInfo, RootOfTrust, SecurityLevel, VerifiedBootState, OID_ANDROID_KEY_ATTESTATION,
};
pub use status_list::{StatusEntry, StatusList};

use const_oid::ObjectIdentifier;
use der::Decode as _;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

/// Policy knobs the caller supplies. These are the levers a consumer
/// actually adjusts; everything else is enforced by spec compliance.
#[derive(Debug, Clone)]
pub struct Policy<'a> {
    /// Minimum security level required for both the attestation itself
    /// (`attestationSecurityLevel`) and the key it describes
    /// (`keymintSecurityLevel`).
    pub min_security_level: SecurityLevel,
    /// Require the device boot to be Verified (GREEN). If `false`, the
    /// caller MUST supply [`allowed_self_signed_keys`] to allow specific
    /// alt-OS boot keys (e.g., GrapheneOS).
    pub require_verified_boot: bool,
    /// Allow `SelfSigned` (YELLOW) boot state, but ONLY when the
    /// `verifiedBootKey` hash matches one of these entries. Empty list +
    /// `require_verified_boot = false` means YELLOW is accepted with no
    /// key restriction (not recommended for production).
    pub allowed_self_signed_keys: &'a [Vec<u8>],
    /// Require `deviceLocked = true`. Should almost always be `true`.
    pub require_device_locked: bool,
    /// Optional revocation status list. If supplied, every certificate
    /// serial in the chain is checked against it and any REVOKED or
    /// SUSPENDED match aborts verification.
    pub status_list: Option<&'a StatusList>,
}

impl Default for Policy<'_> {
    fn default() -> Self {
        Self {
            min_security_level: SecurityLevel::TrustedEnvironment,
            require_verified_boot: true,
            allowed_self_signed_keys: &[],
            require_device_locked: true,
            status_list: None,
        }
    }
}

/// Verify an Android Key Attestation chain.
///
/// # Arguments
/// * `chain` — DER-encoded certificates, ordered leaf-first.
/// * `challenge` — caller-supplied bytes the leaf's
///   `attestationChallenge` field must equal exactly.
/// * `policy` — security-level and boot-state requirements.
/// * `clock_ms` — current verifier timestamp, milliseconds since Unix epoch.
///
/// # Returns
/// An [`Outcome`] whose `attested_value` is the leaf certificate's
/// `subjectPublicKeyInfo` encoded as DER. (We deliberately return the SPKI
/// rather than a curve-specific byte form: KeyMint can attest P-256,
/// P-384, RSA, and Ed25519, so the SPKI is the only universal carrier.)
pub fn verify_attestation(
    chain: &[Vec<u8>],
    challenge: &[u8],
    policy: &Policy<'_>,
    clock_ms: u64,
) -> Result<Outcome> {
    // 1. Chain → leaf.
    let leaf = roots::validate_chain(chain, clock_ms)?;

    // 2. Revocation check, every cert.
    if let Some(list) = policy.status_list {
        for der in chain {
            check_status(der, list)?;
        }
    }

    // 3. Decode the Android key-description extension.
    let ext_value = extract_attestation_extension(&leaf)?;
    let kd = KeyDescription::from_der(&ext_value)?;

    // 4. Challenge equality.
    if kd.attestation_challenge.as_slice() != challenge {
        return Err(Error::ChallengeMismatch);
    }

    // 5. Security level — BOTH the attestation itself and the key it
    //    describes must meet the minimum. Reject when either is software.
    if !kd.attestation_security_level.meets(policy.min_security_level) {
        return Err(Error::InsufficientSecurityLevel {
            got: kd.attestation_security_level,
            required: policy.min_security_level,
        });
    }
    if !kd.keymint_security_level.meets(policy.min_security_level) {
        return Err(Error::InsufficientSecurityLevel {
            got: kd.keymint_security_level,
            required: policy.min_security_level,
        });
    }

    // 6. Verified Boot — only trust hardwareEnforced.rootOfTrust.
    //
    // Acceptance matrix:
    //   require_verified_boot = true             → GREEN only.
    //   require_verified_boot = false +
    //       allowed_self_signed_keys empty       → any state accepted.
    //   require_verified_boot = false +
    //       allowed_self_signed_keys non-empty   → GREEN, or YELLOW iff
    //                                              boot key matches.
    if let Some(rot) = &kd.hardware_enforced.root_of_trust {
        if policy.require_device_locked && !rot.device_locked {
            return Err(Error::DeviceUnlocked);
        }
        match rot.verified_boot_state {
            VerifiedBootState::Verified => {}
            _ if !policy.require_verified_boot && policy.allowed_self_signed_keys.is_empty() => {
                // Caller has opted out of boot-state checks entirely.
            }
            VerifiedBootState::SelfSigned
                if !policy.require_verified_boot
                    && policy
                        .allowed_self_signed_keys
                        .iter()
                        .any(|k| k.as_slice() == rot.verified_boot_key.as_slice()) => {}
            state => return Err(Error::UnacceptableBootState(state)),
        }
    } else if policy.require_verified_boot {
        return Err(Error::UnacceptableBootState(VerifiedBootState::Failed));
    }

    // 7. Pull leaf SPKI as the attested value.
    let spki_der = leaf
        .tbs_certificate
        .subject_public_key_info
        .to_der_vec()?;

    let detail_hash: Vec<u8> = Sha256::digest(canonical_chain_hash_input(chain)).to_vec();

    Ok(Outcome {
        source: sources::ANDROID_KEY_ATTEST.to_string(),
        attested_value: spki_der,
        challenge: challenge.to_vec(),
        timestamp_ms: clock_ms,
        detail_hash,
    })
}

/// Helper to encode the leaf SPKI to DER.
trait ToDerVec {
    fn to_der_vec(&self) -> Result<Vec<u8>>;
}

impl ToDerVec for x509_cert::spki::SubjectPublicKeyInfoOwned {
    fn to_der_vec(&self) -> Result<Vec<u8>> {
        use der::Encode as _;
        self.to_der()
            .map_err(|e| Error::Der(format!("SPKI encode: {e}")))
    }
}

/// Returns the bytes *inside* the OCTET STRING wrapper of the Android key
/// attestation extension on the leaf certificate.
fn extract_attestation_extension(leaf: &Certificate) -> Result<Vec<u8>> {
    let target_oid: ObjectIdentifier = OID_ANDROID_KEY_ATTESTATION
        .parse()
        .expect("constant OID is well-formed");

    let exts = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(Error::MissingAttestationExtension)?;

    let ext = exts
        .iter()
        .find(|e| e.extn_id == target_oid)
        .ok_or(Error::MissingAttestationExtension)?;

    // The extension `extnValue` is itself an OCTET STRING; its inner
    // bytes are the DER-encoded KeyDescription.
    Ok(ext.extn_value.as_bytes().to_vec())
}

fn canonical_chain_hash_input(chain: &[Vec<u8>]) -> Vec<u8> {
    let mut buf = Vec::new();
    for c in chain {
        buf.extend_from_slice(&(c.len() as u32).to_be_bytes());
        buf.extend_from_slice(c);
    }
    buf
}

fn check_status(der: &[u8], list: &StatusList) -> Result<()> {
    let cert = Certificate::from_der(der)
        .map_err(|e| Error::Der(format!("cert parse for status: {e}")))?;
    let serial = cert.tbs_certificate.serial_number.as_bytes();
    let mut hex = String::with_capacity(serial.len() * 2);
    let mut leading = true;
    for b in serial {
        if leading {
            if *b == 0 {
                continue;
            }
            leading = false;
        }
        hex.push_str(&format!("{b:02x}"));
    }
    if hex.is_empty() {
        hex.push('0');
    }
    if let Some(entry) = list.lookup_serial(&hex) {
        return Err(Error::Revoked {
            serial: hex,
            status: entry.status.clone(),
            reason: entry.reason.clone(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod smoke {
    use super::*;

    #[test]
    fn empty_chain_rejected() {
        let r = verify_attestation(&[], b"x", &Policy::default(), 0);
        assert!(matches!(r, Err(Error::EmptyChain)));
    }
}
