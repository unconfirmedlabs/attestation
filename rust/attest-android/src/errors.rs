//! Error types for the Android Key Attestation verifier.

use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("DER decoding error: {0}")]
    Der(String),

    #[error("certificate chain is empty")]
    EmptyChain,

    #[error("certificate chain does not anchor at any pinned Google attestation root")]
    UntrustedChain,

    #[error("attestation extension (OID 1.3.6.1.4.1.11129.2.1.17) not present on leaf cert")]
    MissingAttestationExtension,

    #[error("attestation challenge does not match expected value")]
    ChallengeMismatch,

    #[error(
        "attestation security level {got:?} does not meet required minimum {required:?}"
    )]
    InsufficientSecurityLevel {
        got: crate::key_description::SecurityLevel,
        required: crate::key_description::SecurityLevel,
    },

    #[error("attested public key encoding is malformed: {0}")]
    BadAttestedKey(String),

    #[error("certificate revoked or suspended: serial {serial}, status {status}, reason {reason}")]
    Revoked {
        serial: String,
        status: String,
        reason: String,
    },

    #[error("verifiedBootState {0:?} is not acceptable for this verifier")]
    UnacceptableBootState(crate::key_description::VerifiedBootState),

    #[error("device is unlocked (root-of-trust deviceLocked = false)")]
    DeviceUnlocked,
}
