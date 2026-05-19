use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("CBOR decode error: {0}")]
    Cbor(String),

    #[error("DER/X.509 error: {0}")]
    Der(String),

    #[error("COSE_Key parse error: {0}")]
    Cose(String),

    #[error("attestation has wrong fmt: expected 'apple-appattest', got '{0}'")]
    WrongFormat(String),

    #[error("x5c chain is empty")]
    EmptyX5c,

    #[error("x5c chain does not terminate at Apple App Attestation Root CA")]
    UntrustedChain,

    #[error("missing Apple nonce extension (OID 1.2.840.113635.100.8.2) on leaf certificate")]
    MissingNonceExtension,

    #[error("computed nonce does not match certificate extension nonce")]
    NonceMismatch,

    #[error("attested keyId does not match SHA-256 of the public key")]
    KeyIdMismatch,

    #[error("aaguid mismatch: expected {expected}, got {got:?}")]
    AaguidMismatch { expected: &'static str, got: Vec<u8> },

    #[error("rpIdHash does not match SHA-256(app_id)")]
    RpIdHashMismatch,

    #[error("signCount must be 0 on initial attestation, got {0}")]
    SignCountNotZero(u32),

    #[error("authData is too short: got {0} bytes")]
    AuthDataTooShort(usize),

    #[error("authData missing attested-credential-data flag")]
    NoAttestedCredentialData,

    #[error("public key is not P-256")]
    NotP256,
}
