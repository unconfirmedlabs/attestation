//! Shared outcome type for the attestation primitive family.
//!
//! Each per-platform Rust verifier produces an [`Outcome`] describing a
//! successfully-verified hardware attestation. The outcome is BCS-encoded,
//! signed by a trusted verifier (typically a Nautilus enclave), and submitted
//! on-chain. The corresponding Move package decodes the BCS, verifies the
//! signature, and emits a typed `Witness<Source>` for downstream consumers.
//!
//! The fields are deliberately minimal: anything platform-specific lives in
//! `detail_hash` as a commitment, not as readable structured data.

use serde::{Deserialize, Serialize};

/// A successfully-verified attestation outcome.
///
/// The on-chain Move representation of this struct must match the BCS layout
/// produced here exactly: source (utf8 bytes, length-prefixed), attested_value
/// (length-prefixed bytes), challenge (length-prefixed bytes), timestamp_ms
/// (u64 LE), detail_hash (length-prefixed bytes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Outcome {
    /// Identifier of the attestation source.
    ///
    /// Must match the corresponding [`sources`] constant. The on-chain consumer
    /// rejects outcomes whose source does not match its expected value, so
    /// outcomes are not transferable between packages.
    pub source: String,

    /// The attested value:
    /// - For asymmetric attestations: the attested public key (e.g., P-256
    ///   uncompressed SEC1, 65 bytes).
    /// - For symmetric attestations (e.g., NTAG): the chip UID.
    pub attested_value: Vec<u8>,

    /// The challenge the attestation was bound to. The consumer reconstructs
    /// the canonical challenge from its own state and compares.
    pub challenge: Vec<u8>,

    /// Verifier timestamp in milliseconds since Unix epoch. Used by the
    /// consumer to reject stale outcomes.
    pub timestamp_ms: u64,

    /// SHA-256 hash of the raw platform attestation blob. Recorded on-chain
    /// as a commitment so the original attestation can be presented later
    /// for re-verification or dispute resolution.
    pub detail_hash: Vec<u8>,
}

impl Outcome {
    pub fn to_bcs(&self) -> bcs::Result<Vec<u8>> {
        bcs::to_bytes(self)
    }

    pub fn from_bcs(bytes: &[u8]) -> bcs::Result<Self> {
        bcs::from_bytes(bytes)
    }
}

/// Canonical source identifiers.
///
/// These string constants are what each verifier puts in [`Outcome::source`]
/// and what each consuming Move package compares against.
pub mod sources {
    pub const APPLE_APP_ATTEST: &str = "apple-app-attest";
    pub const APPLE_WEBAUTHN: &str = "apple-webauthn";
    pub const ANDROID_KEY_ATTEST: &str = "android-key-attest";
    pub const ANDROID_WEBAUTHN_KEY: &str = "android-webauthn-key";
    pub const NTAG_ORIGINALITY: &str = "ntag-originality";
    pub const FIDO_PACKED: &str = "fido-packed";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_bcs_roundtrip() {
        let outcome = Outcome {
            source: sources::APPLE_APP_ATTEST.to_string(),
            attested_value: vec![0x04; 65],
            challenge: vec![0xAB; 32],
            timestamp_ms: 1_700_000_000_000,
            detail_hash: vec![0xCD; 32],
        };
        let bytes = outcome.to_bcs().expect("encode");
        let decoded = Outcome::from_bcs(&bytes).expect("decode");
        assert_eq!(decoded, outcome);
    }

    #[test]
    fn bcs_layout_is_stable() {
        // Pin the BCS encoding so on-chain decoders stay in sync.
        let outcome = Outcome {
            source: "x".to_string(),
            attested_value: vec![1, 2, 3],
            challenge: vec![4, 5],
            timestamp_ms: 1,
            detail_hash: vec![6],
        };
        let bytes = outcome.to_bcs().expect("encode");
        // Layout: vec_u8 prefixes are ULEB128; "x" = [1, b'x'], etc.
        let expected = [
            0x01, b'x', // source
            0x03, 0x01, 0x02, 0x03, // attested_value
            0x02, 0x04, 0x05, // challenge
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp_ms LE
            0x01, 0x06, // detail_hash
        ];
        assert_eq!(bytes, expected);
    }
}
