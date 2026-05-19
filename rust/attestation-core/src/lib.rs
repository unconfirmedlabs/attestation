//! Shared outcome type for the attestation primitive family.
//!
//! Each per-platform Rust verifier returns an [`Outcome`] describing a
//! successfully-verified hardware attestation. This struct is internal to
//! the verifier toolchain — `enclave-server` reads its fields, constructs a
//! per-platform `<Platform>Payload` (matching the Move-side struct exactly),
//! BCS-encodes the payload, and binds `SHA-256(payload_bcs)` into the
//! `user_data` field of a fresh AWS-Nitro-signed NSM attestation document.
//!
//! The on-chain Move side does NOT decode `Outcome`. It re-derives the
//! payload BCS hash from individual fields submitted by the caller and
//! checks it against the NSM doc's `user_data`. The Move verifier emits a
//! typed `Witness<Source>` whose timestamp comes from the NSM document, not
//! from any field in `Outcome`.
//!
//! Fields are deliberately minimal: anything platform-specific lives in
//! `detail_hash` as a commitment, not as readable structured data.

use serde::{Deserialize, Serialize};

/// A successfully-verified attestation outcome.
///
/// Internal to the verifier toolchain. `enclave-server` reads these fields
/// individually and constructs a per-platform `<Platform>Payload` (a strict
/// subset, with field order matching the Move struct) for the NSM `user_data`
/// binding. The on-chain consumer never sees this struct.
///
/// The BCS roundtrip methods + the layout-stability test below exist so the
/// struct can be cached or transported between Rust processes — they are
/// NOT a load-bearing on-chain contract.
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
    pub const APPLE_APP_ATTEST_ASSERTION: &str = "apple-app-attest-assertion";
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
        // Pin the BCS encoding of `Outcome` so cross-process callers that
        // serialize/deserialize the struct don't drift. The on-chain trust
        // path does NOT depend on this layout — each Move package binds to
        // its own per-platform Payload BCS hash.
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
