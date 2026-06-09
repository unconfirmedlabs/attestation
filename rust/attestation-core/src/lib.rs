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

    // --- helpers ----------------------------------------------------------

    /// A fully-specified, representative `Outcome` used across several tests.
    fn sample_outcome() -> Outcome {
        Outcome {
            source: sources::APPLE_APP_ATTEST.to_string(),
            attested_value: vec![0x04; 65],
            challenge: vec![0xAB; 32],
            timestamp_ms: 1_700_000_000_000,
            detail_hash: vec![0xCD; 32],
        }
    }

    /// Assert that an `Outcome` survives a BCS encode/decode round-trip.
    fn assert_roundtrip(outcome: &Outcome) {
        let bytes = outcome.to_bcs().expect("encode");
        let decoded = Outcome::from_bcs(&bytes).expect("decode");
        assert_eq!(&decoded, outcome);
    }

    // --- round-trip across edge field values ------------------------------

    #[test]
    fn roundtrip_all_fields_empty() {
        // Empty string, empty vecs, zero timestamp — minimal encoding.
        assert_roundtrip(&Outcome {
            source: String::new(),
            attested_value: Vec::new(),
            challenge: Vec::new(),
            timestamp_ms: 0,
            detail_hash: Vec::new(),
        });
    }

    #[test]
    fn roundtrip_timestamp_min_and_max() {
        let mut outcome = sample_outcome();
        outcome.timestamp_ms = u64::MIN;
        assert_roundtrip(&outcome);
        outcome.timestamp_ms = u64::MAX;
        assert_roundtrip(&outcome);
    }

    #[test]
    fn roundtrip_byte_value_extremes() {
        // Vecs containing the full 0x00..=0xFF byte range exercise that every
        // byte value survives intact (no UTF-8 / signedness surprises).
        let all_bytes: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        assert_roundtrip(&Outcome {
            source: "all-byte-source".to_string(),
            attested_value: all_bytes.clone(),
            challenge: all_bytes.clone(),
            timestamp_ms: 42,
            detail_hash: all_bytes,
        });
    }

    #[test]
    fn roundtrip_long_fields() {
        // Lengths that cross the single-byte ULEB128 boundary (>= 128) to make
        // sure multi-byte length prefixes round-trip.
        assert_roundtrip(&Outcome {
            source: "s".repeat(300),
            attested_value: vec![0x11; 1000],
            challenge: vec![0x22; 200],
            timestamp_ms: u64::MAX,
            detail_hash: vec![0x33; 128],
        });
    }

    #[test]
    fn roundtrip_unicode_source() {
        // `source` is a String; confirm multi-byte UTF-8 survives intact.
        assert_roundtrip(&Outcome {
            source: "ソース-source-🔐".to_string(),
            attested_value: vec![1, 2, 3],
            challenge: vec![4, 5, 6],
            timestamp_ms: 9,
            detail_hash: vec![7, 8, 9],
        });
    }

    #[test]
    fn roundtrip_each_canonical_source() {
        // Every published source identifier must round-trip cleanly.
        for source in [
            sources::APPLE_APP_ATTEST,
            sources::APPLE_APP_ATTEST_ASSERTION,
            sources::APPLE_WEBAUTHN,
            sources::ANDROID_KEY_ATTEST,
            sources::ANDROID_WEBAUTHN_KEY,
            sources::NTAG_ORIGINALITY,
            sources::FIDO_PACKED,
        ] {
            let mut outcome = sample_outcome();
            outcome.source = source.to_string();
            assert_roundtrip(&outcome);
        }
    }

    // --- malformed / truncated / empty input ------------------------------

    #[test]
    fn from_bcs_empty_is_err() {
        assert!(Outcome::from_bcs(&[]).is_err());
    }

    #[test]
    fn from_bcs_truncated_at_every_prefix_is_err() {
        // Every strict prefix of a valid encoding (except the full length) must
        // be rejected, never panic.
        let bytes = sample_outcome().to_bcs().expect("encode");
        for len in 0..bytes.len() {
            assert!(
                Outcome::from_bcs(&bytes[..len]).is_err(),
                "expected Err for prefix of length {len}",
            );
        }
        // Sanity: the full slice still decodes.
        assert!(Outcome::from_bcs(&bytes).is_ok());
    }

    #[test]
    fn from_bcs_trailing_garbage_is_err() {
        // BCS is canonical: leftover bytes after a valid value are an error.
        let mut bytes = sample_outcome().to_bcs().expect("encode");
        bytes.push(0xFF);
        assert!(Outcome::from_bcs(&bytes).is_err());
    }

    #[test]
    fn from_bcs_length_prefix_exceeds_remaining_is_err() {
        // A `source` length prefix claiming more bytes than are present must be
        // rejected rather than over-reading.
        let bytes = [0x7F, b'a', b'b']; // claims 127-byte string, only 2 present
        assert!(Outcome::from_bcs(&bytes).is_err());
    }

    #[test]
    fn from_bcs_invalid_utf8_source_is_err() {
        // `source` is a String, so non-UTF-8 bytes in that field must fail.
        // Layout: [len=1][0xFF invalid utf8] then the remaining fields.
        let bytes = [
            0x01, 0xFF, // source: length 1, byte 0xFF (invalid UTF-8)
            0x00, // attested_value: empty
            0x00, // challenge: empty
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // timestamp_ms
            0x00, // detail_hash: empty
        ];
        assert!(Outcome::from_bcs(&bytes).is_err());
    }

    // --- golden bytes for a fully-specified Outcome -----------------------

    #[test]
    fn golden_bytes_fully_specified() {
        // A second, independently-derived golden vector for a realistic,
        // fully-populated `Outcome`. Pins field ORDER and per-field encoding so
        // an accidental reorder or type change is caught loudly. Bytes derived
        // by reasoning about BCS (lengths are ULEB128, u64 is little-endian).
        let outcome = Outcome {
            source: "ab".to_string(),
            attested_value: vec![0x10, 0x11, 0x12, 0x13],
            challenge: vec![0x20, 0x21],
            timestamp_ms: 0x0102_0304_0506_0708,
            detail_hash: vec![0xFE, 0xDC, 0xBA],
        };

        let mut expected = Vec::new();
        // source: ULEB128 len (2) + "ab"
        expected.extend_from_slice(&[0x02, b'a', b'b']);
        // attested_value: ULEB128 len (4) + bytes
        expected.extend_from_slice(&[0x04, 0x10, 0x11, 0x12, 0x13]);
        // challenge: ULEB128 len (2) + bytes
        expected.extend_from_slice(&[0x02, 0x20, 0x21]);
        // timestamp_ms: u64 little-endian
        expected.extend_from_slice(&[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        // detail_hash: ULEB128 len (3) + bytes
        expected.extend_from_slice(&[0x03, 0xFE, 0xDC, 0xBA]);

        let bytes = outcome.to_bcs().expect("encode");
        assert_eq!(
            bytes,
            expected,
            "BCS layout drifted; got {}",
            hex::encode(&bytes),
        );
        // And the golden bytes decode back to the original.
        assert_eq!(Outcome::from_bcs(&expected).expect("decode"), outcome);
    }

    #[test]
    fn golden_bytes_multibyte_length_prefix() {
        // Pin a case where a field length (200) requires a 2-byte ULEB128
        // prefix: 200 = 0xC8 -> encoded as [0xC8, 0x01].
        let outcome = Outcome {
            source: String::new(),
            attested_value: vec![0x07; 200],
            challenge: Vec::new(),
            timestamp_ms: 0,
            detail_hash: Vec::new(),
        };
        let bytes = outcome.to_bcs().expect("encode");
        let mut expected = Vec::new();
        expected.push(0x00); // empty source
        expected.extend_from_slice(&[0xC8, 0x01]); // ULEB128 for 200
        expected.extend(std::iter::repeat(0x07).take(200));
        expected.push(0x00); // empty challenge
        expected.extend_from_slice(&[0; 8]); // timestamp_ms = 0
        expected.push(0x00); // empty detail_hash
        assert_eq!(bytes, expected);
    }

    // --- derive coverage --------------------------------------------------

    #[test]
    fn clone_produces_equal_value() {
        let outcome = sample_outcome();
        let cloned = outcome.clone();
        assert_eq!(outcome, cloned);
    }

    #[test]
    fn partial_eq_distinguishes_each_field() {
        let base = sample_outcome();

        let mut diff_source = base.clone();
        diff_source.source = "different".to_string();
        assert_ne!(base, diff_source);

        let mut diff_attested = base.clone();
        diff_attested.attested_value.push(0x00);
        assert_ne!(base, diff_attested);

        let mut diff_challenge = base.clone();
        diff_challenge.challenge.push(0x00);
        assert_ne!(base, diff_challenge);

        let mut diff_timestamp = base.clone();
        diff_timestamp.timestamp_ms = diff_timestamp.timestamp_ms.wrapping_add(1);
        assert_ne!(base, diff_timestamp);

        let mut diff_detail = base.clone();
        diff_detail.detail_hash.push(0x00);
        assert_ne!(base, diff_detail);

        // Reflexivity: equal to itself.
        assert_eq!(base, base.clone());
    }

    #[test]
    fn debug_includes_field_names() {
        // `Debug` is derived; confirm it renders the struct and field names so
        // log/diagnostic output stays useful.
        let debug = format!("{:?}", sample_outcome());
        assert!(debug.contains("Outcome"));
        assert!(debug.contains("source"));
        assert!(debug.contains("attested_value"));
        assert!(debug.contains("challenge"));
        assert!(debug.contains("timestamp_ms"));
        assert!(debug.contains("detail_hash"));
    }
}
