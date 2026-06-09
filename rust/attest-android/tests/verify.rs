//! Integration tests against publicly-published Android Key Attestation
//! chains.
//!
//! Source: `google/android-key-attestation` reference repo
//! (<https://github.com/google/android-key-attestation>), `src/test/resources/pem/`.
//!
//! These chains are publicly distributed by Google and intentionally
//! include real-world layouts (KeyMint security level enums, TEE-enforced
//! AuthorizationList entries, full chain anchoring at Google's pinned root).
//! The leaf's `attestationChallenge` value is whatever Google's test
//! harness happened to use when generating the chain — we read it out of
//! the leaf's extension and use the same value when calling our verifier,
//! since the challenge is caller-supplied and the chain is what it is.

use attest_android::{
    key_description::KeyDescription, verify_attestation, Error, Policy, SecurityLevel,
};
use std::fs;

fn pem_to_der(path: &str) -> Vec<u8> {
    let pem = fs::read_to_string(path).expect("read pem");
    pem::parse(&pem).expect("parse pem").into_contents()
}

fn ec_tee_chain() -> Vec<Vec<u8>> {
    [
        "tests/fixtures/ec_tee_cert0.pem",
        "tests/fixtures/ec_tee_cert1.pem",
        "tests/fixtures/ec_tee_cert2.pem",
        "tests/fixtures/ec_tee_cert3.pem",
    ]
    .iter()
    .map(|p| pem_to_der(p))
    .collect()
}

/// Fixed verifier clock inside the EC TEE sample chain's validity window.
///
/// The sample certs were issued in 2018 and the narrowest validity window
/// (`ec_tee_cert3`, the embedded Google root) expires 2026-05-24, so a real
/// wall-clock `now()` no longer falls inside the chain. Anchoring also
/// validates the pinned RSA root (notBefore 2022-03-20), so the usable window
/// is [2022-03-20, 2026-05-24]; `2024-01-01T00:00:00Z` sits inside it. See
/// `VALID_CLOCK_MS` in `coverage.rs` for the full validity-window analysis.
fn now_ms() -> u64 {
    1_704_067_200_000 // 2024-01-01T00:00:00Z
}

fn extract_leaf_challenge() -> Vec<u8> {
    // Parse the leaf's attestation extension manually so we can use the
    // exact challenge value the sample chain was generated with.
    use const_oid::ObjectIdentifier;
    use der::Decode;
    use x509_cert::Certificate;

    let leaf_der = pem_to_der("tests/fixtures/ec_tee_cert0.pem");
    let leaf = Certificate::from_der(&leaf_der).expect("parse leaf");
    let oid: ObjectIdentifier = "1.3.6.1.4.1.11129.2.1.17".parse().unwrap();
    let ext = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .unwrap()
        .iter()
        .find(|e| e.extn_id == oid)
        .expect("attestation extension");
    let kd = KeyDescription::from_der(ext.extn_value.as_bytes()).expect("decode KD");
    kd.attestation_challenge
}

#[test]
fn ec_tee_sample_verifies() {
    let chain = ec_tee_chain();
    let challenge = extract_leaf_challenge();

    // The sample chains were generated on test hardware whose root-of-trust
    // block reports an unlocked-development device. That's fine for verifier
    // tests — we relax those policy bits and assert the cryptographic parts.
    let policy = Policy {
        min_security_level: SecurityLevel::TrustedEnvironment,
        require_verified_boot: false,
        allowed_self_signed_keys: &[],
        require_device_locked: false,
        status_list: None,
    };

    let outcome = verify_attestation(&chain, &challenge, &policy, now_ms())
        .expect("EC TEE sample chain should verify");

    assert_eq!(outcome.source, "android-key-attest");
    assert!(!outcome.attested_value.is_empty());
    assert_eq!(outcome.challenge, challenge);
    assert_eq!(outcome.detail_hash.len(), 32);
}

#[test]
fn ec_tee_wrong_challenge_rejected() {
    let chain = ec_tee_chain();
    let policy = Policy {
        min_security_level: SecurityLevel::TrustedEnvironment,
        require_verified_boot: false,
        allowed_self_signed_keys: &[],
        require_device_locked: false,
        status_list: None,
    };
    let r = verify_attestation(&chain, b"not-the-real-challenge", &policy, now_ms());
    assert!(matches!(r, Err(Error::ChallengeMismatch)));
}

#[test]
fn key_description_decodes_full() {
    use const_oid::ObjectIdentifier;
    use der::Decode;
    use x509_cert::Certificate;

    let leaf_der = pem_to_der("tests/fixtures/ec_tee_cert0.pem");
    let leaf = Certificate::from_der(&leaf_der).expect("parse leaf");
    let oid: ObjectIdentifier = "1.3.6.1.4.1.11129.2.1.17".parse().unwrap();
    let ext = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .unwrap()
        .iter()
        .find(|e| e.extn_id == oid)
        .expect("attestation extension");

    let kd = KeyDescription::from_der(ext.extn_value.as_bytes()).expect("decode");

    // Sanity check: the sample was a TEE-attested key.
    assert_eq!(kd.attestation_security_level, SecurityLevel::TrustedEnvironment);
    assert_eq!(kd.keymint_security_level, SecurityLevel::TrustedEnvironment);
    assert!(!kd.attestation_challenge.is_empty());
}
