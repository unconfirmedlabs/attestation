//! End-to-end and adversarial tests against the **real** Apple App Attest
//! fixture in `tests/fixtures/dev_iphone_001.json`.
//!
//! The fixture was captured from a real device's `DCAppAttestService`. Apple's
//! App Attest **leaf certificate is short-lived** (~3 days), so unlike the
//! `#[ignore]`d test in `verify.rs` (which uses wall-clock `now()` and only
//! passes while the cert is live), every test here pins `clock_ms` to a value
//! inside the leaf's validity window so the suite stays green forever.
//!
//! Negative cases are derived by corrupting this real blob — flipping a byte,
//! truncating, reordering certs, shifting the clock — never by fabricating
//! certificates or signatures that purport to be Apple-issued.

use attest_apple::{
    authdata, cbor, cose, oids, roots, verify_app_attest, sources, Error,
};

// ---------------------------------------------------------------------------
// Fixture loading + clock anchors.
// ---------------------------------------------------------------------------

/// 2026-05-19T15:13:20Z — inside the leaf cert validity window
/// (notBefore 2026-05-18T03:03:39Z .. notAfter 2026-05-21T03:03:39Z) and inside
/// every other cert in the chain (intermediate + pinned root).
const CLOCK_VALID_MS: u64 = 1_779_200_000_000;

/// 2026-05-17T00:00:00Z — before the leaf's notBefore.
const CLOCK_TOO_EARLY_MS: u64 = 1_778_976_000_000;

/// 2026-05-22T00:00:00Z — after the leaf's notAfter.
const CLOCK_TOO_LATE_MS: u64 = 1_779_408_000_000;

struct Fixture {
    attestation_object: Vec<u8>,
    key_id: Vec<u8>,
    challenge: Vec<u8>,
    app_id: String,
    production: bool,
}

fn load() -> Fixture {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/dev_iphone_001.json"
    );
    let raw = std::fs::read_to_string(path).expect("fixture present");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("fixture is JSON");
    Fixture {
        attestation_object: hex::decode(v["attestation_object_hex"].as_str().unwrap()).unwrap(),
        key_id: hex::decode(v["key_id_hex"].as_str().unwrap()).unwrap(),
        challenge: hex::decode(v["challenge_hex"].as_str().unwrap()).unwrap(),
        app_id: v["app_id"].as_str().unwrap().to_string(),
        production: v["production"].as_bool().unwrap(),
    }
}

/// The x5c chain extracted from the real fixture.
fn fixture_x5c() -> Vec<Vec<u8>> {
    let f = load();
    cbor::decode_attestation_object(&f.attestation_object)
        .unwrap()
        .x5c
}

// ===========================================================================
// verify_app_attest — full pipeline
// ===========================================================================

#[test]
fn verify_app_attest_happy_path() {
    let f = load();
    let outcome = verify_app_attest(
        &f.attestation_object,
        &f.key_id,
        &f.challenge,
        &f.app_id,
        f.production,
        CLOCK_VALID_MS,
    )
    .expect("real fixture must verify inside the cert validity window");

    assert_eq!(outcome.source, sources::APPLE_APP_ATTEST);
    assert_eq!(outcome.attested_value.len(), 65);
    assert_eq!(outcome.attested_value[0], 0x04); // SEC1 uncompressed
    assert_eq!(outcome.challenge, f.challenge);
    assert_eq!(outcome.timestamp_ms, CLOCK_VALID_MS);
    // detail_hash commits to the raw attestation blob.
    use sha2::{Digest, Sha256};
    assert_eq!(
        outcome.detail_hash,
        Sha256::digest(&f.attestation_object).to_vec()
    );
}

#[test]
fn verify_app_attest_wrong_challenge_fails_nonce() {
    let f = load();
    // Flip one bit of the challenge → expected nonce changes → NonceMismatch.
    let mut bad = f.challenge.clone();
    bad[0] ^= 0x01;
    let err = verify_app_attest(
        &f.attestation_object,
        &f.key_id,
        &bad,
        &f.app_id,
        f.production,
        CLOCK_VALID_MS,
    )
    .unwrap_err();
    assert!(matches!(err, Error::NonceMismatch), "got {err:?}");
}

#[test]
fn verify_app_attest_zero_challenge_fails_nonce() {
    let f = load();
    let zero = vec![0u8; 32];
    let err = verify_app_attest(
        &f.attestation_object,
        &f.key_id,
        &zero,
        &f.app_id,
        f.production,
        CLOCK_VALID_MS,
    )
    .unwrap_err();
    assert!(matches!(err, Error::NonceMismatch), "got {err:?}");
}

#[test]
fn verify_app_attest_empty_challenge_fails_nonce() {
    let f = load();
    let err = verify_app_attest(
        &f.attestation_object,
        &f.key_id,
        &[],
        &f.app_id,
        f.production,
        CLOCK_VALID_MS,
    )
    .unwrap_err();
    assert!(matches!(err, Error::NonceMismatch), "got {err:?}");
}

#[test]
fn verify_app_attest_wrong_key_id_fails() {
    let f = load();
    let mut bad_kid = f.key_id.clone();
    bad_kid[0] ^= 0xFF;
    let err = verify_app_attest(
        &f.attestation_object,
        &bad_kid,
        &f.challenge,
        &f.app_id,
        f.production,
        CLOCK_VALID_MS,
    )
    .unwrap_err();
    assert!(matches!(err, Error::KeyIdMismatch), "got {err:?}");
}

#[test]
fn verify_app_attest_wrong_app_id_fails_rp_hash() {
    let f = load();
    let err = verify_app_attest(
        &f.attestation_object,
        &f.key_id,
        &f.challenge,
        "WRONG.bundle.id",
        f.production,
        CLOCK_VALID_MS,
    )
    .unwrap_err();
    assert!(matches!(err, Error::RpIdHashMismatch), "got {err:?}");
}

#[test]
fn verify_app_attest_wrong_aaguid_production_flag_fails() {
    let f = load();
    // Fixture is a *development* attestation (aaguid = "appattestdevelop").
    // Asserting production=true must trip the aaguid check.
    assert!(!f.production, "fixture is expected to be a dev attestation");
    let err = verify_app_attest(
        &f.attestation_object,
        &f.key_id,
        &f.challenge,
        &f.app_id,
        true, // wrong: claim production
        CLOCK_VALID_MS,
    )
    .unwrap_err();
    match err {
        Error::AaguidMismatch { expected, got } => {
            assert_eq!(expected, "appattest");
            assert_eq!(&got, b"appattestdevelop");
        }
        other => panic!("expected AaguidMismatch, got {other:?}"),
    }
}

#[test]
fn verify_app_attest_expired_clock_fails() {
    let f = load();
    let err = verify_app_attest(
        &f.attestation_object,
        &f.key_id,
        &f.challenge,
        &f.app_id,
        f.production,
        CLOCK_TOO_LATE_MS,
    )
    .unwrap_err();
    // Cert validity is enforced inside validate_x5c_chain → Der(...).
    assert!(matches!(err, Error::Der(_)), "got {err:?}");
}

#[test]
fn verify_app_attest_not_yet_valid_clock_fails() {
    let f = load();
    let err = verify_app_attest(
        &f.attestation_object,
        &f.key_id,
        &f.challenge,
        &f.app_id,
        f.production,
        CLOCK_TOO_EARLY_MS,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Der(_)), "got {err:?}");
}

#[test]
fn verify_app_attest_tampered_attestation_object_fails() {
    let f = load();
    // The leaf certificate begins at offset 38 (CBOR-tagged DER SEQUENCE
    // 30 82 04 20 ...) and spans ~1056 bytes. Flipping a byte inside the leaf's
    // tbsCertificate keeps the blob structurally CBOR-decodable but invalidates
    // the intermediate's signature over the leaf → chain verification fails.
    let mut blob = f.attestation_object.clone();
    // Sanity-check we're hitting the leaf cert region.
    assert_eq!(&blob[38..42], &[0x30, 0x82, 0x04, 0x20]);
    blob[98] ^= 0xFF; // inside leaf tbsCertificate
    let err = verify_app_attest(
        &blob,
        &f.key_id,
        &f.challenge,
        &f.app_id,
        f.production,
        CLOCK_VALID_MS,
    )
    .unwrap_err();
    // Corruption surfaces as a parse failure or a broken chain signature.
    assert!(
        matches!(err, Error::Der(_) | Error::UntrustedChain | Error::Cbor(_)),
        "got {err:?}"
    );
}

#[test]
fn verify_app_attest_truncated_object_fails_not_panics() {
    let f = load();
    let truncated = &f.attestation_object[..f.attestation_object.len() / 2];
    let err = verify_app_attest(
        truncated,
        &f.key_id,
        &f.challenge,
        &f.app_id,
        f.production,
        CLOCK_VALID_MS,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Cbor(_)), "got {err:?}");
}

// ===========================================================================
// validate_x5c_chain — chain & clock adversarial cases
// ===========================================================================

#[test]
fn x5c_valid_chain_at_valid_clock() {
    let leaf = roots::validate_x5c_chain(&fixture_x5c(), CLOCK_VALID_MS)
        .expect("real chain must validate inside its window");
    // The returned cert is the leaf (first in the chain). It carries the Apple
    // nonce extension; the intermediate does not.
    assert!(oids::extract_nonce_extension(&leaf).is_ok());
}

#[test]
fn x5c_empty_chain_rejected() {
    let err = roots::validate_x5c_chain(&[], CLOCK_VALID_MS).unwrap_err();
    assert!(matches!(err, Error::EmptyX5c), "got {err:?}");
}

#[test]
fn x5c_reordered_chain_rejected() {
    // Real chain is [leaf, intermediate]. Swapping to [intermediate, leaf]
    // breaks the "each cert signed by the next" relationship and the leaf is
    // not a CA where a CA is now required.
    let mut chain = fixture_x5c();
    assert_eq!(chain.len(), 2, "fixture chain is [leaf, intermediate]");
    chain.reverse();
    let err = roots::validate_x5c_chain(&chain, CLOCK_VALID_MS).unwrap_err();
    assert!(
        matches!(err, Error::Der(_) | Error::UntrustedChain),
        "got {err:?}"
    );
}

#[test]
fn x5c_incomplete_chain_missing_intermediate_rejected() {
    // Drop the intermediate, leaving only the leaf. The leaf is not signed by
    // the pinned root, so the root-anchor check must fail.
    let chain = fixture_x5c();
    let leaf_only = vec![chain[0].clone()];
    let err = roots::validate_x5c_chain(&leaf_only, CLOCK_VALID_MS).unwrap_err();
    assert!(
        matches!(err, Error::Der(_) | Error::UntrustedChain),
        "got {err:?}"
    );
}

#[test]
fn x5c_tampered_leaf_signature_rejected() {
    // Flip a byte near the end of the leaf DER (inside its signature region) so
    // the intermediate's signature over the leaf no longer verifies.
    let mut chain = fixture_x5c();
    let leaf = &mut chain[0];
    let n = leaf.len();
    leaf[n - 5] ^= 0xFF;
    let err = roots::validate_x5c_chain(&chain, CLOCK_VALID_MS).unwrap_err();
    assert!(
        matches!(err, Error::Der(_) | Error::UntrustedChain),
        "got {err:?}"
    );
}

#[test]
fn x5c_garbage_cert_bytes_rejected() {
    let chain = vec![vec![0xDE, 0xAD, 0xBE, 0xEF], vec![0x00]];
    let err = roots::validate_x5c_chain(&chain, CLOCK_VALID_MS).unwrap_err();
    assert!(matches!(err, Error::Der(_)), "got {err:?}");
}

#[test]
fn x5c_expired_clock_rejected() {
    let err = roots::validate_x5c_chain(&fixture_x5c(), CLOCK_TOO_LATE_MS).unwrap_err();
    assert!(matches!(err, Error::Der(_)), "got {err:?}");
}

#[test]
fn x5c_not_yet_valid_clock_rejected() {
    let err = roots::validate_x5c_chain(&fixture_x5c(), CLOCK_TOO_EARLY_MS).unwrap_err();
    assert!(matches!(err, Error::Der(_)), "got {err:?}");
}

// ===========================================================================
// extract_nonce_extension — on the real leaf
// ===========================================================================

#[test]
fn nonce_extension_present_on_real_leaf() {
    let leaf = roots::validate_x5c_chain(&fixture_x5c(), CLOCK_VALID_MS).unwrap();
    let nonce = oids::extract_nonce_extension(&leaf).expect("leaf carries Apple nonce extension");
    assert_eq!(nonce.len(), 32);
}

#[test]
fn nonce_extension_absent_on_intermediate() {
    // The intermediate ("Apple App Attestation CA 1") does NOT carry the Apple
    // App Attest nonce extension.
    use der::Decode;
    use x509_cert::Certificate;
    let chain = fixture_x5c();
    let intermediate = Certificate::from_der(&chain[1]).unwrap();
    let err = oids::extract_nonce_extension(&intermediate).unwrap_err();
    assert!(matches!(err, Error::MissingNonceExtension), "got {err:?}");
}

#[test]
fn nonce_extension_matches_expected_from_blob() {
    // Independently recompute the expected nonce = SHA256(authData || SHA256(challenge))
    // and confirm it equals the leaf's certificate extension. This is the exact
    // binding verify_app_attest enforces.
    use sha2::{Digest, Sha256};
    let f = load();
    let stmt = cbor::decode_attestation_object(&f.attestation_object).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&stmt.auth_data);
    hasher.update(Sha256::digest(&f.challenge));
    let expected: [u8; 32] = hasher.finalize().into();

    let leaf = roots::validate_x5c_chain(&stmt.x5c, CLOCK_VALID_MS).unwrap();
    let cert_nonce = oids::extract_nonce_extension(&leaf).unwrap();
    assert_eq!(cert_nonce, expected);
}

// ===========================================================================
// parse / decode_attestation_object / extract_p256_pk — on real data
// ===========================================================================

#[test]
fn decode_attestation_object_on_real_blob() {
    let f = load();
    let stmt = cbor::decode_attestation_object(&f.attestation_object).unwrap();
    assert_eq!(stmt.fmt, "apple-appattest");
    assert_eq!(stmt.x5c.len(), 2);
    assert!(!stmt.auth_data.is_empty());
    assert!(!stmt.receipt.is_empty(), "real blob carries a receipt");
}

#[test]
fn parse_real_auth_data() {
    let f = load();
    let stmt = cbor::decode_attestation_object(&f.attestation_object).unwrap();
    let auth = authdata::parse(&stmt.auth_data).unwrap();
    assert_eq!(auth.rp_id_hash.len(), 32);
    assert_eq!(&auth.aaguid, b"appattestdevelop");
    assert_eq!(auth.sign_count, 0, "initial attestation has signCount 0");
    assert!(!auth.credential_public_key.is_empty());
}

#[test]
fn extract_p256_pk_from_real_auth_data_and_keyid_roundtrip() {
    use sha2::{Digest, Sha256};
    let f = load();
    let stmt = cbor::decode_attestation_object(&f.attestation_object).unwrap();
    let auth = authdata::parse(&stmt.auth_data).unwrap();
    let pk = cose::extract_p256_pk(&auth.credential_public_key).unwrap();
    assert_eq!(pk[0], 0x04);

    // keyId == SHA256(X9.63 uncompressed pubkey). Must equal the fixture keyId.
    let computed: [u8; 32] = Sha256::digest(cose::key_id_input(&pk)).into();
    assert_eq!(computed.as_slice(), f.key_id.as_slice());
}

#[test]
fn parse_truncated_real_auth_data_errors_not_panics() {
    let f = load();
    let stmt = cbor::decode_attestation_object(&f.attestation_object).unwrap();
    let truncated = &stmt.auth_data[..40]; // past the 37-byte header, mid-aaguid
    assert!(authdata::parse(truncated).is_err());
}
