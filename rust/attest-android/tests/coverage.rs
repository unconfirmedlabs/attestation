//! Comprehensive surface-area coverage for the `attest-android` verifier.
//!
//! Companion to `verify.rs`. Where `verify.rs` proves the happy path on the
//! real Google `ec_tee_cert*` sample chain, this file fills every remaining
//! gap with an emphasis on NEGATIVE / adversarial cases that are
//! security-critical for anti-scalping device attestation:
//!
//!   * `validate_chain` — happy path + reordered / broken / truncated /
//!     incomplete chains, clock outside validity, empty chain.
//!   * `StatusList` — Google JSON format, lookup hit/miss, len/is_empty,
//!     malformed JSON, and (crucially) a status list crafted to contain the
//!     real fixture's serial → `verify_attestation` must REJECT.
//!   * `SecurityLevel::meets` — full ordering / threshold matrix.
//!   * `KeyDescription::from_der` — real fixture fields + malformed DER.
//!   * `verify_attestation` with `Policy` — conforming pass, plus each policy
//!     violation rejected independently (security level too low, verified
//!     boot required, device-locked required, allow-list mismatch, revoked
//!     serial, wrong challenge, untrusted root).
//!   * `attestation_application_id` — real package info + malformed input.
//!
//! All negative cases are REAL corruptions of the genuine fixtures (byte
//! flips, truncation, reordering, crafted status lists) — never fabricated
//! "valid" crypto.
//!
//! ## Fixture facts (dumped from the real chain)
//!
//! Chain is leaf-first: `cert0` (leaf, serial `01`) → `cert1`
//! (`13206311789638820911`) → `cert2` (`0388266760658996857d`) → `cert3`
//! (`e8fa196314d2fa18`, an older Google RSA root, subject
//! `serialNumber=f92009e853b6b045`, self-signed; anchors against the pinned
//! RSA root which shares its subject/public key).
//!
//! Leaf KeyDescription: attestationVersion 3, both security levels
//! `TrustedEnvironment`, challenge = `abc` (`616263`), root-of-trust
//! `verified_boot_state = Unverified` (ORANGE), `device_locked = false`,
//! `verified_boot_key` = 32 zero bytes. `attestationApplicationId` lives in
//! the SOFTWARE-enforced list and names packages `android`,
//! `com.android.keychain`, ... with one signature digest.
//!
//! Validity windows (UTC): cert0 1970→2106, cert1 2018-03-21→2028-03-18,
//! cert2 2018-03-21→2028-03-18, cert3 (embedded root) 2016-05-26→2026-05-24.
//! Anchoring ALSO validates the pinned RSA root (`google_attestation_root_0`,
//! notBefore 2022-03-20), so the usable window is [2022-03-20, 2026-05-24];
//! `VALID_CLOCK_MS` (2024-01-01) sits safely inside it.

use attest_android::{
    attestation_application_id, key_description::KeyDescription, roots::validate_chain,
    verify_attestation, Error, Policy, SecurityLevel, StatusList, VerifiedBootState,
};
use const_oid::ObjectIdentifier;
use der::Decode;
use std::fs;
use x509_cert::Certificate;

/// Fixed verifier clock inside every fixture cert's validity window AND the
/// pinned RSA root's (notBefore 2022-03-20). 2024-01-01T00:00:00Z.
const VALID_CLOCK_MS: u64 = 1_704_067_200_000; // 2024-01-01T00:00:00Z
/// Before `cert1`/`cert2` `notBefore` (2018-03-21) → those certs not yet valid.
const TOO_EARLY_CLOCK_MS: u64 = 1_483_228_800_000; // 2017-01-01T00:00:00Z
/// After `cert3` `notAfter` (2026-05-24) → embedded root expired.
const TOO_LATE_CLOCK_MS: u64 = 1_893_456_000_000; // 2030-01-01T00:00:00Z

const ATT_OID: &str = "1.3.6.1.4.1.11129.2.1.17";

fn pem_to_der(name: &str) -> Vec<u8> {
    let pem = fs::read_to_string(format!("tests/fixtures/{name}")).expect("read pem");
    pem::parse(&pem).expect("parse pem").into_contents()
}

/// Full leaf-first chain, leaf → ... → embedded root.
fn ec_tee_chain() -> Vec<Vec<u8>> {
    ["ec_tee_cert0.pem", "ec_tee_cert1.pem", "ec_tee_cert2.pem", "ec_tee_cert3.pem"]
        .iter()
        .map(|p| pem_to_der(p))
        .collect()
}

/// The leaf's attestation extension `extnValue` inner bytes (the
/// DER-encoded `KeyDescription`).
fn leaf_extension_bytes() -> Vec<u8> {
    let leaf_der = pem_to_der("ec_tee_cert0.pem");
    let leaf = Certificate::from_der(&leaf_der).expect("parse leaf");
    let oid: ObjectIdentifier = ATT_OID.parse().unwrap();
    leaf.tbs_certificate
        .extensions
        .as_ref()
        .unwrap()
        .iter()
        .find(|e| e.extn_id == oid)
        .expect("attestation extension")
        .extn_value
        .as_bytes()
        .to_vec()
}

fn leaf_key_description() -> KeyDescription {
    KeyDescription::from_der(&leaf_extension_bytes()).expect("decode KD")
}

fn leaf_challenge() -> Vec<u8> {
    leaf_key_description().attestation_challenge
}

/// Policy that accepts the real sample chain (a dev device: unlocked,
/// ORANGE boot). We deliberately relax the boot/lock bits so the chain
/// passes; individual tests tighten one knob at a time to prove rejection.
fn permissive_policy<'a>() -> Policy<'a> {
    Policy {
        min_security_level: SecurityLevel::TrustedEnvironment,
        require_verified_boot: false,
        allowed_self_signed_keys: &[],
        require_device_locked: false,
        status_list: None,
    }
}

// ===========================================================================
// validate_chain
// ===========================================================================

#[test]
fn validate_chain_happy_path_returns_leaf() {
    let chain = ec_tee_chain();
    let leaf = validate_chain(&chain, VALID_CLOCK_MS).expect("chain anchors at pinned root");
    // Leaf serial is 0x01.
    assert_eq!(leaf.tbs_certificate.serial_number.as_bytes(), &[1u8]);
    // Leaf subject is the Android Keystore Key.
    let subject = leaf.tbs_certificate.subject.to_string();
    assert!(subject.contains("Android Keystore Key"), "got subject {subject}");
}

#[test]
fn validate_chain_empty_is_rejected() {
    let r = validate_chain(&[], VALID_CLOCK_MS);
    assert!(matches!(r, Err(Error::EmptyChain)));
}

#[test]
fn validate_chain_reordered_is_rejected() {
    // Swap leaf and its issuer: now cert1 signs cert0's slot incorrectly and
    // the inner-chain signature checks fail.
    let mut chain = ec_tee_chain();
    chain.swap(0, 1);
    let r = validate_chain(&chain, VALID_CLOCK_MS);
    assert!(r.is_err(), "reordered chain must not validate");
    // Reordering breaks an inner signature check → UntrustedChain (sig fail)
    // or a Der parse-shaped error; assert it's not Ok and not a happy serial.
    match r {
        Err(Error::UntrustedChain) | Err(Error::Der(_)) => {}
        other => panic!("unexpected result for reordered chain: {other:?}"),
    }
}

#[test]
fn validate_chain_reversed_is_rejected() {
    // Fully reverse the chain (root-first). Top element becomes the leaf,
    // which does not anchor at a pinned root.
    let mut chain = ec_tee_chain();
    chain.reverse();
    let r = validate_chain(&chain, VALID_CLOCK_MS);
    assert!(r.is_err(), "reversed chain must not validate");
}

#[test]
fn validate_chain_incomplete_missing_root_is_rejected() {
    // Drop the embedded root (cert3). The new top (cert2) is signed by the
    // root, not byte-equal to any pinned root, and the pinned RSA root's key
    // DOES verify cert2... so this still anchors. To get a genuinely
    // unanchored chain, drop the two top certs so the new top (cert1) is
    // signed by cert2's key, which no pinned root holds.
    let chain = ec_tee_chain();
    let truncated: Vec<Vec<u8>> = chain[..2].to_vec(); // leaf + cert1 only
    let r = validate_chain(&truncated, VALID_CLOCK_MS);
    assert!(matches!(r, Err(Error::UntrustedChain)), "got {r:?}");
}

#[test]
fn validate_chain_leaf_only_is_rejected() {
    // A lone leaf cannot anchor at a pinned Google root.
    let chain = ec_tee_chain();
    let leaf_only = vec![chain[0].clone()];
    let r = validate_chain(&leaf_only, VALID_CLOCK_MS);
    assert!(matches!(r, Err(Error::UntrustedChain)), "got {r:?}");
}

#[test]
fn validate_chain_broken_signature_is_rejected() {
    // Corrupt a byte inside the leaf's signature region (last bytes of the
    // DER) so the inner-chain signature check under cert1 fails.
    let mut chain = ec_tee_chain();
    let leaf = &mut chain[0];
    let n = leaf.len();
    leaf[n - 1] ^= 0xFF;
    let r = validate_chain(&chain, VALID_CLOCK_MS);
    assert!(r.is_err(), "tampered leaf signature must not validate");
}

#[test]
fn validate_chain_corrupt_tbs_breaks_signature() {
    // Flip a byte near the middle of cert1 (inside its tbsCertificate). Its
    // signature, made by cert2, no longer covers the mutated bytes.
    let mut chain = ec_tee_chain();
    let cert1 = &mut chain[1];
    let mid = cert1.len() / 2;
    cert1[mid] ^= 0x01;
    let r = validate_chain(&chain, VALID_CLOCK_MS);
    assert!(r.is_err(), "tampered tbsCertificate must not validate");
}

#[test]
fn validate_chain_garbage_der_is_rejected() {
    // A cert slot that isn't valid DER at all.
    let mut chain = ec_tee_chain();
    chain[0] = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let r = validate_chain(&chain, VALID_CLOCK_MS);
    assert!(matches!(r, Err(Error::Der(_))), "got {r:?}");
}

#[test]
fn validate_chain_truncated_der_is_rejected() {
    // Chop the leaf DER in half: still "looks" like the start of a cert but
    // is incomplete.
    let mut chain = ec_tee_chain();
    let half = chain[0].len() / 2;
    chain[0].truncate(half);
    let r = validate_chain(&chain, VALID_CLOCK_MS);
    assert!(matches!(r, Err(Error::Der(_))), "got {r:?}");
}

#[test]
fn validate_chain_clock_before_validity_is_rejected() {
    // 2017 is before cert1/cert2 notBefore → "not yet valid".
    let chain = ec_tee_chain();
    let r = validate_chain(&chain, TOO_EARLY_CLOCK_MS);
    match r {
        Err(Error::Der(msg)) => assert!(msg.contains("not yet valid"), "got {msg}"),
        other => panic!("expected not-yet-valid Der error, got {other:?}"),
    }
}

#[test]
fn validate_chain_clock_after_validity_is_rejected() {
    // 2030 is after cert3 (embedded root) notAfter → "expired".
    let chain = ec_tee_chain();
    let r = validate_chain(&chain, TOO_LATE_CLOCK_MS);
    match r {
        Err(Error::Der(msg)) => assert!(msg.contains("expired"), "got {msg}"),
        other => panic!("expected expired Der error, got {other:?}"),
    }
}

// ===========================================================================
// StatusList
// ===========================================================================

#[test]
fn status_list_parses_google_format() {
    // Mirrors the real Google /attestation/status JSON shape.
    let json = r#"{
        "entries": {
            "6681152659205225093": {"status": "REVOKED", "reason": "KEY_COMPROMISE"},
            "1107446593373043": {"status": "SUSPENDED", "reason": "SOFTWARE_FLAW"}
        }
    }"#;
    let list = StatusList::from_json(json).expect("parse");
    assert_eq!(list.len(), 2);
    assert!(!list.is_empty());

    let revoked = list.lookup_serial("6681152659205225093").expect("present");
    assert_eq!(revoked.status, "REVOKED");
    assert_eq!(revoked.reason, "KEY_COMPROMISE");

    let suspended = list.lookup_serial("1107446593373043").expect("present");
    assert_eq!(suspended.status, "SUSPENDED");
    assert_eq!(suspended.reason, "SOFTWARE_FLAW");
}

#[test]
fn status_list_lookup_unknown_returns_none() {
    let json = r#"{"entries":{"abc123":{"status":"REVOKED","reason":"SUPERSEDED"}}}"#;
    let list = StatusList::from_json(json).expect("parse");
    assert!(list.lookup_serial("ffffffff").is_none());
    assert!(list.lookup_serial("ABC123").is_none(), "lookup is case-sensitive on the stored lowercase key");
    assert!(list.lookup_serial("abc123").is_some());
}

#[test]
fn status_list_serials_stored_lowercase() {
    // Uppercase hex serials in the JSON are normalised to lowercase keys.
    let json = r#"{"entries":{"DEADBEEF":{"status":"REVOKED","reason":"CA_COMPROMISE"}}}"#;
    let list = StatusList::from_json(json).expect("parse");
    assert!(list.lookup_serial("deadbeef").is_some());
    assert!(list.lookup_serial("DEADBEEF").is_none());
}

#[test]
fn status_list_empty_is_empty() {
    let list = StatusList::from_json(r#"{"entries":{}}"#).expect("parse");
    assert!(list.is_empty());
    assert_eq!(list.len(), 0);
    assert!(list.lookup_serial("01").is_none());
}

#[test]
fn status_list_tolerates_bom_and_whitespace() {
    let json = "\u{feff}  {\n  \"entries\" : {\n  \"01\" : { \"status\" : \"REVOKED\" , \"reason\" : \"KEY_COMPROMISE\" } }\n}";
    let list = StatusList::from_json(json).expect("parse with BOM + whitespace");
    assert_eq!(list.len(), 1);
    assert!(list.lookup_serial("01").is_some());
}

#[test]
fn status_list_malformed_not_object_is_err() {
    let r = StatusList::from_json("[]");
    assert!(matches!(r, Err(Error::Der(_))), "got {r:?}");
}

#[test]
fn status_list_malformed_wrong_top_key_is_err() {
    let r = StatusList::from_json(r#"{"records":{}}"#);
    match r {
        Err(Error::Der(msg)) => assert!(msg.contains("entries"), "got {msg}"),
        other => panic!("expected Der error about 'entries', got {other:?}"),
    }
}

#[test]
fn status_list_malformed_unterminated_string_is_err() {
    let r = StatusList::from_json(r#"{"entries":{"01":{"status":"REVOKED}}"#);
    assert!(matches!(r, Err(Error::Der(_))), "got {r:?}");
}

#[test]
fn status_list_malformed_truncated_is_err() {
    let r = StatusList::from_json(r#"{"entries":{"01":{"status":"REVOKED","reason":"X"}"#);
    assert!(matches!(r, Err(Error::Der(_))), "got {r:?}");
}

#[test]
fn status_list_empty_string_is_err() {
    assert!(matches!(StatusList::from_json(""), Err(Error::Der(_))));
}

// ===========================================================================
// Revocation enforcement via verify_attestation
// ===========================================================================

#[test]
fn verify_rejects_when_leaf_serial_is_revoked() {
    // The leaf cert's serial is the single byte 0x01. `check_status` strips
    // leading ZERO BYTES (not nibbles), so this hex-encodes to "01". Craft a
    // status list revoking exactly that serial and prove the verifier aborts.
    let json = r#"{"entries":{"01":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"#;
    let list = StatusList::from_json(json).expect("parse");
    let policy = Policy { status_list: Some(&list), ..permissive_policy() };

    let chain = ec_tee_chain();
    let r = verify_attestation(&chain, &leaf_challenge(), &policy, VALID_CLOCK_MS);
    match r {
        Err(Error::Revoked { serial, status, reason }) => {
            assert_eq!(serial, "01");
            assert_eq!(status, "REVOKED");
            assert_eq!(reason, "KEY_COMPROMISE");
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
}

#[test]
fn verify_rejects_when_intermediate_serial_is_revoked() {
    // cert2's serial bytes start with 0x03 (no leading zero byte to strip),
    // hex-encoding to "0388266760658996857d". Revoking ANY cert in the chain
    // — not just the leaf — must abort verification.
    let json = r#"{"entries":{"0388266760658996857d":{"status":"SUSPENDED","reason":"CA_COMPROMISE"}}}"#;
    let list = StatusList::from_json(json).expect("parse");
    let policy = Policy { status_list: Some(&list), ..permissive_policy() };

    let chain = ec_tee_chain();
    let r = verify_attestation(&chain, &leaf_challenge(), &policy, VALID_CLOCK_MS);
    match r {
        Err(Error::Revoked { serial, status, .. }) => {
            assert_eq!(serial, "0388266760658996857d");
            assert_eq!(status, "SUSPENDED");
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
}

#[test]
fn verify_passes_when_status_list_has_unrelated_serials() {
    // Status list present but contains only serials not in our chain.
    let json = r#"{"entries":{"deadbeef":{"status":"REVOKED","reason":"KEY_COMPROMISE"}}}"#;
    let list = StatusList::from_json(json).expect("parse");
    let policy = Policy { status_list: Some(&list), ..permissive_policy() };

    let chain = ec_tee_chain();
    let outcome = verify_attestation(&chain, &leaf_challenge(), &policy, VALID_CLOCK_MS)
        .expect("unrelated status list must not block a valid chain");
    assert_eq!(outcome.source, "android-key-attest");
}

// ===========================================================================
// SecurityLevel::meets — full matrix
// ===========================================================================

#[test]
fn security_level_meets_matrix() {
    use SecurityLevel::*;
    // Reflexive: each level meets itself.
    assert!(Software.meets(Software));
    assert!(TrustedEnvironment.meets(TrustedEnvironment));
    assert!(StrongBox.meets(StrongBox));

    // Stronger meets weaker requirement.
    assert!(TrustedEnvironment.meets(Software));
    assert!(StrongBox.meets(Software));
    assert!(StrongBox.meets(TrustedEnvironment));

    // Weaker does NOT meet stronger requirement.
    assert!(!Software.meets(TrustedEnvironment));
    assert!(!Software.meets(StrongBox));
    assert!(!TrustedEnvironment.meets(StrongBox));
}

// ===========================================================================
// KeyDescription::from_der
// ===========================================================================

#[test]
fn key_description_extracts_expected_fields() {
    let kd = leaf_key_description();
    assert_eq!(kd.attestation_version, 3);
    assert_eq!(kd.attestation_security_level, SecurityLevel::TrustedEnvironment);
    assert_eq!(kd.keymint_version, 4);
    assert_eq!(kd.keymint_security_level, SecurityLevel::TrustedEnvironment);
    assert_eq!(kd.attestation_challenge, b"abc");
    assert!(kd.unique_id.is_empty());

    // Hardware-enforced root of trust: ORANGE / unlocked dev device.
    let rot = kd.hardware_enforced.root_of_trust.as_ref().expect("rot present");
    assert_eq!(rot.verified_boot_state, VerifiedBootState::Unverified);
    assert!(!rot.device_locked);
    assert_eq!(rot.verified_boot_key, vec![0u8; 32]);
    assert!(rot.verified_boot_hash.is_some());

    // Hardware-enforced OS patch level is a real YYYYMM value.
    assert_eq!(kd.hardware_enforced.os_patch_level, Some(201907));

    // attestationApplicationId is in the SOFTWARE-enforced list for this fixture.
    assert!(kd.software_enforced.attestation_application_id.is_some());
    assert!(kd.hardware_enforced.attestation_application_id.is_none());
}

#[test]
fn key_description_empty_input_is_err() {
    let r = KeyDescription::from_der(&[]);
    assert!(matches!(r, Err(Error::Der(_))), "got {r:?}");
}

#[test]
fn key_description_not_a_sequence_is_err() {
    // 0x02 = INTEGER tag, not SEQUENCE.
    let r = KeyDescription::from_der(&[0x02, 0x01, 0x00]);
    match r {
        Err(Error::Der(msg)) => assert!(msg.contains("SEQUENCE"), "got {msg}"),
        other => panic!("expected SEQUENCE Der error, got {other:?}"),
    }
}

#[test]
fn key_description_truncated_body_is_err() {
    // Take the real extension bytes and chop them mid-body. The outer
    // SEQUENCE header now claims more bytes than remain.
    let mut bytes = leaf_extension_bytes();
    bytes.truncate(bytes.len() / 2);
    let r = KeyDescription::from_der(&bytes);
    assert!(matches!(r, Err(Error::Der(_))), "got {r:?}");
}

#[test]
fn key_description_flipped_security_level_byte_is_err_or_changed() {
    // Mutate enough that decode either errors or yields a different value;
    // here we corrupt the very first content byte (attestationVersion) which
    // shifts the whole structure and must not silently match the original.
    let original = leaf_key_description();
    let mut bytes = leaf_extension_bytes();
    // Flip a byte well inside the body (skip the SEQUENCE header) to perturb
    // an integer field; structure usually still parses but to a different
    // value, never the pristine one.
    let idx = 6.min(bytes.len() - 1);
    bytes[idx] ^= 0xFF;
    match KeyDescription::from_der(&bytes) {
        Ok(kd) => assert_ne!(kd, original, "corruption must not reproduce the original KD"),
        Err(Error::Der(_)) => {}
        other => panic!("unexpected: {other:?}"),
    }
}

// ===========================================================================
// attestation_application_id
// ===========================================================================

#[test]
fn attestation_application_id_parses_real_packages() {
    let kd = leaf_key_description();
    let aaid_bytes = kd
        .software_enforced
        .attestation_application_id
        .expect("aaid present");
    let aaid = attestation_application_id(&aaid_bytes).expect("parse aaid");

    assert!(!aaid.package_infos.is_empty());
    // First package in the real fixture is "android" version 29.
    let first = &aaid.package_infos[0];
    assert_eq!(first.package_name, b"android");
    assert_eq!(first.version, 29);

    let names: Vec<String> = aaid
        .package_infos
        .iter()
        .map(|p| String::from_utf8_lossy(&p.package_name).into_owned())
        .collect();
    assert!(names.iter().any(|n| n == "com.android.keychain"));

    // Exactly one signature digest, 32 bytes (SHA-256 of the signing cert).
    assert_eq!(aaid.signature_digests.len(), 1);
    assert_eq!(aaid.signature_digests[0].len(), 32);
}

#[test]
fn attestation_application_id_empty_is_err() {
    assert!(matches!(attestation_application_id(&[]), Err(Error::Der(_))));
}

#[test]
fn attestation_application_id_not_sequence_is_err() {
    // 0x04 = OCTET STRING tag, but the parser expects a SEQUENCE.
    let r = attestation_application_id(&[0x04, 0x01, 0x00]);
    match r {
        Err(Error::Der(msg)) => assert!(msg.contains("SEQUENCE"), "got {msg}"),
        other => panic!("expected SEQUENCE Der error, got {other:?}"),
    }
}

#[test]
fn attestation_application_id_truncated_is_err() {
    let kd = leaf_key_description();
    let mut bytes = kd.software_enforced.attestation_application_id.unwrap();
    bytes.truncate(bytes.len() / 2);
    assert!(matches!(attestation_application_id(&bytes), Err(Error::Der(_))));
}

// ===========================================================================
// verify_attestation — full policy matrix
// ===========================================================================

#[test]
fn verify_conforming_attestation_succeeds() {
    let chain = ec_tee_chain();
    let challenge = leaf_challenge();
    let outcome = verify_attestation(&chain, &challenge, &permissive_policy(), VALID_CLOCK_MS)
        .expect("conforming attestation should verify");

    assert_eq!(outcome.source, "android-key-attest");
    assert!(!outcome.attested_value.is_empty());
    assert_eq!(outcome.challenge, challenge);
    assert_eq!(outcome.timestamp_ms, VALID_CLOCK_MS);
    assert_eq!(outcome.detail_hash.len(), 32);

    // attested_value is the leaf SPKI in DER → re-parses as an SPKI.
    use der::Encode;
    let leaf = Certificate::from_der(&chain[0]).unwrap();
    let expected_spki = leaf.tbs_certificate.subject_public_key_info.to_der().unwrap();
    assert_eq!(outcome.attested_value, expected_spki);
}

#[test]
fn verify_rejects_wrong_challenge() {
    let chain = ec_tee_chain();
    let r = verify_attestation(&chain, b"not-the-challenge", &permissive_policy(), VALID_CLOCK_MS);
    assert!(matches!(r, Err(Error::ChallengeMismatch)), "got {r:?}");
}

#[test]
fn verify_rejects_security_level_too_high_requirement() {
    // The fixture is TrustedEnvironment; require StrongBox → insufficient.
    let chain = ec_tee_chain();
    let policy = Policy {
        min_security_level: SecurityLevel::StrongBox,
        ..permissive_policy()
    };
    let r = verify_attestation(&chain, &leaf_challenge(), &policy, VALID_CLOCK_MS);
    match r {
        Err(Error::InsufficientSecurityLevel { got, required }) => {
            assert_eq!(got, SecurityLevel::TrustedEnvironment);
            assert_eq!(required, SecurityLevel::StrongBox);
        }
        other => panic!("expected InsufficientSecurityLevel, got {other:?}"),
    }
}

#[test]
fn verify_accepts_lower_security_requirement() {
    // Requiring only Software is met by a TrustedEnvironment attestation.
    let chain = ec_tee_chain();
    let policy = Policy {
        min_security_level: SecurityLevel::Software,
        ..permissive_policy()
    };
    let outcome = verify_attestation(&chain, &leaf_challenge(), &policy, VALID_CLOCK_MS)
        .expect("TEE attestation meets a Software floor");
    assert_eq!(outcome.source, "android-key-attest");
}

#[test]
fn verify_rejects_require_verified_boot_on_unverified_device() {
    // Fixture boots ORANGE (Unverified); requiring verified boot must reject.
    let chain = ec_tee_chain();
    let policy = Policy {
        require_verified_boot: true,
        require_device_locked: false,
        ..permissive_policy()
    };
    let r = verify_attestation(&chain, &leaf_challenge(), &policy, VALID_CLOCK_MS);
    match r {
        Err(Error::UnacceptableBootState(state)) => {
            assert_eq!(state, VerifiedBootState::Unverified);
        }
        other => panic!("expected UnacceptableBootState(Unverified), got {other:?}"),
    }
}

#[test]
fn verify_rejects_unlocked_device_when_lock_required() {
    // Fixture reports device_locked = false; requiring a locked device rejects.
    let chain = ec_tee_chain();
    let policy = Policy {
        require_device_locked: true,
        require_verified_boot: false,
        ..permissive_policy()
    };
    let r = verify_attestation(&chain, &leaf_challenge(), &policy, VALID_CLOCK_MS);
    assert!(matches!(r, Err(Error::DeviceUnlocked)), "got {r:?}");
}

#[test]
fn verify_rejects_unverified_device_when_allow_list_non_empty() {
    // require_verified_boot = false but a NON-EMPTY allow-list means only
    // GREEN or a matching-key YELLOW is accepted. The fixture is ORANGE
    // (Unverified), so it must be rejected — proving the allow-list path
    // does not silently fall through to "accept anything".
    let chain = ec_tee_chain();
    let allowed: Vec<Vec<u8>> = vec![vec![0u8; 32]]; // matches verified_boot_key, but state is wrong
    let policy = Policy {
        require_verified_boot: false,
        allowed_self_signed_keys: &allowed,
        require_device_locked: false,
        ..permissive_policy()
    };
    let r = verify_attestation(&chain, &leaf_challenge(), &policy, VALID_CLOCK_MS);
    match r {
        Err(Error::UnacceptableBootState(state)) => {
            assert_eq!(state, VerifiedBootState::Unverified);
        }
        other => panic!("expected UnacceptableBootState(Unverified), got {other:?}"),
    }
}

#[test]
fn verify_rejects_expired_chain() {
    // Same chain, clock past the embedded root's expiry → chain validation
    // fails before any policy checks.
    let chain = ec_tee_chain();
    let r = verify_attestation(&chain, &leaf_challenge(), &permissive_policy(), TOO_LATE_CLOCK_MS);
    match r {
        Err(Error::Der(msg)) => assert!(msg.contains("expired"), "got {msg}"),
        other => panic!("expected expired Der error, got {other:?}"),
    }
}

#[test]
fn verify_rejects_empty_chain() {
    let r = verify_attestation(&[], &leaf_challenge(), &permissive_policy(), VALID_CLOCK_MS);
    assert!(matches!(r, Err(Error::EmptyChain)), "got {r:?}");
}

#[test]
fn verify_rejects_untrusted_root() {
    // Leaf-only chain: cannot anchor at a pinned Google root.
    let chain = ec_tee_chain();
    let leaf_only = vec![chain[0].clone()];
    let r = verify_attestation(&leaf_only, &leaf_challenge(), &permissive_policy(), VALID_CLOCK_MS);
    assert!(matches!(r, Err(Error::UntrustedChain)), "got {r:?}");
}

#[test]
fn verify_default_policy_rejects_dev_device() {
    // The shipped Default policy is strict (TEE + verified boot + locked).
    // Our dev-device fixture (ORANGE, unlocked) must NOT pass it — this is
    // the production-safe default behaving correctly.
    let chain = ec_tee_chain();
    let r = verify_attestation(&chain, &leaf_challenge(), &Policy::default(), VALID_CLOCK_MS);
    // It fails on the first strict check it hits (device lock), proving the
    // default is not permissive.
    assert!(r.is_err(), "strict default must reject an unlocked dev device");
    assert!(
        matches!(r, Err(Error::DeviceUnlocked) | Err(Error::UnacceptableBootState(_))),
        "got {r:?}"
    );
}

#[test]
fn verify_missing_attestation_extension_is_rejected() {
    // Build a chain whose leaf is a valid Google cert WITHOUT the attestation
    // extension: reuse the embedded root (cert3) as a stand-in "leaf". The
    // chain still anchors (it's a pinned-equivalent root) so we get past
    // validate_chain, then fail extracting the extension.
    //
    // Chain = [cert3] (a self-signed pinned-equivalent root, no att ext).
    let chain = vec![pem_to_der("ec_tee_cert3.pem")];
    let r = verify_attestation(&chain, b"abc", &permissive_policy(), VALID_CLOCK_MS);
    assert!(
        matches!(r, Err(Error::MissingAttestationExtension)),
        "got {r:?}"
    );
}
