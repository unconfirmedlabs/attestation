/// secp256r1 (NIST P-256) verifier for `device_binding`. P-256 covers Apple Secure Enclave, most Android
/// Keystore/StrongBox, and WebAuthn/passkeys.
///
/// This is the pluggable verifier pattern: `verify` runs Sui's native `ecdsa_r1` check and, on success,
/// returns a `device_binding::Verified<Secp256r1>` — a receipt only this package can mint (the witness-
/// gated constructor requires a `Secp256r1` value). `device_binding::verify_action` then accepts that
/// receipt for any `DeviceBinding<_, Secp256r1>`. Adding another curve = another sibling package; the
/// `device_binding` package never changes.
module device_binding_secp256r1::device_binding_secp256r1;

use sui::ecdsa_r1;
use device_binding::device_binding::{Self, Verified};

/// The signature did not verify under the device key.
const EBadSignature: u64 = 0;

/// `hash` selector for `ecdsa_r1` (0 = keccak256, 1 = sha256).
const SHA256: u8 = 1;

/// Scheme marker for secp256r1 device keys. Only this package can construct it, so only this package can
/// mint `Verified<Secp256r1>`.
public struct Secp256r1 has drop {}

/// Verify a P-256 signature of `pk` over `message`, returning a receipt `device_binding::verify_action`
/// accepts. `pk` is X9.63 uncompressed (65 B), the form an attestation provides; `signature` is 64-byte
/// `r ‖ s` (low-S). Aborts if the signature is invalid.
public fun verify(pk: vector<u8>, message: vector<u8>, signature: vector<u8>): Verified<Secp256r1> {
    assert!(ecdsa_r1::secp256r1_verify(&signature, &compress(&pk), &message, SHA256), EBadSignature);
    device_binding::verified(Secp256r1 {}, pk, message)
}

/// X9.63 uncompressed (`0x04 ‖ X ‖ Y`, 65 B) → SEC1 compressed (`0x02|parity ‖ X`, 33 B), as `ecdsa_r1`
/// expects a 33-byte compressed key.
fun compress(uncompressed: &vector<u8>): vector<u8> {
    let parity = *uncompressed.borrow(64) % 2;
    let prefix: u8 = 2 + parity;
    let mut out = vector[prefix];
    let mut i = 1;
    while (i <= 32) {
        out.push_back(*uncompressed.borrow(i));
        i = i + 1;
    };
    out
}

// === Tests ===

#[test_only] use std::unit_test::assert_eq;

// Real secp256r1 vector (low-S): key signs SHA256(b"miso-binding-test"). Byte 64 of the uncompressed key
// is 0xe7 (odd) → compressed prefix 0x03, so this fixture exercises the odd-parity branch of `compress`.
#[test_only] const TEST_PK: vector<u8> = x"041c7650d32da9bd74ce2acad51fad14f7dd2359511cdb2dea24dd256ef70655d96c6522ceceb15d5b923d78ca4ad2d6b0b60a20fedba20cc6b725228afba5f9e7";
#[test_only] const TEST_SIG: vector<u8> = x"a0ff0691c3eb057dd78b652fdda0c635f5f1c2127629e04a939a7eafa6489429337332bddc50a5b2571bdaf132e39412ee0cab7abd6fad1a5f5a7fd3fb059258";
#[test_only] const TEST_COMPRESSED: vector<u8> = x"031c7650d32da9bd74ce2acad51fad14f7dd2359511cdb2dea24dd256ef70655d9";

// Synthetic X9.63-shaped key whose final byte (0x40) is even → compressed prefix 0x02. Not an on-curve
// point; only used to drive the even-parity branch of `compress` (a pure byte op that never touches the
// curve) and as a "wrong pk" for `verify` (secp256r1_verify returns false → `verify` aborts EBadSignature).
#[test_only] const EVEN_PK: vector<u8> = x"040102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40";
#[test_only] const EVEN_COMPRESSED: vector<u8> = x"020102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";

// --- compress ---

#[test]
#[allow(implicit_const_copy)]
fun test_compress_matches_sec1() {
    // Odd-parity fixture: byte 64 = 0xe7 → prefix 0x03.
    assert_eq!(compress(&TEST_PK), TEST_COMPRESSED);
}

#[test]
#[allow(implicit_const_copy)]
fun test_compress_even_parity_prefix() {
    // Even-parity fixture: byte 64 = 0x40 → prefix 0x02.
    assert_eq!(compress(&EVEN_PK), EVEN_COMPRESSED);
}

#[test]
#[allow(implicit_const_copy)]
fun test_compress_emits_33_bytes_and_x_coordinate() {
    // 1 prefix byte + 32-byte X coordinate, dropping the 32-byte Y coordinate.
    let out = compress(&TEST_PK);
    assert_eq!(out.length(), 33);
    // Prefix is read from byte 64 (the last byte of Y), not from the X9.63 0x04 header.
    assert_eq!(*out.borrow(0), 0x03);
    // Bytes 1..=32 are copied verbatim from the X coordinate (bytes 1..=32 of the uncompressed key).
    let mut i = 1;
    while (i <= 32) {
        assert_eq!(*out.borrow(i), *TEST_PK.borrow(i));
        i = i + 1;
    };
}

// --- verify: happy path ---

#[test]
#[allow(implicit_const_copy)]
fun test_verify_accepts_real_signature() {
    // Returns a Verified (dropped here); reaching this line without aborting == verified.
    verify(TEST_PK, b"miso-binding-test", TEST_SIG);
}

// --- verify: rejections (each asserts → aborts EBadSignature) ---

#[test, expected_failure(abort_code = EBadSignature)]
#[allow(implicit_const_copy)]
fun test_verify_rejects_wrong_message() {
    verify(TEST_PK, b"wrong-message", TEST_SIG);
}

#[test, expected_failure(abort_code = EBadSignature)]
#[allow(implicit_const_copy)]
fun test_verify_rejects_empty_message() {
    verify(TEST_PK, b"", TEST_SIG);
}

#[test, expected_failure(abort_code = EBadSignature)]
#[allow(implicit_const_copy)]
fun test_verify_rejects_tampered_signature() {
    // Flip the high bit of the first byte of r: still 64 bytes, still low-S shaped, but no longer valid.
    let mut sig = TEST_SIG;
    let first = *sig.borrow(0);
    *sig.borrow_mut(0) = first ^ 0x80;
    verify(TEST_PK, b"miso-binding-test", sig);
}

#[test, expected_failure(abort_code = EBadSignature)]
#[allow(implicit_const_copy)]
fun test_verify_rejects_tampered_signature_last_byte() {
    // Tamper the final byte of s: still low-S shaped, but no longer the valid signature.
    let mut sig = TEST_SIG;
    let last = sig.length() - 1;
    let b = *sig.borrow(last);
    *sig.borrow_mut(last) = b ^ 0x01;
    verify(TEST_PK, b"miso-binding-test", sig);
}

#[test, expected_failure(abort_code = EBadSignature)]
#[allow(implicit_const_copy)]
fun test_verify_rejects_wrong_pk() {
    // Correct message + signature, but verified against a different (non-signer) key → returns false.
    verify(EVEN_PK, b"miso-binding-test", TEST_SIG);
}
