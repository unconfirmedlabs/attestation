/// secp256k1 verifier for `device_binding`. secp256k1 covers Arx HaLo / ECDSA tap chips, blockchain
/// hardware wallets, and Sui secp256k1 accounts.
///
/// This is the pluggable verifier pattern: `verify` runs Sui's native `ecdsa_k1` check and, on success,
/// returns a `device_binding::Verified<Secp256k1>` — a receipt only this package can mint (the witness-
/// gated constructor requires a `Secp256k1` value). `device_binding::verify_action` then accepts that
/// receipt for any `DeviceBinding<_, Secp256k1>`. Adding another curve = another sibling package; the
/// `device_binding` package never changes.
module device_binding_secp256k1::device_binding_secp256k1;

use sui::ecdsa_k1;
use device_binding::device_binding::{Self, Verified};

/// The signature did not verify under the device key.
const EBadSignature: u64 = 0;

/// `hash` selector for `ecdsa_k1` (0 = keccak256, 1 = sha256). SHA256 matches the secp256r1 sibling, so
/// the signer must hash the message with the same function it used to produce the signature.
const SHA256: u8 = 1;

/// Scheme marker for secp256k1 device keys. Only this package can construct it, so only this package can
/// mint `Verified<Secp256k1>`.
public struct Secp256k1 has drop {}

/// Verify a secp256k1 signature of `pk` over `message`, returning a receipt `device_binding::verify_action`
/// accepts. `pk` is X9.63 uncompressed (65 B), the form an attestation/chip provides; `signature` is
/// 64-byte `r ‖ s` (low-S — `ecdsa_k1` rejects high-S). Aborts if the signature is invalid.
public fun verify(pk: vector<u8>, message: vector<u8>, signature: vector<u8>): Verified<Secp256k1> {
    assert!(ecdsa_k1::secp256k1_verify(&signature, &compress(&pk), &message, SHA256), EBadSignature);
    device_binding::verified(Secp256k1 {}, pk, message)
}

/// X9.63 uncompressed (`0x04 ‖ X ‖ Y`, 65 B) → SEC1 compressed (`0x02|parity ‖ X`, 33 B), as `ecdsa_k1`
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

// Real secp256k1 vector (low-S): key signs SHA256(b"miso-binding-test"). Byte 64 of the uncompressed key
// is 0x69 (odd) → compressed prefix 0x03, so this fixture exercises the odd-parity branch of `compress`.
#[test_only] const TEST_PK: vector<u8> = x"04802ce867524d4ca1c63e78983a4838c3b37395bb8febf54253791654e4c8e2d12e8dc010ac3d83ad3b5292d89f5c0aea218f424da6652b6f7f5914f7dd36ce69";
#[test_only] const TEST_SIG: vector<u8> = x"f6f1340f587c5d004e2bd3639e477b1b058057fd3744b356a0754c5a51b0ae692493a9f6f1d6b73ae4efb78380da4623ec85b8278f29d735258916e875c32d2e";
#[test_only] const TEST_COMPRESSED: vector<u8> = x"03802ce867524d4ca1c63e78983a4838c3b37395bb8febf54253791654e4c8e2d1";

// A second real on-curve secp256k1 key (not the signer). Byte 64 is 0x3e (even) → compressed prefix 0x02,
// so this fixture drives the even-parity branch of `compress`. It is also a genuine "wrong pk" for `verify`:
// secp256k1_verify against this key returns false → `verify` aborts EBadSignature.
#[test_only] const EVEN_PK: vector<u8> = x"0443d057d259541d6ff623dde35acf20d73528710da02e5162faf7a44c2cc7d9c2b6b7b506bf843818ed4dc4d049b2699effa6a57da4b3e16b4fc0a7f4cafb103e";
#[test_only] const EVEN_COMPRESSED: vector<u8> = x"0243d057d259541d6ff623dde35acf20d73528710da02e5162faf7a44c2cc7d9c2";

// --- compress ---

#[test]
#[allow(implicit_const_copy)]
fun test_compress_matches_sec1() {
    // Odd-parity fixture: byte 64 = 0x69 → prefix 0x03.
    assert_eq!(compress(&TEST_PK), TEST_COMPRESSED);
}

#[test]
#[allow(implicit_const_copy)]
fun test_compress_even_parity_prefix() {
    // Even-parity fixture: byte 64 = 0x3e → prefix 0x02.
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
    // Correct message + signature, but verified against a different (non-signer) on-curve key → false.
    verify(EVEN_PK, b"miso-binding-test", TEST_SIG);
}
