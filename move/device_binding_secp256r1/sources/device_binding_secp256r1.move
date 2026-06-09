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

// Real secp256r1 vector (low-S): key signs SHA256(b"miso-binding-test").
#[test_only] const TEST_PK: vector<u8> = x"041c7650d32da9bd74ce2acad51fad14f7dd2359511cdb2dea24dd256ef70655d96c6522ceceb15d5b923d78ca4ad2d6b0b60a20fedba20cc6b725228afba5f9e7";
#[test_only] const TEST_SIG: vector<u8> = x"a0ff0691c3eb057dd78b652fdda0c635f5f1c2127629e04a939a7eafa6489429337332bddc50a5b2571bdaf132e39412ee0cab7abd6fad1a5f5a7fd3fb059258";
#[test_only] const TEST_COMPRESSED: vector<u8> = x"031c7650d32da9bd74ce2acad51fad14f7dd2359511cdb2dea24dd256ef70655d9";

#[test]
fun test_compress_matches_sec1() {
    assert!(compress(&TEST_PK) == TEST_COMPRESSED);
}

#[test]
fun test_verify_accepts_real_signature() {
    // Returns a Verified (dropped here); reaching this line without aborting == verified.
    verify(TEST_PK, b"miso-binding-test", TEST_SIG);
}

#[test, expected_failure(abort_code = EBadSignature)]
fun test_verify_rejects_wrong_message() {
    verify(TEST_PK, b"wrong-message", TEST_SIG);
}
