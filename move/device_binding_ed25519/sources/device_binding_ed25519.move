/// Ed25519 verifier for `device_binding`. Ed25519 covers Tangem cards, FIDO2/WebAuthn EdDSA
/// authenticators, SSH/PGP Ed25519 keys, and Sui's own native account signature scheme.
///
/// This is the pluggable verifier pattern: `verify` runs Sui's native `ed25519` check and, on success,
/// returns a `device_binding::Verified<Ed25519>` — a receipt only this package can mint (the witness-
/// gated constructor requires an `Ed25519` value). `device_binding::verify_action` then accepts that
/// receipt for any `DeviceBinding<_, Ed25519>`. Adding another scheme = another sibling package; the
/// `device_binding` package never changes.
///
/// Differences vs the ECDSA siblings (`device_binding_secp256r1`, …):
/// - **No `compress` helper.** Ed25519 public keys are already 32-byte compressed Edwards points; `pk`
///   is passed to the native verifier verbatim.
/// - **No hash selector.** Ed25519 hashes the message internally with SHA-512, so verification is over
///   the **raw** message, never a pre-hash.
/// - **No low-S normalization.** EdDSA is deterministic and not malleable the way ECDSA is, so there is
///   no low-S concern.
module device_binding_ed25519::device_binding_ed25519;

use sui::ed25519;
use device_binding::device_binding::{Self, Verified};

/// The signature did not verify under the device key.
const EBadSignature: u64 = 0;

/// Scheme marker for Ed25519 device keys. Only this package can construct it, so only this package can
/// mint `Verified<Ed25519>`.
public struct Ed25519 has drop {}

/// Verify an Ed25519 signature of `pk` over `message`, returning a receipt `device_binding::verify_action`
/// accepts. `pk` is the 32-byte compressed Edwards public key (the form an attestation provides and the
/// form stored in the binding); `signature` is the 64-byte `R ‖ S`. Verification is over the **raw**
/// `message` (Ed25519 hashes internally with SHA-512) — no pre-hash, no hash selector, no low-S step, and
/// no point compression. Aborts if the signature is invalid.
public fun verify(pk: vector<u8>, message: vector<u8>, signature: vector<u8>): Verified<Ed25519> {
    assert!(ed25519::ed25519_verify(&signature, &pk, &message), EBadSignature);
    device_binding::verified(Ed25519 {}, pk, message)
}

// === Tests ===

// Real Ed25519 vector: key signs the RAW bytes of b"miso-binding-test" (no pre-hash). pk is the 32-byte
// compressed Edwards point; sig is 64-byte R‖S. The native verifier is the oracle — these bytes pass it.
#[test_only] const TEST_PK: vector<u8> = x"d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737";
#[test_only] const TEST_SIG: vector<u8> = x"a50fa1f60a1635c69b078e0a16ebdadb16332f3037ad8c1703ed5572feebc1a7d57ea53bdbbb7e3cdd42b83c6431cc22ee6f8fba4c5a08f44680505a0129d805";

// A second, independent real vector: a different key signs the RAW bytes of b"miso-binding-test-2".
// Demonstrates the verifier is general, not fitted to one fixture. Also serves as a "wrong pk".
#[test_only] const TEST_PK2: vector<u8> = x"a09aa5f47a6759802ff955f8dc2d2a14a5c99d23be97f864127ff9383455a4f0";
#[test_only] const TEST_SIG2: vector<u8> = x"0a277291c1bd43bdd6a378908c41aaabd94f27a63137b6a36afbd3de333fb801712ad6d384c5ba251f0150c869a204fe48c8bbfae1d847f51cf327465dc7cb0d";

// --- verify: happy path ---

#[test]
#[allow(implicit_const_copy)]
fun test_verify_accepts_real_signature() {
    // Returns a Verified (dropped here); reaching this line without aborting == verified.
    verify(TEST_PK, b"miso-binding-test", TEST_SIG);
}

#[test]
#[allow(implicit_const_copy)]
fun test_verify_accepts_second_real_signature() {
    // A second, independent key/message pair to show the verifier is not fitted to one fixture.
    verify(TEST_PK2, b"miso-binding-test-2", TEST_SIG2);
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
    // Flip the high bit of the first byte of R: still 64 bytes, but no longer the valid signature.
    let mut sig = TEST_SIG;
    let first = *sig.borrow(0);
    *sig.borrow_mut(0) = first ^ 0x80;
    verify(TEST_PK, b"miso-binding-test", sig);
}

#[test, expected_failure(abort_code = EBadSignature)]
#[allow(implicit_const_copy)]
fun test_verify_rejects_tampered_signature_last_byte() {
    // Tamper the final byte of S: still 64 bytes, but no longer the valid signature.
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
    verify(TEST_PK2, b"miso-binding-test", TEST_SIG);
}
