/// Persists a hardware attestation into a soulbound, account-anchored device credential, and gates
/// per-action use behind a device signature — without knowing *how* that signature is verified.
///
/// `new` consumes an `attestation::witness::Witness<Source>` (proof the key is genuine hardware) once and
/// mints a `DeviceBinding<Source, Scheme>` — `key`-only, so it is **soulbound** and Sui object ownership
/// *is* the account binding. The two phantom params are orthogonal: `Source` = which package proved
/// genuineness (`AppleAppAttest`, …); `Scheme` = which signature algorithm verifies the device key
/// (`Secp256r1`, …).
///
/// Verification is **pluggable** so the package never needs upgrading for a new curve (Move can't add
/// enum variants on upgrade). This module does no crypto: a per-scheme verifier package runs the native
/// check and returns a `Verified<Scheme>` receipt — constructible only by that scheme's own package (it
/// must supply a `Scheme` witness). `verify_action` accepts the receipt and confirms it matches this
/// binding's key, scheme (by type), and canonical action message. New scheme = new verifier package.
module device_binding::device_binding;

use std::type_name;
use std::bcs;
use sui::clock::Clock;
use sui::event;
use attestation::witness::{Self, Witness};

/// The supplied public key does not match the attested key in the witness.
const EKeyMismatch: u64 = 0;

/// Domain-separation prefix mixed into every signed message (package · verb · version).
const MESSAGE_PREFIX: vector<u8> = b"device_binding::verify_action::v1";

/// A genuine device key bound to its holder. `key`-only → **soulbound**. Owned by the holder's account,
/// so Sui ownership is the account binding. `Source` = attestation provenance, `Scheme` = signature
/// algorithm — both in the type, so neither needs a field.
public struct DeviceBinding<phantom Source, phantom Scheme> has key {
    id: UID,
    pk: vector<u8>,
    issued_at_ms: u64,
}

/// A receipt that a `Scheme` verifier checked a signature of `pk` over `message`. Constructible only by
/// the package that defines `Scheme` (it must hold a `Scheme` value), so this module trusts it without
/// knowing the curve. Ephemeral (`drop`).
public struct Verified<phantom Scheme> has drop {
    pk: vector<u8>,
    message: vector<u8>,
}

public struct DeviceBoundEvent has copy, drop {
    binding_id: ID,
    source: vector<u8>,
    scheme: vector<u8>,
}

public struct DeviceBindingDestroyedEvent has copy, drop {
    binding_id: ID,
}

// === Verifier interface ===

/// Mint a verification receipt. Witness-gated: only the package that defines `Scheme` can call this (it
/// must supply a `Scheme` value). A scheme verifier calls this after a successful native signature check.
public fun verified<Scheme: drop>(_scheme: Scheme, pk: vector<u8>, message: vector<u8>): Verified<Scheme> {
    Verified { pk, message }
}

// === Enrollment ===

/// Mint a soulbound binding from a one-time attestation. `pk` must equal the attested key, so the scheme
/// tag is caller-supplied but the key material is the genuine attested one. Pure: returns the object; the
/// caller places it with `transfer_to`.
public fun new<Source: drop, Scheme>(
    attestation: Witness<Source>,
    pk: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
): DeviceBinding<Source, Scheme> {
    assert!(pk == *witness::attested_value(&attestation), EKeyMismatch);
    let binding = DeviceBinding<Source, Scheme> {
        id: object::new(ctx),
        pk,
        issued_at_ms: clock.timestamp_ms(),
    };
    event::emit(DeviceBoundEvent {
        binding_id: object::id(&binding),
        source: type_name::with_defining_ids<Source>().into_string().into_bytes(),
        scheme: type_name::with_defining_ids<Scheme>().into_string().into_bytes(),
    });
    binding
}

/// Place a freshly-minted binding with its holder. Soulbound: only this module can move it.
public fun transfer_to<Source, Scheme>(binding: DeviceBinding<Source, Scheme>, recipient: address) {
    transfer::transfer(binding, recipient);
}

// === Per-action verification ===

/// The canonical message a device must sign to authorize `(domain, action_hash, expiry_ms)` for this
/// binding — domain-separated and scoped to this exact binding id. Hand it to the scheme verifier; pass
/// the same args to `verify_action`.
public fun action_message<Source, Scheme>(
    binding: &DeviceBinding<Source, Scheme>,
    domain: vector<u8>,
    action_hash: vector<u8>,
    expiry_ms: u64,
): vector<u8> {
    canonical_message(object::id(binding), domain, action_hash, expiry_ms)
}

/// Confirm a `Verified<Scheme>` receipt authorizes this exact action: the receipt's `Scheme` matches the
/// binding's (compile-time), its key is the bound key, its message is the canonical action message, and
/// the action is unexpired.
public fun verify_action<Source, Scheme>(
    binding: &DeviceBinding<Source, Scheme>,
    verified: Verified<Scheme>,
    domain: vector<u8>,
    action_hash: vector<u8>,
    expiry_ms: u64,
    clock: &Clock,
): bool {
    let Verified { pk, message } = verified;
    clock.timestamp_ms() <= expiry_ms
        && pk == binding.pk
        && message == canonical_message(object::id(binding), domain, action_hash, expiry_ms)
}

// === Teardown ===

/// Destroy a binding (the consumer's "revoke a device"). Gated by ownership — only the holder can supply
/// the owned object.
public fun destroy<Source, Scheme>(binding: DeviceBinding<Source, Scheme>) {
    let DeviceBinding { id, pk: _, issued_at_ms: _ } = binding;
    event::emit(DeviceBindingDestroyedEvent { binding_id: id.to_inner() });
    id.delete();
}

// === Accessors ===

public fun pk<Source, Scheme>(binding: &DeviceBinding<Source, Scheme>): &vector<u8> { &binding.pk }
public fun issued_at_ms<Source, Scheme>(binding: &DeviceBinding<Source, Scheme>): u64 { binding.issued_at_ms }

// === Internal ===

#[allow(implicit_const_copy)]
fun canonical_message(binding_id: ID, domain: vector<u8>, action_hash: vector<u8>, expiry_ms: u64): vector<u8> {
    let mut message = MESSAGE_PREFIX;
    message.append(domain);
    message.append(bcs::to_bytes(&binding_id));
    message.append(action_hash);
    message.append(bcs::to_bytes(&expiry_ms));
    message
}

// === Tests (verifier-agnostic: a TestScheme stands in for a real curve package) ===

#[test_only] use sui::clock;
#[test_only] public struct TestSource has drop {}
#[test_only] public struct TestScheme has drop {}
#[test_only] const TEST_PK: vector<u8> = b"device-public-key";

#[test_only]
fun fresh_binding(clk: &Clock, ctx: &mut TxContext): DeviceBinding<TestSource, TestScheme> {
    let w = witness::new(TestSource {}, TEST_PK, b"challenge", 0, b"detail");
    new<TestSource, TestScheme>(w, TEST_PK, clk, ctx)
}

#[test]
fun test_verify_action_accepts_matching_receipt() {
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    let msg = action_message(&binding, b"miso/transfer", b"action", 1000);
    let receipt = verified(TestScheme {}, TEST_PK, msg);
    assert!(verify_action(&binding, receipt, b"miso/transfer", b"action", 1000, &clk));
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_verify_action_rejects_wrong_key_action_and_expiry() {
    let ctx = &mut tx_context::dummy();
    let mut clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    let msg = action_message(&binding, b"miso/transfer", b"action", 1000);
    // wrong key in the receipt
    assert!(!verify_action(&binding, verified(TestScheme {}, b"other-key", msg), b"miso/transfer", b"action", 1000, &clk));
    // receipt is over "action" but we ask about "other" → message mismatch
    assert!(!verify_action(&binding, verified(TestScheme {}, TEST_PK, msg), b"miso/transfer", b"other", 1000, &clk));
    // expired
    clk.set_for_testing(2000);
    let msg2 = action_message(&binding, b"miso/transfer", b"action", 1000);
    assert!(!verify_action(&binding, verified(TestScheme {}, TEST_PK, msg2), b"miso/transfer", b"action", 1000, &clk));
    destroy(binding);
    clk.destroy_for_testing();
}

#[test, expected_failure(abort_code = EKeyMismatch)]
fun test_new_rejects_key_mismatch() {
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let w = witness::new(TestSource {}, TEST_PK, b"challenge", 0, b"detail");
    let binding = new<TestSource, TestScheme>(w, b"a-different-key", &clk, ctx);
    transfer_to(binding, @0xA);
    clk.destroy_for_testing();
}

#[test]
fun test_issued_at_recorded() {
    let ctx = &mut tx_context::dummy();
    let mut clk = clock::create_for_testing(ctx);
    clk.set_for_testing(777);
    let binding = fresh_binding(&clk, ctx);
    assert!(binding.issued_at_ms() == 777);
    destroy(binding);
    clk.destroy_for_testing();
}
