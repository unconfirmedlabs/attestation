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
#[test_only] use sui::test_scenario;
#[test_only] use std::unit_test::assert_eq;
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

// === `new` enrollment: happy path records state + emits DeviceBoundEvent ===

#[test]
fun test_new_records_pk_and_issued_at_from_clock() {
    let ctx = &mut tx_context::dummy();
    let mut clk = clock::create_for_testing(ctx);
    clk.set_for_testing(123_456);
    let binding = fresh_binding(&clk, ctx);
    // `new` stores the attested key verbatim and stamps it with the clock at mint.
    assert_eq!(*binding.pk(), TEST_PK);
    assert_eq!(binding.issued_at_ms(), 123_456);
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_new_emits_device_bound_event() {
    let mut scenario = test_scenario::begin(@0xA);
    let clk = clock::create_for_testing(scenario.ctx());
    let binding = fresh_binding(&clk, scenario.ctx());
    let id = object::id(&binding);

    // One DeviceBoundEvent, carrying the binding id and the source/scheme type names.
    assert_eq!(event::num_events(), 1);
    let evs = event::events_by_type<DeviceBoundEvent>();
    assert_eq!(evs.length(), 1);
    assert_eq!(evs[0].binding_id, id);
    assert!(evs[0].source.length() > 0);
    assert!(evs[0].scheme.length() > 0);

    destroy(binding);
    clk.destroy_for_testing();
    scenario.end();
}

#[test]
fun test_new_accepts_empty_pk_when_attested_value_empty() {
    // Edge: an empty attested key is still a valid (if degenerate) binding — `new` only requires
    // pk == attested_value, and stores it verbatim.
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let w = witness::new(TestSource {}, b"", b"challenge", 0, b"detail");
    let binding = new<TestSource, TestScheme>(w, b"", &clk, ctx);
    assert_eq!(*binding.pk(), b"");
    destroy(binding);
    clk.destroy_for_testing();
}

// === `action_message` domain separation: each input axis changes the canonical message ===

#[test]
fun test_action_message_is_deterministic() {
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    // Pure function of its inputs: same args → byte-identical message.
    let a = action_message(&binding, b"miso/transfer", b"action", 1000);
    let b = action_message(&binding, b"miso/transfer", b"action", 1000);
    assert_eq!(a, b);
    assert!(a.length() > 0);
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_action_message_distinct_per_domain() {
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    let m1 = action_message(&binding, b"miso/transfer", b"action", 1000);
    let m2 = action_message(&binding, b"miso/redeem", b"action", 1000);
    assert!(m1 != m2);
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_action_message_distinct_per_action_hash() {
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    let m1 = action_message(&binding, b"miso/transfer", b"action-a", 1000);
    let m2 = action_message(&binding, b"miso/transfer", b"action-b", 1000);
    assert!(m1 != m2);
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_action_message_distinct_per_expiry() {
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    let m1 = action_message(&binding, b"miso/transfer", b"action", 1000);
    let m2 = action_message(&binding, b"miso/transfer", b"action", 2000);
    assert!(m1 != m2);
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_action_message_distinct_per_binding_id() {
    // The message is scoped to a specific binding id, so two distinct bindings with identical
    // (domain, action, expiry) still produce different canonical messages — a receipt for one
    // binding can never authorize an action on another.
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let b1 = fresh_binding(&clk, ctx);
    let b2 = fresh_binding(&clk, ctx);
    assert!(object::id(&b1) != object::id(&b2));
    let m1 = action_message(&b1, b"miso/transfer", b"action", 1000);
    let m2 = action_message(&b2, b"miso/transfer", b"action", 1000);
    assert!(m1 != m2);
    destroy(b1);
    destroy(b2);
    clk.destroy_for_testing();
}

// === `verify_action` false branches, isolated ===

#[test]
fun test_verify_action_rejects_wrong_key_only() {
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    let msg = action_message(&binding, b"miso/transfer", b"action", 1000);
    // Message is canonical and clock is unexpired; the receipt key is the sole defect.
    let receipt = verified(TestScheme {}, b"attacker-key", msg);
    assert!(!verify_action(&binding, receipt, b"miso/transfer", b"action", 1000, &clk));
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_verify_action_rejects_wrong_domain_only() {
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    // Receipt signs the "transfer" domain; we ask verify_action about "redeem".
    let msg = action_message(&binding, b"miso/transfer", b"action", 1000);
    let receipt = verified(TestScheme {}, TEST_PK, msg);
    assert!(!verify_action(&binding, receipt, b"miso/redeem", b"action", 1000, &clk));
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_verify_action_rejects_wrong_action_only() {
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    let msg = action_message(&binding, b"miso/transfer", b"action-a", 1000);
    let receipt = verified(TestScheme {}, TEST_PK, msg);
    assert!(!verify_action(&binding, receipt, b"miso/transfer", b"action-b", 1000, &clk));
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_verify_action_rejects_wrong_expiry_in_message_only() {
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    // Receipt binds expiry 1000; caller claims 2000. Both are in the future (clock = 0) so this is
    // a pure message mismatch, NOT an expiry-clock rejection — proves expiry is part of the message.
    let msg = action_message(&binding, b"miso/transfer", b"action", 1000);
    let receipt = verified(TestScheme {}, TEST_PK, msg);
    assert!(!verify_action(&binding, receipt, b"miso/transfer", b"action", 2000, &clk));
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_verify_action_rejects_expired_clock_only() {
    let ctx = &mut tx_context::dummy();
    let mut clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    let msg = action_message(&binding, b"miso/transfer", b"action", 1000);
    let receipt = verified(TestScheme {}, TEST_PK, msg);
    // Key + message are exactly correct; the clock is the only defect (1001 > expiry 1000).
    clk.set_for_testing(1001);
    assert!(!verify_action(&binding, receipt, b"miso/transfer", b"action", 1000, &clk));
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_verify_action_accepts_at_expiry_boundary() {
    let ctx = &mut tx_context::dummy();
    let mut clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    let msg = action_message(&binding, b"miso/transfer", b"action", 1000);
    let receipt = verified(TestScheme {}, TEST_PK, msg);
    // Boundary: clock == expiry is still valid (check is `timestamp_ms <= expiry_ms`).
    clk.set_for_testing(1000);
    assert!(verify_action(&binding, receipt, b"miso/transfer", b"action", 1000, &clk));
    destroy(binding);
    clk.destroy_for_testing();
}

#[test]
fun test_verify_action_accepts_large_expiry() {
    // Edge: a far-future expiry never trips the clock check.
    let ctx = &mut tx_context::dummy();
    let clk = clock::create_for_testing(ctx);
    let binding = fresh_binding(&clk, ctx);
    let big = 18_446_744_073_709_551_615; // u64::MAX
    let msg = action_message(&binding, b"miso/transfer", b"action", big);
    let receipt = verified(TestScheme {}, TEST_PK, msg);
    assert!(verify_action(&binding, receipt, b"miso/transfer", b"action", big, &clk));
    destroy(binding);
    clk.destroy_for_testing();
}

// Note: a `Verified<Scheme>` minted for the wrong `Scheme` cannot even be passed to
// `verify_action` — the type parameters must unify, so wrong-scheme rejection is enforced at
// compile time and has no runtime test.

// === `transfer_to`: soulbound placement at the recipient ===

#[test]
fun test_transfer_to_lands_at_recipient() {
    let holder = @0xCAFE;
    let mut scenario = test_scenario::begin(@0xA);
    let clk = clock::create_for_testing(scenario.ctx());

    scenario.next_tx(@0xA);
    let binding = fresh_binding(&clk, scenario.ctx());
    let id = object::id(&binding);
    transfer_to(binding, holder);

    // The binding is owned by the holder and takeable there in a later tx.
    scenario.next_tx(holder);
    assert!(test_scenario::has_most_recent_for_address<DeviceBinding<TestSource, TestScheme>>(holder));
    let taken = scenario.take_from_address<DeviceBinding<TestSource, TestScheme>>(holder);
    assert_eq!(object::id(&taken), id);
    assert_eq!(*taken.pk(), TEST_PK);

    destroy(taken);
    clk.destroy_for_testing();
    scenario.end();
}

#[test]
fun test_transfer_to_not_at_other_address() {
    let holder = @0xCAFE;
    let stranger = @0xBEEF;
    let mut scenario = test_scenario::begin(@0xA);
    let clk = clock::create_for_testing(scenario.ctx());

    scenario.next_tx(@0xA);
    let binding = fresh_binding(&clk, scenario.ctx());
    transfer_to(binding, holder);

    // Soulbound: it sits with the holder only — no copy lands anywhere else.
    scenario.next_tx(stranger);
    assert!(!test_scenario::has_most_recent_for_address<DeviceBinding<TestSource, TestScheme>>(stranger));
    assert!(test_scenario::has_most_recent_for_address<DeviceBinding<TestSource, TestScheme>>(holder));

    let taken = scenario.take_from_address<DeviceBinding<TestSource, TestScheme>>(holder);
    destroy(taken);
    clk.destroy_for_testing();
    scenario.end();
}

// === `destroy`: deletes the object and emits DeviceBindingDestroyedEvent ===

#[test]
fun test_destroy_emits_event() {
    let mut scenario = test_scenario::begin(@0xA);
    let clk = clock::create_for_testing(scenario.ctx());

    let binding = fresh_binding(&clk, scenario.ctx());
    let id = object::id(&binding);

    // Isolate the destroy tx so its event count is unambiguous.
    scenario.next_tx(@0xA);
    destroy(binding);

    let evs = event::events_by_type<DeviceBindingDestroyedEvent>();
    assert_eq!(evs.length(), 1);
    assert_eq!(evs[0].binding_id, id);

    clk.destroy_for_testing();
    scenario.end();
}

#[test]
fun test_destroy_removes_object_from_recipient() {
    // After transfer_to then destroy, the object no longer exists at the holder, and the destroy
    // tx records exactly one user event (DeviceBindingDestroyedEvent).
    let holder = @0xCAFE;
    let mut scenario = test_scenario::begin(@0xA);
    let clk = clock::create_for_testing(scenario.ctx());

    scenario.next_tx(@0xA);
    let binding = fresh_binding(&clk, scenario.ctx());
    transfer_to(binding, holder);

    scenario.next_tx(holder);
    let taken = scenario.take_from_address<DeviceBinding<TestSource, TestScheme>>(holder);
    destroy(taken);

    let effects = scenario.next_tx(holder);
    assert_eq!(effects.num_user_events(), 1);
    assert!(!test_scenario::has_most_recent_for_address<DeviceBinding<TestSource, TestScheme>>(holder));

    clk.destroy_for_testing();
    scenario.end();
}
