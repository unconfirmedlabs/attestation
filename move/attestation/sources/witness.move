/// Base attestation witness type, parameterised by `Source`.
///
/// Each per-platform attestation package defines its own `Source` marker (a
/// witness-pattern type only its own module can construct) and exposes a
/// `verify` function that returns a `Witness<Source>`. Consumers accept any
/// `Witness<S>` generically — Move's type system guarantees a
/// `Witness<AppleAppAttest>` could only have come from the `attest_apple`
/// package.
module attestation::witness;

use std::type_name::{Self, TypeName};

/// A typed attestation outcome.
public struct Witness<phantom Source> has drop, store {
    /// The attested value: a public key for asymmetric attestations, or a
    /// chip UID for symmetric ones.
    attested_value: vector<u8>,
    /// The challenge the attestation was bound to.
    challenge: vector<u8>,
    /// Verifier timestamp in milliseconds since Unix epoch.
    timestamp_ms: u64,
    /// SHA-256 hash of the raw platform attestation blob (commitment for
    /// audit / dispute resolution).
    detail_hash: vector<u8>,
}

/// Construct a new witness. The phantom `Source` is bound by the witness
/// pattern: the caller must hold a value of type `Source` to invoke `new`,
/// and `Source` types are constructible only inside their own packages.
public fun new<Source: drop>(
    _source_marker: Source,
    attested_value: vector<u8>,
    challenge: vector<u8>,
    timestamp_ms: u64,
    detail_hash: vector<u8>,
): Witness<Source> {
    Witness {
        attested_value,
        challenge,
        timestamp_ms,
        detail_hash,
    }
}

// === Accessors ===

public fun attested_value<S>(w: &Witness<S>): &vector<u8> { &w.attested_value }

public fun challenge<S>(w: &Witness<S>): &vector<u8> { &w.challenge }

public fun timestamp_ms<S>(w: &Witness<S>): u64 { w.timestamp_ms }

public fun detail_hash<S>(w: &Witness<S>): &vector<u8> { &w.detail_hash }

/// Returns the canonical type name of the source marker. Use this to record
/// "which attestation source produced this witness" when persisting it to an
/// object on-chain.
public fun source<S>(_w: &Witness<S>): TypeName { type_name::with_defining_ids<S>() }

// === Tests ===

// The witness pattern itself (only a holder of `Source` can call `new<Source>`)
// is a compile-time guarantee, not a runtime one, so it cannot be exercised by
// a `#[test]`. We instead cover that two *distinct* markers produce witnesses
// whose `source()` is distinguishable, which is the observable consequence of
// that pattern.

#[test_only] use std::unit_test::assert_eq;
#[test_only] public struct TestSource has drop {}
#[test_only] public struct OtherSource has drop {}

#[test_only] const PK: vector<u8> = b"device-public-key";
#[test_only] const CHALLENGE: vector<u8> = b"server-nonce";
#[test_only] const DETAIL: vector<u8> = b"sha256-of-blob";

/// Every accessor returns exactly what was passed into `new`.
#[test]
fun test_new_accessors_roundtrip() {
    let w = new(TestSource {}, PK, CHALLENGE, 1_700_000_000_000, DETAIL);
    assert_eq!(*w.attested_value(), PK);
    assert_eq!(*w.challenge(), CHALLENGE);
    assert_eq!(w.timestamp_ms(), 1_700_000_000_000);
    assert_eq!(*w.detail_hash(), DETAIL);
}

/// `source()` returns the canonical `TypeName` for the marker, matching
/// `type_name::with_defining_ids` for the same type argument.
#[test]
fun test_source_is_canonical_type_name() {
    let w = new(TestSource {}, PK, CHALLENGE, 0, DETAIL);
    assert_eq!(w.source(), type_name::with_defining_ids<TestSource>());
}

/// Distinct `Source` markers yield witnesses with distinguishable `source()`,
/// the observable consequence of the witness pattern.
#[test]
fun test_distinct_sources_are_distinguishable() {
    let a = new(TestSource {}, PK, CHALLENGE, 0, DETAIL);
    let b = new(OtherSource {}, PK, CHALLENGE, 0, DETAIL);
    assert!(a.source() != b.source());
    // Each still equals its own canonical type name.
    assert_eq!(a.source(), type_name::with_defining_ids<TestSource>());
    assert_eq!(b.source(), type_name::with_defining_ids<OtherSource>());
}

/// Empty byte vectors are accepted and round-trip unchanged for every
/// `vector<u8>` field.
#[test]
fun test_empty_byte_fields() {
    let empty = vector<u8>[];
    let w = new(TestSource {}, empty, empty, 42, empty);
    assert_eq!(*w.attested_value(), empty);
    assert_eq!(*w.challenge(), empty);
    assert_eq!(*w.detail_hash(), empty);
    assert_eq!(w.timestamp_ms(), 42);
}

/// Timestamp boundary values (0 and u64::MAX) round-trip unchanged.
#[test]
fun test_timestamp_boundaries() {
    let zero = new(TestSource {}, PK, CHALLENGE, 0, DETAIL);
    assert_eq!(zero.timestamp_ms(), 0);

    let max = new(TestSource {}, PK, CHALLENGE, 18_446_744_073_709_551_615, DETAIL);
    assert_eq!(max.timestamp_ms(), 18_446_744_073_709_551_615);
}

/// The `Witness` struct has `drop`: it can be created and silently discarded
/// without explicit destruction. (If it lacked `drop`, this test would not
/// compile.) `store` is exercised by `device_binding`, which embeds a
/// `Witness` inside a stored object.
#[test]
fun test_witness_has_drop() {
    let _w = new(TestSource {}, PK, CHALLENGE, 1, DETAIL);
    // falls out of scope and is dropped — no `destroy` needed.
}
