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
