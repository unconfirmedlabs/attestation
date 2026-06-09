/// Apple App Attest source markers.
///
/// Each marker is the witness-pattern type whose presence proves the
/// holding `Witness<Marker>` came from this package. Marker structs have
/// no fields and `drop` only; values are constructed inside their own
/// module and immediately consumed when forming a witness.
module attest_apple::source;

/// Marker for `Witness<AppleAppAttest>`: proves a P-256 public key was
/// generated inside genuine Apple Secure Enclave hardware (full Apple
/// PKI chain to the pinned Apple App Attestation Root CA).
public struct AppleAppAttest has drop {}

/// Marker for `Witness<AppleAssertion>`: proves an Apple-attested SE key
/// signed a specific payload. Always paired conceptually with a prior
/// `Witness<AppleAppAttest>` for the same `attested_key`, but the type
/// system does not enforce that link — composition is the consumer's
/// responsibility.
public struct AppleAssertion has drop {}

public(package) fun new_app_attest(): AppleAppAttest {
    AppleAppAttest {}
}

public(package) fun new_assertion(): AppleAssertion {
    AppleAssertion {}
}

// No Move unit tests: the marker structs are field-less `drop` witnesses with no
// behaviour, and the `Witness<Source>` discrimination they enable is a compile-time
// type property. Provenance is exercised end-to-end via `verify` (Rust crate /
// integration test).
