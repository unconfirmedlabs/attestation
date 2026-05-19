/// The Apple App Attest source marker.
///
/// `AppleAppAttest` is the witness type that proves a `Witness<AppleAppAttest>`
/// was produced by this package. The struct has no fields and `drop` only;
/// values are constructed inside this module via `new()` and immediately
/// consumed when forming a witness.
module attest_apple::source;

public struct AppleAppAttest has drop {}

public(package) fun new(): AppleAppAttest {
    AppleAppAttest {}
}
