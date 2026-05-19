//! Integration tests against real Apple device attestations.
//!
//! Fixtures are captured from the `ios-demo` Xcode project running on a real
//! device. To add one:
//!
//!   1. Run the demo with a known `challenge` (32 random bytes).
//!   2. Save `(attestationObject, keyId, challenge, app_id, production)` as
//!      JSON in `tests/fixtures/`.
//!   3. Add a `#[test]` case below referencing the fixture.
//!
//! These tests are `#[ignore]`d by default — `cargo test -- --ignored` runs
//! them once fixtures exist.

use attest_apple::verify_app_attest;
use std::fs;
use std::path::PathBuf;

#[derive(serde::Deserialize)]
struct Fixture {
    attestation_object_hex: String,
    key_id_hex: String,
    challenge_hex: String,
    app_id: String,
    production: bool,
}

fn load_fixture(name: &str) -> Option<Fixture> {
    let path: PathBuf = ["tests", "fixtures", &format!("{name}.json")]
        .iter()
        .collect();
    let raw = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&raw).ok()
}

#[test]
#[ignore = "requires real-device fixture in tests/fixtures/"]
fn fixture_dev_iphone_001() {
    let Some(f) = load_fixture("dev_iphone_001") else {
        panic!("place dev_iphone_001.json in tests/fixtures/ first");
    };
    let result = verify_app_attest(
        &hex::decode(&f.attestation_object_hex).unwrap(),
        &hex::decode(&f.key_id_hex).unwrap(),
        &hex::decode(&f.challenge_hex).unwrap(),
        &f.app_id,
        f.production,
        1_700_000_000_000,
    );
    assert!(result.is_ok(), "{:?}", result);
}
