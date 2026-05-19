# Contributing

Thanks for considering a contribution.

## Scope

This repo provides **generic, reusable** hardware-attestation primitives for Sui. Contributions that broaden platform coverage, sharpen the verifier crates, or improve the Nitro enclave operational story are welcome.

What we will **not** merge:

- Application-specific code (anything that bakes in a specific dApp's business logic — those belong downstream).
- Hand-rolled cryptography. Use audited crates (`p256`, `p384`, `rsa`, `ed25519-dalek`, `sha2`, `ciborium`, etc.).
- Verifiers that loosen platform vendors' published rules (e.g., accepting `fmt: "none"` for App Attest, or skipping chain anchoring).
- Anything that introduces a new on-chain trust assumption without it being explicit in the Move types.

## Building

```sh
# Rust
cargo build --workspace
cargo test --workspace
cargo test --workspace -- --ignored        # runs the device-fixture tests

# Move
cd move/attestation && sui move build
cd move/attest_apple && sui move build

# Enclave (requires Linux + Docker)
cd enclave && make
```

## Adding a new attestation source

The shape is documented in [`README.md`](./README.md). In short:

1. Add a Rust verifier crate `rust/attest-<platform>/` that:
   - Parses the raw vendor attestation
   - Validates the chain to the pinned root
   - Returns `attestation_core::Outcome` with `source = "<platform>"`
2. Add a Move consumer package `move/attest_<platform>/` that:
   - Defines a `Source` marker (e.g. `MyPlatformAttest`)
   - Defines a `Payload` struct mirroring the Rust verifier's payload —
     field order must match exactly (BCS is order-sensitive)
   - Exposes `verify(&EnclavePolicy<ATTESTATION>, NitroAttestationDocument,
     <payload fields>, &Clock): Witness<MyPlatformAttest>` which:
       1. Asserts the doc's PCR0/1/2 match the policy
       2. Asserts the doc's `user_data` equals `SHA-256(BCS(payload))`
       3. Asserts the doc's NSM timestamp is fresh (caller-supplied bounds)
       4. Emits `attestation::witness::Witness<MyPlatformAttest>` with the
          NSM timestamp as the witness `timestamp_ms`
   - The caller is responsible for producing the `NitroAttestationDocument`
     via `0x2::nitro_attestation::load_nitro_attestation` in the same PTB.
3. Extend `enclave-server`:
   - Mirror the Move `Payload` as a `serde::Serialize` struct (same field order)
   - Add a `POST /attest/<platform>` handler that:
       1. Runs the off-chain verifier
       2. Computes `payload_hash = SHA-256(BCS(payload))`
       3. Requests a fresh NSM attestation document binding
          `user_data = payload_hash`
       4. Returns the NSM doc bytes + the payload fields for the on-chain call

The base [`attestation`](./move/attestation/) package and the [`enclave-server`](./rust/enclave-server/) binary do not need to be modified for new sources — only the per-platform crate and Move package.

## PR checklist

- [ ] `cargo test --workspace` passes
- [ ] `sui move build` passes in each modified Move package
- [ ] New platform verifiers ship with real-device fixtures in `tests/fixtures/`
- [ ] New cryptographic primitives use audited RustCrypto crates only
- [ ] No application-specific identifiers, keys, or business logic
- [ ] Public APIs are documented

## Reproducible builds

The Nitro enclave image (`enclave/Containerfile`) uses StageX-pinned bases for byte-identical builds. If your changes break reproducibility, mention it in the PR — a different PCR set means every downstream consumer has to re-register the enclave.

## License

By contributing, you agree your work is licensed under the [Apache License 2.0](./LICENSE).
