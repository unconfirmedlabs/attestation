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
   - Defines a `Source` marker
   - Takes `&Enclave<ATTESTATION>` and a payload
   - Calls `enclave.verify_signature(intent, ts, payload, sig)`
   - Emits `attestation::witness::Witness<YourSource>`
3. Extend `enclave-server`:
   - Define the matching `Payload` struct (BCS field order must match Move)
   - Add a `POST /attest/<platform>` handler
   - Sign `IntentMessage<Payload>` with the enclave's Ed25519 key

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
