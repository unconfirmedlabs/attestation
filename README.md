# attestation

Hardware-attestation primitives for Sui Move.

A family of small, composable packages that verify a public key was generated inside genuine consumer hardware — Apple Secure Enclave, Android StrongBox, WebAuthn-attested authenticators, NXP NTAG 424 chips — and surface the result as a typed Move object with provable provenance.

## Why

On Sui today, validating standard hardware attestations on-chain is a months-long engineering task: X.509 chain validation across multiple curves, platform-specific CBOR/COSE parsing, root-key management, gas-priced ECDSA. Most projects skip it. The ones that don't reinvent the same wheel each time.

This repo ships the wheel.

- Rust verifier crates for the heavy lifting (parsing, chain validation), reusable outside Move.
- Thin Move "witness" packages that wrap an attestation outcome into a typed `Witness<Source>` consumable in any PTB.
- Generic challenge-bound attestation — the packages do not bake in application semantics. The consumer supplies the challenge that ties the attestation to its domain.

## Package family

| Move package | Status | What it attests |
|---|---|---|
| `attestation` | **v0 scaffolded** | Base `Witness<Source>` type, used by all source packages |
| `attest_apple` | **v0 scaffolded** | Apple App Attest — iOS Secure Enclave-backed P-256 keys (also accepts WebAuthn `fmt: "apple"` later) |
| `attest_android` | planned | Android Key Attestation — StrongBox / TEE-backed keys (also WebAuthn `fmt: "android-key"`) |
| `attest_ntag` | planned | NXP NTAG 424 DNA originality signature — genuine NFC chips |
| `attest_fido` | deferred | WebAuthn `fmt: "packed"` — security keys, self-attested authenticators |

| Rust crate | Status | Purpose |
|---|---|---|
| `attestation-core` | **v0** | Canonical `Outcome` struct with BCS serde — shared by every per-platform crate |
| `attest-apple` | **v0** | Parse and verify Apple App Attest CBOR + X.509 chain to Apple's root |
| `enclave-server` | **v0** | Reference HTTP server that runs verifiers and emits BCS+Ed25519-signed outcomes |
| `attest-android` | planned | Parse and verify Android Key Attestation cert extensions |
| `attest-ntag` | planned | Verify NXP NTAG 424 originality signature (P-224 ECDSA against NXP's root) |
| `attest-fido` | deferred | Parse and verify WebAuthn packed attestation |

## Design at a glance

```
                Holder device
              ┌─────────────────┐
              │ Secure Enclave  │
              │ or NTAG chip    │
              └───────┬─────────┘
                      │ raw attestation blob
                      ▼
              ┌─────────────────┐
              │  Rust verifier  │   ─ runs inside a Nautilus enclave
              │  (per-platform) │     (or any trusted verifier env)
              └───────┬─────────┘
                      │ attestation outcome + Ed25519 signature
                      ▼
              ┌─────────────────┐
              │ Move witness    │   ─ verify enclave signature,
              │ package         │     emit Witness<Source>
              └───────┬─────────┘
                      │ Witness<Source> in PTB
                      ▼
              ┌─────────────────┐
              │ Consumer dApp   │
              └─────────────────┘
```

The heavy cryptographic parsing happens once, in Rust, inside a Nautilus enclave. The Move side verifies an enclave-signed attestation outcome — a small, fast operation — and produces a typed witness with provenance enforced by Move's type system.

## Witness pattern

The base package provides one type:

```move
public struct Witness<phantom Source> has drop, store {
    attested_value: vector<u8>,    // pk or chip UID
    challenge:      vector<u8>,    // caller-supplied freshness binding
    timestamp_ms:   u64,
    detail_hash:    vector<u8>,    // sha256 of platform attestation blob
}
```

Each platform package defines its own `Source` marker (constructible only inside that package) and a `verify(...) -> Witness<Source>` function. Consumers accept `Witness<S>` generically, recording `type_name::with_defining_ids<S>()` to identify the attestation source.

This gives:

- **Provenance**: a `Witness<AppleAppAttest>` could only have come from `attest_apple`. Move's type system enforces it.
- **Generic consumers**: downstream packages accept any Witness without depending on specific platforms.
- **Independent upgrades**: each platform package upgrades on its own cycle.
- **Permissionless extension**: third parties can publish their own attestation packages following the same pattern.

## Status

- **2026-05**: repo bootstrapped, Apple App Attest verifier working end-to-end against real iPhone fixtures with Apple's root CA pinned. Move packages (`attestation` base + `attest_apple`) deployed to Sui testnet (see [`deployments/testnet.json`](./deployments/testnet.json)). Reference `enclave-server` binary exposes `/attest/apple` over HTTP and emits BCS+Ed25519-signed outcomes the Move side consumes directly.
- **Next**: wrap the enclave server in a Nitro Enclave image (PCR-pinned, attested via `sui::nitro_attestation`); capture broader iPhone fixture coverage; begin `attest_ntag`.
- **Then**: `attest_android` and `attest_fido` once devices are on hand.

### Testnet deployment

| Package | Package ID |
|---|---|
| `attestation` | `0x5428972a680e966a3ba4a74f4e3a42e33073b16bc4f7db56f04b4b719690790f` |
| `attest_apple` | `0x75991f659fc203d340701818760eb0f36a1b9e01a020e15ec7f19e91a760da23` |

## License

Apache License 2.0. See [LICENSE](./LICENSE).
