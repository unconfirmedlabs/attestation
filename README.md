# attestation

Hardware-attestation primitives for Sui Move.

A family of small, composable packages that verify a public key was generated inside genuine consumer hardware — Apple Secure Enclave, Android StrongBox, WebAuthn-attested authenticators, NXP NTAG 424 chips — and surface the result as a typed Move object with provable provenance.

## Overview

Two layers:

- **Rust verifier crates.** Parse and validate hardware-attestation blobs: CBOR/COSE decoding, X.509 chain validation across the curves each platform uses, signature checks against pinned roots. Usable as plain libraries outside the Move ecosystem.
- **Move witness packages.** Accept a verifier outcome and emit a typed `Witness<Source>` consumable in any PTB. Each package pins its own platform root and defines its own `Source` marker.

Verifiers run inside an AWS Nitro Enclave. The Move side accepts a verifier outcome only when it arrives inside a fresh Nitro attestation document whose PCRs match an on-chain `Policy` — so on-chain code re-checks the enclave image on every call.

Packages don't bind to application semantics. The consumer supplies the challenge that ties an attestation to its domain.

## Package family

| Move package | Status | What it attests |
|---|---|---|
| `attestation` | **v0 deployed** | Base `Witness<Source>` type, used by all source packages |
| `attest_apple` | **v0 deployed** | Apple App Attest — iOS Secure Enclave-backed P-256 keys. Two peer modules: `attestation` (one-time hardware proof) and `assertion` (per-payload signature) |
| `attest_android` | planned | Android Key Attestation — StrongBox / TEE-backed keys (also WebAuthn `fmt: "android-key"`) |
| `attest_ntag` | planned | NXP NTAG 424 DNA originality signature — genuine NFC chips |
| `attest_fido` | deferred | WebAuthn `fmt: "packed"` — security keys, self-attested authenticators |

| Rust crate | Status | Purpose |
|---|---|---|
| `attestation-core` | **v0** | Common Rust types shared by every per-platform verifier crate: an `Outcome` return struct and the canonical `sources::*` identifier strings. Internal to the verifier toolchain — the on-chain side does not consume `Outcome`; each platform mirrors its Move `Payload` struct independently for the NSM `user_data` binding. |
| `attest-apple` | **v0** | Parse and verify Apple App Attest attestation + assertion. X.509 chain validation across P-256 leaf and P-384 intermediates against Apple's root |
| `enclave-server` | **v0** | Reference HTTP server. Runs verifiers inside a Nitro enclave; every response carries a fresh NSM attestation document the Move side verifies on-chain |
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
       ┌─────────────────────────────────┐
       │  AWS Nitro Enclave              │
       │  (pinned EIF — PCR-identified)  │
       │                                 │
       │  1. Rust verifier parses the    │
       │     blob, validates the chain   │
       │  2. Requests a fresh NSM        │
       │     attestation document whose  │
       │     user_data = SHA-256(BCS(    │
       │     verified outcome))          │
       └────────────────┬────────────────┘
                        │ NSM document
                        │ (AWS-signed COSE_Sign1, ephemeral)
                        ▼
       ┌─────────────────────────────────┐
       │  Move witness package           │
       │                                 │
       │  • sui::nitro_attestation       │
       │    verifies AWS root signature  │
       │  • PCRs match the on-chain      │
       │    Policy object                │
       │  • user_data hash binds payload │
       │  • NSM timestamp gates freshness│
       └────────────────┬────────────────┘
                        │ Witness<Source> in PTB
                        ▼
              ┌─────────────────┐
              │  Consumer dApp  │
              └─────────────────┘
```

The heavy cryptographic parsing (X.509, CBOR, COSE) happens once, in Rust, inside a Nitro Enclave whose image is pinned by PCRs. Each verifier response carries its own fresh NSM attestation document — signed by AWS Nitro, not by the enclave — that binds the verified outcome via `user_data`. The Move side never trusts a long-lived signing key: every on-chain `verify` re-checks the Nitro signature, re-checks the PCRs against the on-chain `Policy`, and re-derives the payload hash. That's the "maximum on-chain checking" guarantee. On success the consumer receives a `Witness<Source>` whose source is enforced by Move's type system.

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

- **2026-05**: Apple App Attest verifier working end-to-end against real iPhone fixtures with Apple's root CA pinned. Both attestation and assertion verbs implemented. `enclave-server` runs inside an AWS Nitro Enclave on a `c6a.xlarge` host; each response carries a fresh NSM-signed attestation document the Move side verifies on-chain. Enclave registered via [`kagi`](https://github.com/unconfirmedlabs/kagi) — PCRs pinned in an immutable on-chain `Policy`. Full deploy + IDs in [`deployments/testnet.json`](./deployments/testnet.json), including the end-to-end Sui tx that verified a real iPhone attestation through the chain.
- **Next**: capture broader iPhone fixture coverage; begin `attest_ntag`.
- **Then**: `attest_android` and `attest_fido` once devices are on hand.

### Testnet deployment

See [`deployments/testnet.json`](./deployments/testnet.json) for the canonical list.

| Package | Package ID |
|---|---|
| `attestation` | `0x63c21a61d4021cebf4fdac6d1b1d1832e5e5c3da017736494f9c0d24c11bfd0e` |
| `attest_apple` | `0xfab0aa286d6e93794020597d20baada133dfb3a3992a070bfa010e0f78990137` |
| `kagi` (enclave registry) | `0x68b0993136fdc5aa02275a3a0b51f93e9b7c3b601867ec4a8123a76503665161` |
| Enclave `Policy` (PCR-pinned) | `0x5ce7b5ccec53698cec0a8cf2a631805069f51dca9c8cded853a1e0680f38bc34` |

End-to-end verified tx (real iPhone attestation → enclave → on-chain `Witness<AppleAppAttest>`): [`EX4ZovBKn4G5w1q3nMkVHQuyuiz6RS24tGNcgZx2bCzs`](https://suiscan.xyz/testnet/tx/EX4ZovBKn4G5w1q3nMkVHQuyuiz6RS24tGNcgZx2bCzs).

## License

Apache License 2.0. See [LICENSE](./LICENSE).
