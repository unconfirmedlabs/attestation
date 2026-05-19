# attestation

Hardware-attestation primitives for Sui Move.

A family of small, composable packages that let any Sui dApp verify that a public key was generated inside genuine consumer hardware — Apple Secure Enclave, Android StrongBox, WebAuthn-attested authenticators, NXP NTAG 424 chips — and consume the result as a typed Move object with provable provenance.

## Why

On Sui today, "bind this account to genuine hardware the user physically controls" is a months-long engineering task involving X.509 chain validation, platform-specific CBOR/COSE parsing, and root-key management. Most dApps skip it. The ones that don't reinvent the same wheel each time.

This repo ships the wheel.

- Rust verifier crates for the heavy lifting (parsing, chain validation), reusable outside Move.
- Thin Move "witness" packages that wrap an attestation outcome into a typed `Witness<Source>` consumable in any PTB.
- Generic challenge-bound attestation — the packages do not bake in application semantics. The consumer (a ticketing dApp, an identity flow, a DePIN enrollment) supplies the challenge that ties the attestation to its domain.

## Package family

| Move package | Status | What it attests |
|---|---|---|
| `attestation` | planned | Base `Witness<Source>` type, used by all source packages |
| `attest_apple` | planned | Apple App Attest — iOS Secure Enclave-backed P-256 keys |
| `attest_android` | planned | Android Key Attestation — StrongBox / TEE-backed keys |
| `attest_webauthn` | planned | WebAuthn registration response — passkeys + security keys |
| `attest_ntag` | planned | NXP NTAG 424 DNA originality signature — genuine NFC chips |

| Rust crate | Status | Purpose |
|---|---|---|
| `attest-apple` | planned | Parse and verify Apple App Attest CBOR + X.509 chain to Apple's root |
| `attest-android` | planned | Parse and verify Android Key Attestation cert extensions |
| `attest-webauthn` | planned | Parse and verify WebAuthn registration attestation statements |
| `attest-ntag` | planned | Verify NXP NTAG 424 originality signature |

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
                      │ attestation outcome + Nautilus signature
                      ▼
              ┌─────────────────┐
              │ Move witness    │   ─ enclave-signature verify
              │ package         │     emits Witness<Source>
              └───────┬─────────┘
                      │ Witness<Source> in PTB
                      ▼
              ┌─────────────────┐
              │ Consumer dApp   │   ─ ticketing, identity, DePIN, etc.
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

Each platform package defines its own `Source` marker (constructible only inside that package) and a `verify(...) -> Witness<Source>` function. Consumers accept `Witness<S>` generically, recording `type_name::get<S>()` to identify the attestation source.

This gives:

- **Provenance**: a `Witness<AppleAppAttest>` could only have come from `attest_apple`. Move's type system enforces it.
- **Generic consumers**: a ticketing package, an identity package, etc., consume any Witness without depending on specific platforms.
- **Independent upgrades**: each platform package upgrades on its own cycle.
- **Permissionless extension**: third parties can publish their own attestation packages following the same pattern.

## Design rationale and threat model

This repo is the *primitive layer* extracted from a larger Miso ticketing design. The architectural reasoning — why challenge-bound attestation, why Nautilus-mediated verification, why this specific package split, what doesn't go into these packages — lives in the Miso experiment doc:

- [`sona/experiments/offline-ticketing/README.md`](https://github.com/unconfirmedlabs/sona/blob/main/experiments/offline-ticketing/README.md) (private)

A standalone design doc will land here as `docs/architecture.md` once stabilized.

## Status

- 2026-05: repo bootstrapped. No package contents yet.
- Initial sequence: Rust `attest-apple` crate (with test vectors) → Move `attestation` base + `attest_apple` wrapper → end-to-end test against a real iOS device.

## License

Apache License 2.0. See [LICENSE](./LICENSE).
