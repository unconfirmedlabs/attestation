# Nitro Enclave image for the attestation server

This directory builds a reproducible AWS Nitro Enclave Image File (EIF) containing the `enclave-server` binary. The EIF is what gets loaded by `nitro-cli run-enclave` on a Nitro-supported EC2 host.

## Layout

```
enclave/
├── Containerfile         # StageX-based reproducible build recipe
├── Makefile              # build / run / debug targets
├── proxy/                # Host-side TCP↔VSOCK forwarder
│   ├── main.go
│   └── go.mod
└── out/                  # Build output (gitignored)
    ├── nitro.eif         # The enclave image
    ├── nitro.pcrs        # SHA-384 PCRs (anchor these on-chain)
    └── rootfs.cpio       # Intermediate artifact
```

## Building

Building requires Linux + Docker. macOS works through Docker Desktop with the linux/amd64 platform flag (slow on Apple Silicon — ~10 min first build).

```sh
cd enclave
make            # ./out/nitro.eif and ./out/nitro.pcrs
make pcrs       # print the PCR values once built
```

The build is hermetic: same git tree → byte-identical EIF → identical PCRs. **Anyone running `make` on a clean checkout should get the same PCRs** as the operator. This is how downstream consumers verify they're talking to the right enclave image.

If you don't get identical PCRs, the build is non-deterministic and that's a bug — usually a stray timestamp, file mode, or a non-pinned base image.

## Running on EC2 Nitro

Prerequisites on the host:
- Amazon Linux 2 / 2023 with `aws-nitro-enclaves-cli` installed
- `nitro-enclaves-allocator` service running
- The host EC2 instance type supports Nitro (`c5.xlarge` or larger, `m5.xlarge`, etc.)
- Enclave allocator configured to reserve CPU + memory

```sh
# Copy the EIF to the host
scp out/nitro.eif ec2-user@HOST:~/attestation/

# On the host
sudo nitro-cli run-enclave \
    --cpu-count 2 \
    --memory 512 \
    --eif-path ~/attestation/nitro.eif
sudo nitro-cli describe-enclaves          # note the EnclaveCID
```

Then start the host-side TCP↔VSOCK proxy and point the world at it:

```sh
cd enclave/proxy
go run . --vsock-cid <ENCLAVE_CID> --vsock-port 3000 --tcp 0.0.0.0:8080
```

Now `curl http://HOST:8080/health` reaches the enclave's HTTP server.

For debug mode (console output streamed back to the host):

```sh
make run-debug
```

## HTTP surface

The in-enclave server exposes:

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness check. Reports supported attestation sources. |
| `GET /attestation` | Fresh NSM attestation document for this enclave. Used to register the enclave on-chain via `kagi`. |
| `POST /attest/apple/attestation` | Verify an Apple App Attest one-time hardware proof. Returns a BCS-encoded outcome wrapped inside a fresh NSM document. |
| `POST /attest/apple/assertion` | Verify an Apple App Attest per-payload assertion against a previously-attested public key. Same NSM-wrapped outcome shape. |
| `POST /attest/android/attestation` | Verify an Android Key Attestation X.509 chain (TEE / StrongBox). Decodes the KeyMint `KeyDescription` extension, validates against Google's pinned attestation roots, applies the requested security-level / verified-boot policy. |

Every verification response carries its own freshly-generated NSM attestation document. That means the Move side never trusts a long-lived enclave signature — each on-chain verify call re-checks PCR0/PCR1/PCR2 and the AWS Nitro root signature for this specific response. That's "maximum on-chain checking" by design.

## On-chain registration

After building, the file `out/nitro.pcrs` contains PCR0/PCR1/PCR2 — these identify the exact image. Registering the enclave is done with [`kagi`](https://github.com/unconfirmedlabs/kagi):

1. Boot the enclave on a Nitro host.
2. Fetch a Nitro attestation document: `curl http://HOST:8080/attestation > nsm.bin`.
3. Use kagi to create an immutable `Policy` object on Sui bound to PCR0/1/2 from `nsm.bin`. Downstream Move packages (`attest_apple::attestation`, `attest_apple::assertion`) accept a `&Policy` argument and reject any NSM document whose PCRs don't match.

The PCR-pinned policy is what makes the trust chain meaningful: only an enclave built from this exact source tree can produce an NSM document a registered policy accepts.

A reference deploy lives in [`../deployments/testnet.json`](../deployments/testnet.json) — `policy.id` is the live Sui object, `policy.pcr0..pcr2` are the values its enclaves must report.

## What this image deliberately does not include

- **No outbound HTTP** — the attestation flow is pure compute. No calls to Apple, NXP, or anywhere else.
- **No long-lived signing keys** — every response includes a fresh NSM-signed attestation document. There is no enclave Ed25519 keypair to "lose" or rotate.
- **No persistent storage** — the enclave is stateless. Boot, serve, shut down: nothing carries over.
- **No logging to disk** — stdout only, drained by `nitro-cli console`.
- **No shell** — the only entry point is `nit.target=/enclave-server`, the binary runs as PID 1.

## Verifying PCRs from outside

To prove that a deployed enclave is running the source in this repo:

```sh
# 1. On the deployed host
sudo nitro-cli describe-enclaves --metadata | jq '.[].Measurements'

# 2. On any machine with the source
cd enclave && make pcrs

# 3. Compare PCR0/PCR1/PCR2 — they must match exactly.
```

The PCRs only match if (a) the host is running our EIF, (b) the EIF was built from this commit, (c) the build was reproducible. All three together are what makes the trust chain meaningful.
