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

## On-chain registration

After building, the file `out/nitro.pcrs` contains PCR0/PCR1/PCR2 — these identify the exact image. To register the enclave on Sui:

1. Capture PCR0/1/2 from `out/nitro.pcrs`.
2. Boot the enclave; fetch the Nitro attestation document from `GET /attestation` (todo: add this endpoint).
3. Submit an on-chain tx that:
   - Calls `0x2::nitro_attestation::load_nitro_attestation` to parse + verify the doc
   - Creates an `Enclave<ATTESTATION>` object (or equivalent) bound to the verified PCRs and the enclave's Ed25519 public key
4. Downstream Move packages (`attest_apple`, etc.) reference this enclave object when verifying outcomes.

This wiring lands in a follow-up commit once the in-enclave NSM attestation flow is added to `enclave-server`.

## What this image deliberately does not include

- **No outbound HTTP** — the attestation flow is pure compute. No calls to Apple, NXP, or anywhere else.
- **No persistent storage** — each enclave generates a fresh Ed25519 keypair on boot. (Future: derive the key deterministically from NSM attestation so it survives restarts without leaving the enclave.)
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
