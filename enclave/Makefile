REGISTRY := local

.DEFAULT_GOAL := default
.PHONY: default
default: out/nitro.eif

# Build context is the repo root (one level up) so the Containerfile can
# COPY the whole workspace (Cargo.toml + rust/*).
out:
	mkdir -p out

out/nitro.eif: $(shell cd .. && git ls-files | sed 's|^|../|') | out
	cd .. && docker build \
		--pull \
		--tag $(REGISTRY)/attestation-enclave \
		--progress=plain \
		--platform linux/amd64 \
		--provenance=false \
		--output type=local,rewrite-timestamp=true,dest=enclave/out \
		-f enclave/Containerfile \
		.

.PHONY: run
run: out/nitro.eif
	sudo nitro-cli \
		run-enclave \
		--cpu-count 2 \
		--memory 512 \
		--eif-path out/nitro.eif

.PHONY: run-debug
run-debug: out/nitro.eif
	sudo nitro-cli \
		run-enclave \
		--cpu-count 2 \
		--memory 512 \
		--eif-path out/nitro.eif \
		--debug-mode \
		--attach-console

.PHONY: pcrs
pcrs: out/nitro.eif
	@cat out/nitro.pcrs

.PHONY: clean
clean:
	rm -rf out

.PHONY: dev
dev:
	cd .. && RUST_LOG=info cargo run -p enclave-server
