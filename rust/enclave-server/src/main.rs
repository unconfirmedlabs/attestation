//! Reference enclave server for the `unconfirmedlabs/attestation` family.
//!
//! Exposes an HTTP interface over which clients submit raw platform
//! attestations (Apple App Attest today; Android Key Attestation and NTAG 424
//! to follow). The server verifies the attestation using the corresponding
//! `attest-*` crate, then serializes the resulting [`Outcome`] in BCS and
//! signs it with an Ed25519 key. The client takes those bytes on-chain;
//! Move-side code verifies the Ed25519 signature against the enclave's
//! public key and emits a typed `Witness<Source>`.
//!
//! Boot-time behaviour:
//!   * Generates a fresh Ed25519 keypair (later: replaced by an enclave-pinned
//!     key derived from NSM attestation).
//!   * Binds to `127.0.0.1:3000` by default; override with `ENCLAVE_BIND`.
//!
//! Endpoints:
//!   * `GET  /health`       — returns the enclave's Ed25519 public key.
//!   * `POST /attest/apple` — verifies Apple App Attest, returns signed Outcome.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

use attestation_core::Outcome;

#[derive(Clone)]
struct AppState {
    signing_key: Arc<SigningKey>,
    verifying_key: VerifyingKey,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,enclave_server=debug".into()),
        )
        .init();

    let in_enclave = std::path::Path::new("/dev/vsock").exists();
    if in_enclave {
        setup_loopback();
        // Bridge VSOCK:3000 → TCP 127.0.0.1:3000 so axum can use its
        // standard TCP listener. Bytes arriving from the host-side proxy
        // come in over VSOCK; this task copies them onto local TCP.
        tokio::spawn(vsock_to_tcp_bridge(3000, 3000));
    }

    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    info!(
        "enclave Ed25519 public key: {}",
        hex::encode(verifying_key.to_bytes())
    );

    let state = AppState {
        signing_key: Arc::new(signing_key),
        verifying_key,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/attestation", get(attestation_doc))
        .route("/attest/apple/attestation", post(attest_apple_attestation))
        // Backward-compatible alias for the original endpoint path.
        .route("/attest/apple", post(attest_apple_attestation))
        .route("/attest/apple/assertion", post(attest_apple_assertion))
        .with_state(state);

    let bind = std::env::var("ENCLAVE_BIND").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let addr: SocketAddr = bind.parse()?;
    info!("listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Inside the Nitro enclave, bring up the loopback interface so axum can
/// bind to 127.0.0.1. The enclave's root filesystem includes busybox,
/// which provides the `ip` command. Any failure here is fatal: without
/// loopback, axum can't serve and the enclave is operationally useless.
fn setup_loopback() {
    use std::process::Command;
    let assign = Command::new("busybox")
        .args(["ip", "addr", "add", "127.0.0.1/8", "dev", "lo"])
        .status()
        .expect("busybox ip addr add failed to spawn");
    if !assign.success() {
        panic!(
            "busybox ip addr add 127.0.0.1/8 dev lo: exit {:?}",
            assign.code()
        );
    }
    let up = Command::new("busybox")
        .args(["ip", "link", "set", "dev", "lo", "up"])
        .status()
        .expect("busybox ip link set failed to spawn");
    if !up.success() {
        panic!("busybox ip link set lo up: exit {:?}", up.code());
    }
}

/// Accept VSOCK connections on the given port and shuttle bytes to/from
/// the local TCP port. Each connection runs in its own task. Bytes come
/// in from the host's TCP↔VSOCK proxy; this re-emerges them as a local
/// TCP connection that axum picks up via its standard listener.
async fn vsock_to_tcp_bridge(vsock_port: u32, tcp_port: u16) {
    use tokio_vsock::{VsockAddr, VsockListener, VMADDR_CID_ANY};

    let addr = VsockAddr::new(VMADDR_CID_ANY, vsock_port);
    let listener = match VsockListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("VSOCK bind {vsock_port} failed: {e}");
            return;
        }
    };
    info!("VSOCK:{vsock_port} → TCP:127.0.0.1:{tcp_port} bridge listening");

    let mut incoming = listener;
    loop {
        match incoming.accept().await {
            Ok((mut vsock_stream, _)) => {
                tokio::spawn(async move {
                    match tokio::net::TcpStream::connect(("127.0.0.1", tcp_port)).await {
                        Ok(mut tcp_stream) => {
                            let _ = tokio::io::copy_bidirectional(
                                &mut vsock_stream,
                                &mut tcp_stream,
                            )
                            .await;
                        }
                        Err(e) => tracing::warn!(
                            "TCP connect 127.0.0.1:{tcp_port} failed: {e}"
                        ),
                    }
                });
            }
            Err(e) => tracing::warn!("VSOCK accept error: {e}"),
        }
        // Keep `incoming` borrowed; silence the unused-assignment lint by
        // touching it explicitly. (Without this, `incoming` is moved.)
        let _ = &mut incoming;
    }
}

// ---------- /health ----------

#[derive(Serialize)]
struct Health {
    public_key_hex: String,
    version: &'static str,
    sources: &'static [&'static str],
}

async fn health(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        public_key_hex: hex::encode(state.verifying_key.to_bytes()),
        version: env!("CARGO_PKG_VERSION"),
        sources: &[attestation_core::sources::APPLE_APP_ATTEST],
    })
}

// ---------- /attestation ----------

#[derive(Serialize)]
struct AttestationDoc {
    /// Hex-encoded CBOR (COSE_Sign1) NSM attestation document. Submit on-chain
    /// via `0x2::nitro_attestation::load_nitro_attestation` then pass to
    /// `kagi::enclave::new` to register this enclave under a policy.
    document_hex: String,
}

async fn attestation_doc(
    State(state): State<AppState>,
) -> Result<Json<AttestationDoc>, (StatusCode, Json<serde_json::Value>)> {
    // Boot-time / registration attestation: bind the enclave's pk, no
    // user_data (this doc isn't tied to any specific attestation payload).
    let doc = request_nsm_attestation(state.verifying_key.to_bytes().to_vec(), vec![])
        .map_err(|e| {
            let code = match e {
                AttestError::NsmInit => StatusCode::NOT_IMPLEMENTED,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (code, Json(serde_json::json!({ "error": e.to_string() })))
        })?;
    Ok(Json(AttestationDoc {
        document_hex: hex::encode(doc),
    }))
}

// ---------- /attest/apple ----------

#[derive(Deserialize)]
struct AppleRequest {
    attestation_object_hex: String,
    key_id_hex: String,
    challenge_hex: String,
    app_id: String,
    production: bool,
}

/// The payload that's hashed into the NSM doc's `user_data` field.
/// Field order must match the Move struct in `attest_apple::attest::ApplePayload`
/// exactly (BCS is order-sensitive).
#[derive(serde::Serialize)]
struct ApplePayload {
    attested_value: Vec<u8>,
    challenge: Vec<u8>,
    detail_hash: Vec<u8>,
}

#[derive(Serialize)]
struct AttestResponse {
    /// Raw Nitro attestation document (CBOR / COSE_Sign1). Caller passes
    /// this to `0x2::nitro_attestation::load_nitro_attestation` and then
    /// to `attest_apple::attest::verify` in the same PTB. AWS-Nitro-signed;
    /// the doc's `timestamp` is the freshness anchor (unspoofable), and
    /// its `user_data` is SHA-256(BCS(ApplePayload)) — binds it to the
    /// payload fields below.
    nsm_doc_hex: String,
    attested_value_hex: String,
    challenge_hex: String,
    detail_hash_hex: String,
    /// Enclave's Ed25519 public key (informational; same as /health).
    /// On the per-request path the on-chain check uses this only via the
    /// NSM doc's `public_key` field, not for any signature verify here.
    public_key_hex: String,
}

#[derive(Debug, thiserror::Error)]
enum AttestError {
    #[error("invalid hex in field `{0}`: {1}")]
    InvalidHex(&'static str, hex::FromHexError),
    #[error("attest-apple verify failed: {0}")]
    VerifyFailed(#[from] attest_apple::Error),
    #[error("bcs encode failed: {0}")]
    Bcs(#[from] bcs::Error),
    #[error("NSM init failed (not running inside a Nitro enclave?)")]
    NsmInit,
    #[error("NSM request failed: {0}")]
    Nsm(String),
}

impl IntoResponse for AttestError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({ "error": self.to_string() });
        (StatusCode::BAD_REQUEST, Json(body)).into_response()
    }
}

async fn attest_apple_attestation(
    State(state): State<AppState>,
    Json(req): Json<AppleRequest>,
) -> Result<Json<AttestResponse>, AttestError> {
    let attestation_object = hex::decode(&req.attestation_object_hex)
        .map_err(|e| AttestError::InvalidHex("attestation_object_hex", e))?;
    let key_id =
        hex::decode(&req.key_id_hex).map_err(|e| AttestError::InvalidHex("key_id_hex", e))?;
    let challenge = hex::decode(&req.challenge_hex)
        .map_err(|e| AttestError::InvalidHex("challenge_hex", e))?;

    // The wall clock inside the enclave is spoofable by the parent EC2
    // host. We don't use it for the signed timestamp — that comes from
    // the NSM doc below, which is signed by AWS Nitro and unspoofable.
    // We still pass a clock value to attest-apple (used only for
    // `Outcome.timestamp_ms`, which we don't surface in the response).
    let stamp_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let outcome: Outcome = attest_apple::verify_app_attest(
        &attestation_object,
        &key_id,
        &challenge,
        &req.app_id,
        req.production,
        stamp_ms,
    )?;

    // Bind the NSM doc to this exact payload. user_data = SHA-256(BCS(payload)).
    let payload = ApplePayload {
        attested_value: outcome.attested_value.clone(),
        challenge: outcome.challenge.clone(),
        detail_hash: outcome.detail_hash.clone(),
    };
    let payload_bcs = bcs::to_bytes(&payload)?;
    let payload_hash: [u8; 32] = Sha256::digest(&payload_bcs).into();

    let nsm_doc = request_nsm_attestation(
        state.verifying_key.to_bytes().to_vec(),
        payload_hash.to_vec(),
    )?;

    Ok(Json(AttestResponse {
        nsm_doc_hex: hex::encode(&nsm_doc),
        attested_value_hex: hex::encode(&outcome.attested_value),
        challenge_hex: hex::encode(&outcome.challenge),
        detail_hash_hex: hex::encode(&outcome.detail_hash),
        public_key_hex: hex::encode(state.verifying_key.to_bytes()),
    }))
}

/// Request a Nitro attestation document binding the enclave's public key
/// to the given `user_data`. The returned bytes are the raw CBOR/COSE_Sign1
/// document signed by AWS Nitro. The on-chain `nitro_attestation` module
/// verifies the AWS signature; we treat the returned bytes as opaque.
#[cfg(target_os = "linux")]
fn request_nsm_attestation(
    public_key: Vec<u8>,
    user_data: Vec<u8>,
) -> Result<Vec<u8>, AttestError> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request};
    let fd = nsm_init();
    if fd < 0 {
        return Err(AttestError::NsmInit);
    }
    let req = Request::Attestation {
        public_key: Some(public_key.into()),
        user_data: Some(user_data.into()),
        nonce: None,
    };
    match nsm_process_request(fd, req) {
        Response::Attestation { document } => Ok(document),
        other => Err(AttestError::Nsm(format!("unexpected NSM response: {:?}", other))),
    }
}

#[cfg(not(target_os = "linux"))]
fn request_nsm_attestation(
    _public_key: Vec<u8>,
    _user_data: Vec<u8>,
) -> Result<Vec<u8>, AttestError> {
    Err(AttestError::NsmInit)
}

// ---------- /attest/apple/assertion ----------

/// Mirror of Move's `attest_apple::assertion::AssertionPayload`. Field
/// order is significant — must BCS-encode identically to the Move struct.
#[derive(serde::Serialize)]
struct AssertionPayload {
    attested_key: Vec<u8>,
    client_data: Vec<u8>,
}

#[derive(Deserialize)]
struct AppleAssertionRequest {
    /// CBOR bytes returned by `DCAppAttestService.generateAssertion`.
    assertion_object_hex: String,
    /// The exact bytes the SE key signed (the iOS app hashed these with
    /// SHA-256 and passed as `clientDataHash`).
    client_data_hex: String,
    /// The previously-attested SE public key (P-256 X9.63 uncompressed,
    /// 65 B). The caller is responsible for ensuring this pk was attested
    /// via a prior `attest_apple::attestation::verify` call.
    attested_key_hex: String,
    /// `"<teamID>.<bundleID>"` of the app — same value passed at
    /// attestation time. The assertion's `rpIdHash` must equal
    /// `SHA-256(app_id)`.
    app_id: String,
}

#[derive(Serialize)]
struct AssertionResponse {
    nsm_doc_hex: String,
    attested_key_hex: String,
    client_data_hex: String,
    public_key_hex: String,
}

async fn attest_apple_assertion(
    State(state): State<AppState>,
    Json(req): Json<AppleAssertionRequest>,
) -> Result<Json<AssertionResponse>, AttestError> {
    let assertion_object = hex::decode(&req.assertion_object_hex)
        .map_err(|e| AttestError::InvalidHex("assertion_object_hex", e))?;
    let client_data = hex::decode(&req.client_data_hex)
        .map_err(|e| AttestError::InvalidHex("client_data_hex", e))?;
    let attested_key = hex::decode(&req.attested_key_hex)
        .map_err(|e| AttestError::InvalidHex("attested_key_hex", e))?;

    let stamp_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // Run the off-chain assertion verifier (CBOR + ECDSA verify against pk).
    let outcome: Outcome = attest_apple::verify_assertion(
        &assertion_object,
        &client_data,
        &attested_key,
        &req.app_id,
        stamp_ms,
    )?;

    // Bind a fresh NSM doc to the (attested_key, client_data) pair.
    let payload = AssertionPayload {
        attested_key: outcome.attested_value.clone(),
        client_data: outcome.challenge.clone(),
    };
    let payload_bcs = bcs::to_bytes(&payload)?;
    let payload_hash: [u8; 32] = Sha256::digest(&payload_bcs).into();
    let nsm_doc = request_nsm_attestation(
        state.verifying_key.to_bytes().to_vec(),
        payload_hash.to_vec(),
    )?;

    Ok(Json(AssertionResponse {
        nsm_doc_hex: hex::encode(&nsm_doc),
        attested_key_hex: hex::encode(&outcome.attested_value),
        client_data_hex: hex::encode(&outcome.challenge),
        public_key_hex: hex::encode(state.verifying_key.to_bytes()),
    }))
}
