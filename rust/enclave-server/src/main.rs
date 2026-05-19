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
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
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
        .route("/attest/apple", post(attest_apple))
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
/// which provides the `ip` command.
fn setup_loopback() {
    use std::process::Command;
    let _ = Command::new("busybox")
        .args(["ip", "addr", "add", "127.0.0.1/8", "dev", "lo"])
        .status();
    let _ = Command::new("busybox")
        .args(["ip", "link", "set", "dev", "lo", "up"])
        .status();
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

#[cfg(target_os = "linux")]
async fn attestation_doc(
    State(state): State<AppState>,
) -> Result<Json<AttestationDoc>, (StatusCode, Json<serde_json::Value>)> {
    use aws_nitro_enclaves_nsm_api::api::{Request, Response};
    use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request};

    let fd = nsm_init();
    if fd < 0 {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "nsm_init failed (not running inside a Nitro Enclave?)"
            })),
        ));
    }

    let pk_bytes = state.verifying_key.to_bytes().to_vec();

    let request = Request::Attestation {
        public_key: Some(pk_bytes.into()),
        user_data: None,
        nonce: None,
    };
    let response = nsm_process_request(fd, request);

    match response {
        Response::Attestation { document } => Ok(Json(AttestationDoc {
            document_hex: hex::encode(document),
        })),
        other => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("unexpected NSM response: {:?}", other)
            })),
        )),
    }
}

#[cfg(not(target_os = "linux"))]
async fn attestation_doc(
    State(_state): State<AppState>,
) -> Result<Json<AttestationDoc>, (StatusCode, Json<serde_json::Value>)> {
    Err((
        StatusCode::NOT_IMPLEMENTED,
        Json(serde_json::json!({
            "error": "/attestation is only available on Linux (Nitro Enclave host)"
        })),
    ))
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

/// The payload signed inside the kagi `IntentMessage<P>` wrapper for
/// Apple App Attest. Field order must match the Move struct in
/// `attest_apple::attest::ApplePayload` exactly (BCS is order-sensitive).
#[derive(serde::Serialize)]
struct ApplePayload {
    attested_value: Vec<u8>,
    challenge: Vec<u8>,
    detail_hash: Vec<u8>,
}

/// Mirror of `kagi::enclave::IntentMessage<P>`.
#[derive(serde::Serialize)]
struct IntentMessage<P: serde::Serialize> {
    intent: u8,
    timestamp_ms: u64,
    payload: P,
}

/// Intent scope byte for Apple App Attest attestation outcomes.
/// Mirror of `attest_apple::attest::INTENT_APPLE_APP_ATTEST`.
const INTENT_APPLE_APP_ATTEST: u8 = 0;

#[derive(Serialize)]
struct AttestResponse {
    /// Caller passes these fields back to `attest_apple::verify` on-chain;
    /// the Move package reconstructs the same `IntentMessage<ApplePayload>`,
    /// BCS-serializes, and verifies the signature against `Enclave.pk`.
    attested_value_hex: String,
    challenge_hex: String,
    detail_hash_hex: String,
    timestamp_ms: u64,
    signature_hex: String,
    /// Enclave's Ed25519 public key (informational; same as /health).
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
}

impl IntoResponse for AttestError {
    fn into_response(self) -> axum::response::Response {
        let body = serde_json::json!({ "error": self.to_string() });
        (StatusCode::BAD_REQUEST, Json(body)).into_response()
    }
}

async fn attest_apple(
    State(state): State<AppState>,
    Json(req): Json<AppleRequest>,
) -> Result<Json<AttestResponse>, AttestError> {
    let attestation_object = hex::decode(&req.attestation_object_hex)
        .map_err(|e| AttestError::InvalidHex("attestation_object_hex", e))?;
    let key_id =
        hex::decode(&req.key_id_hex).map_err(|e| AttestError::InvalidHex("key_id_hex", e))?;
    let challenge = hex::decode(&req.challenge_hex)
        .map_err(|e| AttestError::InvalidHex("challenge_hex", e))?;

    let clock_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let outcome: Outcome = attest_apple::verify_app_attest(
        &attestation_object,
        &key_id,
        &challenge,
        &req.app_id,
        req.production,
        clock_ms,
    )?;

    // Wrap in a kagi IntentMessage<ApplePayload> and sign the BCS bytes.
    let payload = ApplePayload {
        attested_value: outcome.attested_value.clone(),
        challenge: outcome.challenge.clone(),
        detail_hash: outcome.detail_hash.clone(),
    };
    let intent = IntentMessage {
        intent: INTENT_APPLE_APP_ATTEST,
        timestamp_ms: outcome.timestamp_ms,
        payload,
    };
    let intent_bytes = bcs::to_bytes(&intent)?;
    let sig = state.signing_key.sign(&intent_bytes);

    Ok(Json(AttestResponse {
        attested_value_hex: hex::encode(&outcome.attested_value),
        challenge_hex: hex::encode(&outcome.challenge),
        detail_hash_hex: hex::encode(&outcome.detail_hash),
        timestamp_ms: outcome.timestamp_ms,
        signature_hex: hex::encode(sig.to_bytes()),
        public_key_hex: hex::encode(state.verifying_key.to_bytes()),
    }))
}
