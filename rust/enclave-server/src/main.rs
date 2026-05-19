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
        .route("/attest/apple", post(attest_apple))
        .with_state(state);

    let bind = std::env::var("ENCLAVE_BIND").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let addr: SocketAddr = bind.parse()?;
    info!("listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
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

// ---------- /attest/apple ----------

#[derive(Deserialize)]
struct AppleRequest {
    attestation_object_hex: String,
    key_id_hex: String,
    challenge_hex: String,
    app_id: String,
    production: bool,
}

#[derive(Serialize)]
struct AttestResponse {
    /// BCS-encoded `attestation_core::Outcome`. The Move side BCS-decodes
    /// this and treats the result as the verified attestation outcome.
    outcome_hex: String,
    /// Ed25519 signature over the raw BCS bytes of the outcome.
    signature_hex: String,
    /// The enclave's Ed25519 public key. Same as `/health.public_key_hex`,
    /// included here for client convenience.
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

    let outcome_bytes = outcome.to_bcs()?;
    let sig = state.signing_key.sign(&outcome_bytes);

    Ok(Json(AttestResponse {
        outcome_hex: hex::encode(&outcome_bytes),
        signature_hex: hex::encode(sig.to_bytes()),
        public_key_hex: hex::encode(state.verifying_key.to_bytes()),
    }))
}
