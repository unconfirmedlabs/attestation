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
//!   * `GET  /health`                       — enclave Ed25519 public key + supported sources.
//!   * `GET  /attestation`                  — fresh NSM doc binding the enclave pk (registration).
//!   * `POST /attest/apple/attestation`     — Apple App Attest one-time hardware proof.
//!   * `POST /attest/apple/assertion`       — Apple App Attest per-payload assertion.
//!   * `POST /attest/android/attestation`   — Android Key Attestation chain.

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

    let app = app(state);

    let bind = std::env::var("ENCLAVE_BIND").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let addr: SocketAddr = bind.parse()?;
    info!("listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

/// Build the application router with all attestation routes wired to `state`.
///
/// Extracted from `main` so tests can drive the exact same route table
/// in-process via `tower::ServiceExt::oneshot`, without binding a socket
/// or entering a real Nitro enclave. Production startup and tests share
/// this single definition, so route/handler drift can't slip past tests.
fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/attestation", get(attestation_doc))
        .route("/attest/apple/attestation", post(attest_apple_attestation))
        // Backward-compatible alias for the original endpoint path.
        .route("/attest/apple", post(attest_apple_attestation))
        .route("/attest/apple/assertion", post(attest_apple_assertion))
        .route("/attest/android/attestation", post(attest_android_attestation))
        .route("/attest/android", post(attest_android_attestation))
        .with_state(state)
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
        sources: &[
            attestation_core::sources::APPLE_APP_ATTEST,
            attestation_core::sources::APPLE_APP_ATTEST_ASSERTION,
            attestation_core::sources::ANDROID_KEY_ATTEST,
        ],
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
    #[error("attest-android verify failed: {0}")]
    AndroidVerifyFailed(#[from] attest_android::Error),
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

// ---------- /attest/android ----------

#[derive(Deserialize)]
struct AndroidRequest {
    /// X.509 chain, leaf first. Each entry is hex-encoded DER.
    chain_hex: Vec<String>,
    /// Hex-encoded challenge bytes the leaf's `attestationChallenge`
    /// must equal exactly.
    challenge_hex: String,
    /// Minimum security level: `"software"`, `"tee"`, or `"strongbox"`.
    /// Defaults to `"tee"` when omitted.
    #[serde(default)]
    min_security_level: Option<String>,
    /// Require `verifiedBootState = Verified` (GREEN). Default `true`.
    #[serde(default = "default_true")]
    require_verified_boot: bool,
    /// Require `rootOfTrust.deviceLocked = true`. Default `true`.
    #[serde(default = "default_true")]
    require_device_locked: bool,
    /// Optional list of hex-encoded `verifiedBootKey` values to allow
    /// when boot state is YELLOW (SelfSigned) — i.e., locked with a
    /// user-installed key like GrapheneOS. Ignored when
    /// `require_verified_boot = true`.
    #[serde(default)]
    allowed_self_signed_keys_hex: Vec<String>,
    /// Optional Google `/attestation/status` JSON. If supplied, every
    /// serial in the chain is checked.
    #[serde(default)]
    status_list_json: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Mirror of Move's `attest_android::attestation::AndroidPayload`. Field
/// order must match the Move struct exactly (BCS is order-sensitive).
#[derive(serde::Serialize)]
struct AndroidPayload {
    attested_value: Vec<u8>,
    challenge: Vec<u8>,
    detail_hash: Vec<u8>,
}

#[derive(Serialize)]
struct AndroidResponse {
    nsm_doc_hex: String,
    /// DER-encoded `subjectPublicKeyInfo` of the attested key.
    attested_value_hex: String,
    challenge_hex: String,
    detail_hash_hex: String,
    public_key_hex: String,
}

async fn attest_android_attestation(
    State(state): State<AppState>,
    Json(req): Json<AndroidRequest>,
) -> Result<Json<AndroidResponse>, AttestError> {
    let chain: Vec<Vec<u8>> = req
        .chain_hex
        .iter()
        .enumerate()
        .map(|(i, h)| {
            hex::decode(h).map_err(|e| {
                AttestError::InvalidHex(Box::leak(format!("chain[{i}]").into_boxed_str()), e)
            })
        })
        .collect::<Result<_, _>>()?;
    let challenge = hex::decode(&req.challenge_hex)
        .map_err(|e| AttestError::InvalidHex("challenge_hex", e))?;

    let min_level = parse_security_level(req.min_security_level.as_deref())?;

    let allowed_keys: Vec<Vec<u8>> = req
        .allowed_self_signed_keys_hex
        .iter()
        .enumerate()
        .map(|(i, h)| {
            hex::decode(h).map_err(|e| {
                AttestError::InvalidHex(
                    Box::leak(format!("allowed_self_signed_keys_hex[{i}]").into_boxed_str()),
                    e,
                )
            })
        })
        .collect::<Result<_, _>>()?;

    let status_list = match req.status_list_json.as_deref() {
        Some(json) => Some(attest_android::StatusList::from_json(json)?),
        None => None,
    };

    let policy = attest_android::Policy {
        min_security_level: min_level,
        require_verified_boot: req.require_verified_boot,
        allowed_self_signed_keys: &allowed_keys,
        require_device_locked: req.require_device_locked,
        status_list: status_list.as_ref(),
    };

    let stamp_ms: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    let outcome: Outcome =
        attest_android::verify_attestation(&chain, &challenge, &policy, stamp_ms)?;

    let payload = AndroidPayload {
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

    Ok(Json(AndroidResponse {
        nsm_doc_hex: hex::encode(&nsm_doc),
        attested_value_hex: hex::encode(&outcome.attested_value),
        challenge_hex: hex::encode(&outcome.challenge),
        detail_hash_hex: hex::encode(&outcome.detail_hash),
        public_key_hex: hex::encode(state.verifying_key.to_bytes()),
    }))
}

fn parse_security_level(s: Option<&str>) -> Result<attest_android::SecurityLevel, AttestError> {
    use attest_android::SecurityLevel;
    Ok(match s.unwrap_or("tee") {
        "software" => SecurityLevel::Software,
        "tee" | "trustedenvironment" | "trusted_environment" => SecurityLevel::TrustedEnvironment,
        "strongbox" => SecurityLevel::StrongBox,
        other => {
            return Err(AttestError::Nsm(format!(
                "unknown min_security_level '{other}' (want software|tee|strongbox)"
            )));
        }
    })
}

// ============================================================================
// Tests
// ============================================================================
//
// These live in-crate (not under `tests/`) on purpose: `enclave-server` is a
// *binary* with no `[lib]`, so an external integration-test crate can neither
// `use` the private handlers nor reach the `app()` router builder. A `#[cfg(test)]`
// module is the only place that can drive the real route table in-process.
//
// Strategy:
//   * Routing / framework behaviour (404, 405, /health, route aliases) and ALL
//     input-validation error paths are exercised against the real `app()` router
//     via `tower::ServiceExt::oneshot` — no socket, no enclave.
//   * The NSM-backed `/attestation` path is testable off-enclave: the non-Linux
//     (and Linux-without-/dev/nsm) stub returns `AttestError::NsmInit`, which the
//     handler maps to HTTP 501. We assert that mapping.
//   * The Outcome → per-platform `Payload` → BCS → SHA-256 binding seam (the part
//     of each attest handler that runs *before* the NSM call) is verified directly
//     against the verifier crates using the real sibling fixtures, with a clock
//     pinned inside the fixtures' certificate-validity windows.
//   * The Ed25519 signing seam is exercised independently (sign/verify a BCS
//     `Outcome`), since the per-request handlers don't surface a signature today.
//
// OUT OF SCOPE — requires a real AWS Nitro enclave, cannot run under `cargo test`:
//   * A 2xx response from `/attest/apple*`, `/attest/android*`, or `/attestation`.
//     Each calls `request_nsm_attestation`, which talks to `/dev/nsm`; off-enclave
//     that returns `NsmInit`. The handlers also stamp time via `SystemTime::now()`
//     with no injection seam, so even a fresh (non-expired) fixture would still
//     fail at the NSM boundary. The success path up to that boundary is covered by
//     the binding-seam tests below.
//   * `setup_loopback()` / `vsock_to_tcp_bridge()` — enclave-only networking.
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Method, Request, StatusCode};
    use http_body_util::BodyExt;
    use std::fs;
    use tower::ServiceExt; // for `oneshot`

    // ---- harness -----------------------------------------------------------

    /// A deterministic router with a fixed-seed-free fresh keypair. We only
    /// need *a* valid Ed25519 key; tests that care about the key read it back
    /// from the state.
    fn test_state() -> AppState {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        AppState {
            signing_key: Arc::new(signing_key),
            verifying_key,
        }
    }

    fn router() -> Router {
        app(test_state())
    }

    /// Send one request through the real router and return (status, json body).
    async fn send(req: Request<Body>) -> (StatusCode, serde_json::Value) {
        let resp = router().oneshot(req).await.expect("router responds");
        let status = resp.status();
        let bytes = resp
            .into_body()
            .collect()
            .await
            .expect("collect body")
            .to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    /// POST `body` (a serde_json value) as `application/json` to `path`.
    fn post_json(path: &str, body: serde_json::Value) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    }

    /// POST raw bytes as `application/json` (for deliberately-malformed bodies).
    fn post_raw(path: &str, raw: impl Into<Body>) -> Request<Body> {
        Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(raw.into())
            .unwrap()
    }

    fn get(path: &str) -> Request<Body> {
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    // ---- /health -----------------------------------------------------------

    #[tokio::test]
    async fn health_ok_shape() {
        let (status, body) = send(get("/health")).await;
        assert_eq!(status, StatusCode::OK);

        let pk = body["public_key_hex"].as_str().expect("public_key_hex");
        assert_eq!(pk.len(), 64, "32-byte Ed25519 pk as hex");
        assert!(hex::decode(pk).is_ok(), "pk hex decodes");

        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));

        let sources = body["sources"].as_array().expect("sources array");
        let names: Vec<&str> = sources.iter().map(|s| s.as_str().unwrap()).collect();
        assert_eq!(
            names,
            vec![
                attestation_core::sources::APPLE_APP_ATTEST,
                attestation_core::sources::APPLE_APP_ATTEST_ASSERTION,
                attestation_core::sources::ANDROID_KEY_ATTEST,
            ]
        );
    }

    #[tokio::test]
    async fn health_public_key_matches_state() {
        // The /health pk must be exactly the verifying key in app state.
        let state = test_state();
        let expected = hex::encode(state.verifying_key.to_bytes());
        let resp = app(state).oneshot(get("/health")).await.unwrap();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["public_key_hex"], expected);
    }

    // ---- routing: unknown route / wrong method -----------------------------

    #[tokio::test]
    async fn unknown_route_is_404() {
        let (status, _) = send(get("/does/not/exist")).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn wrong_method_on_post_route_is_405() {
        // GET on a POST-only route → axum returns 405 Method Not Allowed.
        let (status, _) = send(get("/attest/apple/attestation")).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn wrong_method_on_get_route_is_405() {
        // POST on a GET-only route → 405.
        let (status, _) = send(post_json("/health", serde_json::json!({}))).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn all_routes_exist_including_aliases() {
        // Each declared route must respond with something other than 404.
        // (Aliases `/attest/apple` and `/attest/android` must resolve.)
        for path in [
            "/attest/apple/attestation",
            "/attest/apple",
            "/attest/apple/assertion",
            "/attest/android/attestation",
            "/attest/android",
        ] {
            // An empty JSON object is missing required fields → 4xx, never 404/405.
            let (status, _) = send(post_json(path, serde_json::json!({}))).await;
            assert_ne!(status, StatusCode::NOT_FOUND, "route {path} should exist");
            assert_ne!(
                status,
                StatusCode::METHOD_NOT_ALLOWED,
                "route {path} should accept POST"
            );
        }
    }

    // ---- /attestation (NSM, off-enclave) -----------------------------------

    #[tokio::test]
    async fn attestation_doc_off_enclave_is_501() {
        // Off a real Nitro enclave, `request_nsm_attestation` returns `NsmInit`,
        // which `attestation_doc` maps to 501 Not Implemented with an error body.
        let (status, body) = send(get("/attestation")).await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
        assert!(
            body["error"].as_str().unwrap_or("").contains("NSM"),
            "error body mentions NSM, got {body:?}"
        );
    }

    // ---- Apple attestation: input validation -------------------------------

    fn apple_body(
        att: &str,
        key_id: &str,
        chal: &str,
        app_id: &str,
        prod: bool,
    ) -> serde_json::Value {
        serde_json::json!({
            "attestation_object_hex": att,
            "key_id_hex": key_id,
            "challenge_hex": chal,
            "app_id": app_id,
            "production": prod,
        })
    }

    #[tokio::test]
    async fn apple_malformed_json_is_rejected_not_panicked() {
        let (status, _) = send(post_raw("/attest/apple/attestation", "{not json")).await;
        // axum's JSON rejection is 400 Bad Request.
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn apple_empty_body_is_rejected() {
        let (status, _) = send(post_raw("/attest/apple/attestation", "")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn apple_missing_field_is_rejected() {
        // Drop `production` → deserialization fails → 4xx (422 from axum).
        let body = serde_json::json!({
            "attestation_object_hex": "00",
            "key_id_hex": "00",
            "challenge_hex": "00",
            "app_id": "team.bundle",
        });
        let (status, _) = send(post_json("/attest/apple/attestation", body)).await;
        assert!(status.is_client_error(), "got {status}");
        assert_ne!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn apple_wrong_field_type_is_rejected() {
        // `production` must be a bool; a string must be rejected by serde.
        let body = serde_json::json!({
            "attestation_object_hex": "00",
            "key_id_hex": "00",
            "challenge_hex": "00",
            "app_id": "team.bundle",
            "production": "yes",
        });
        let (status, _) = send(post_json("/attest/apple/attestation", body)).await;
        assert!(status.is_client_error(), "got {status}");
    }

    #[tokio::test]
    async fn apple_invalid_hex_attestation_object_is_400() {
        // Valid JSON, but `attestation_object_hex` isn't hex → AttestError::InvalidHex
        // → 400 with a field-named error.
        let body = apple_body("zz", "00", "00", "team.bundle", false);
        let (status, json) = send(post_json("/attest/apple/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let err = json["error"].as_str().unwrap_or("");
        assert!(
            err.contains("attestation_object_hex"),
            "error names the bad field, got {err:?}"
        );
    }

    #[tokio::test]
    async fn apple_invalid_hex_key_id_is_400() {
        let body = apple_body("00", "zz", "00", "team.bundle", false);
        let (status, json) = send(post_json("/attest/apple/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json["error"].as_str().unwrap().contains("key_id_hex"));
    }

    #[tokio::test]
    async fn apple_invalid_hex_challenge_is_400() {
        let body = apple_body("00", "00", "zz", "team.bundle", false);
        let (status, json) = send(post_json("/attest/apple/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json["error"].as_str().unwrap().contains("challenge_hex"));
    }

    #[tokio::test]
    async fn apple_garbage_attestation_bytes_is_400_not_panic() {
        // Well-formed hex that isn't a valid attestation object: the CBOR
        // decode inside attest-apple fails → VerifyFailed → 400. The key
        // assertion is *no panic* on attacker-controlled bytes.
        let garbage = hex::encode([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03]);
        let body = apple_body(&garbage, "00", "00", "team.bundle", false);
        let (status, _) = send(post_json("/attest/apple/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn apple_oversized_garbage_is_400_not_panic() {
        // ~64 KiB of valid-hex garbage must be rejected cleanly, not OOM/panic.
        let big = hex::encode(vec![0xAB_u8; 64 * 1024]);
        let body = apple_body(&big, "00", "00", "team.bundle", false);
        let (status, _) = send(post_json("/attest/apple/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn apple_real_fixture_expired_cert_is_400() {
        // The real iPhone fixture's leaf cert is valid only for a 3-day window
        // in May 2026. At the handler's wall clock (SystemTime::now, today), the
        // chain is expired, so attest-apple returns a Der("cert expired") error
        // → VerifyFailed → 400. This proves the handler funnels verifier errors
        // into a clean 400 rather than 500/panic, and documents WHY the success
        // path can't be reached here (see module-level OUT OF SCOPE note).
        let Some(fx) = load_apple_fixture() else {
            // Fixture absent in this checkout — nothing to assert.
            return;
        };
        let body = apple_body(
            &fx.attestation_object_hex,
            &fx.key_id_hex,
            &fx.challenge_hex,
            &fx.app_id,
            fx.production,
        );
        let (status, _) = send(post_json("/attest/apple/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn apple_alias_route_behaves_identically() {
        // `/attest/apple` is a backward-compat alias for `/attest/apple/attestation`.
        let body = apple_body("zz", "00", "00", "team.bundle", false);
        let (a, _) = send(post_json("/attest/apple", body.clone())).await;
        let (b, _) = send(post_json("/attest/apple/attestation", body)).await;
        assert_eq!(a, b);
        assert_eq!(a, StatusCode::BAD_REQUEST);
    }

    // ---- Apple assertion: input validation ---------------------------------

    fn assertion_body(obj: &str, cd: &str, key: &str, app_id: &str) -> serde_json::Value {
        serde_json::json!({
            "assertion_object_hex": obj,
            "client_data_hex": cd,
            "attested_key_hex": key,
            "app_id": app_id,
        })
    }

    #[tokio::test]
    async fn assertion_malformed_json_is_rejected() {
        let (status, _) = send(post_raw("/attest/apple/assertion", "}}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn assertion_missing_field_is_rejected() {
        let body = serde_json::json!({
            "assertion_object_hex": "00",
            "client_data_hex": "00",
            // attested_key_hex missing
            "app_id": "team.bundle",
        });
        let (status, _) = send(post_json("/attest/apple/assertion", body)).await;
        assert!(status.is_client_error());
    }

    #[tokio::test]
    async fn assertion_invalid_hex_each_field_is_400() {
        for (obj, cd, key, field) in [
            ("zz", "00", "00", "assertion_object_hex"),
            ("00", "zz", "00", "client_data_hex"),
            ("00", "00", "zz", "attested_key_hex"),
        ] {
            let body = assertion_body(obj, cd, key, "team.bundle");
            let (status, json) = send(post_json("/attest/apple/assertion", body)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "field {field}");
            assert!(
                json["error"].as_str().unwrap().contains(field),
                "error names {field}"
            );
        }
    }

    #[tokio::test]
    async fn assertion_garbage_cbor_is_400_not_panic() {
        // Valid hex, invalid assertion CBOR → attest-apple Cbor error → 400.
        let garbage = hex::encode([0x00, 0x11, 0x22, 0x33, 0x44]);
        let body = assertion_body(&garbage, "00", "00", "team.bundle");
        let (status, _) = send(post_json("/attest/apple/assertion", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // ---- Android attestation: input validation -----------------------------

    fn android_body(chain: Vec<&str>, chal: &str) -> serde_json::Value {
        serde_json::json!({
            "chain_hex": chain,
            "challenge_hex": chal,
        })
    }

    #[tokio::test]
    async fn android_malformed_json_is_rejected() {
        let (status, _) = send(post_raw("/attest/android/attestation", "nope")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn android_missing_required_field_is_rejected() {
        // `chain_hex` is required (no serde default).
        let body = serde_json::json!({ "challenge_hex": "00" });
        let (status, _) = send(post_json("/attest/android/attestation", body)).await;
        assert!(status.is_client_error());
    }

    #[tokio::test]
    async fn android_invalid_hex_in_chain_is_400() {
        let body = android_body(vec!["zz"], "00");
        let (status, json) = send(post_json("/attest/android/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Field name is `chain[0]`.
        assert!(
            json["error"].as_str().unwrap().contains("chain[0]"),
            "got {:?}",
            json["error"]
        );
    }

    #[tokio::test]
    async fn android_invalid_hex_challenge_is_400() {
        let body = android_body(vec!["00"], "zz");
        let (status, json) = send(post_json("/attest/android/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json["error"].as_str().unwrap().contains("challenge_hex"));
    }

    #[tokio::test]
    async fn android_unknown_security_level_is_400() {
        let body = serde_json::json!({
            "chain_hex": ["00"],
            "challenge_hex": "00",
            "min_security_level": "quantum",
        });
        let (status, json) = send(post_json("/attest/android/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let err = json["error"].as_str().unwrap();
        assert!(err.contains("quantum"), "error echoes bad level, got {err:?}");
    }

    #[tokio::test]
    async fn android_bad_status_list_json_is_400() {
        // A non-empty but malformed status_list_json is parsed eagerly and must
        // produce a 400, not a panic.
        let body = serde_json::json!({
            "chain_hex": ["00"],
            "challenge_hex": "00",
            "status_list_json": "{ this is not valid status json }",
        });
        let (status, _) = send(post_json("/attest/android/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn android_invalid_hex_in_allowed_keys_is_400() {
        let body = serde_json::json!({
            "chain_hex": ["00"],
            "challenge_hex": "00",
            "require_verified_boot": false,
            "allowed_self_signed_keys_hex": ["zz"],
        });
        let (status, json) = send(post_json("/attest/android/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("allowed_self_signed_keys_hex[0]"));
    }

    #[tokio::test]
    async fn android_empty_chain_is_400_not_panic() {
        // Empty chain → attest-android EmptyChain → 400. No panic.
        let body = android_body(vec![], "00");
        let (status, _) = send(post_json("/attest/android/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn android_garbage_cert_bytes_is_400_not_panic() {
        let garbage = hex::encode(vec![0xFF_u8; 200]);
        let body = android_body(vec![&garbage], "00");
        let (status, _) = send(post_json("/attest/android/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn android_real_chain_expired_root_is_400() {
        // The Google sample chain's root cert is outside its validity window at
        // today's wall clock, so attest-android rejects it → 400. Documents why
        // the Android success path can't be reached through the handler here.
        let Some(chain_hex) = load_android_chain_hex() else {
            return;
        };
        let refs: Vec<&str> = chain_hex.iter().map(|s| s.as_str()).collect();
        let body = serde_json::json!({
            "chain_hex": refs,
            "challenge_hex": "00",
            "require_verified_boot": false,
            "require_device_locked": false,
        });
        let (status, _) = send(post_json("/attest/android/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn android_defaults_applied_when_optional_fields_absent() {
        // Only required fields present: optional policy knobs must default
        // (require_verified_boot=true etc.) and the request must still reach the
        // verifier (→ 400 on this dummy chain), proving serde defaults parse.
        let body = android_body(vec!["00"], "00");
        let (status, _) = send(post_json("/attest/android/attestation", body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // ---- parse_security_level (unit) ---------------------------------------

    #[test]
    fn parse_security_level_all_aliases() {
        use attest_android::SecurityLevel;
        assert_eq!(parse_security_level(None).unwrap(), SecurityLevel::TrustedEnvironment);
        assert_eq!(
            parse_security_level(Some("software")).unwrap(),
            SecurityLevel::Software
        );
        for tee in ["tee", "trustedenvironment", "trusted_environment"] {
            assert_eq!(
                parse_security_level(Some(tee)).unwrap(),
                SecurityLevel::TrustedEnvironment,
                "alias {tee}"
            );
        }
        assert_eq!(
            parse_security_level(Some("strongbox")).unwrap(),
            SecurityLevel::StrongBox
        );
        assert!(parse_security_level(Some("bogus")).is_err());
    }

    // ---- AttestError → response mapping ------------------------------------

    #[tokio::test]
    async fn attesterror_into_response_is_400_with_error_body() {
        // The blanket `IntoResponse` for AttestError must yield 400 + {"error": ..}.
        let resp = AttestError::InvalidHex(
            "field_x",
            hex::decode("zz").unwrap_err(),
        )
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(json["error"].as_str().unwrap().contains("field_x"));
    }

    #[test]
    fn nsm_init_error_message_is_descriptive() {
        let msg = AttestError::NsmInit.to_string();
        assert!(msg.contains("NSM"));
    }

    // ---- request_nsm_attestation off-enclave -------------------------------

    #[test]
    fn request_nsm_attestation_off_enclave_errors() {
        // On non-Linux this is the stub; on Linux-without-/dev/nsm, nsm_init() < 0.
        // Either way, off a real enclave the call must fail (never return bytes)
        // so callers map it to a 5xx rather than emitting an unsigned doc.
        let r = request_nsm_attestation(vec![0u8; 32], vec![]);
        assert!(r.is_err(), "NSM must be unavailable in the test environment");
    }

    // ========================================================================
    // Binding seam: Outcome → per-platform Payload → BCS → SHA-256
    //
    // This is the deterministic slice of each attest handler that runs *before*
    // the NSM call. We reproduce the handler's exact construction against real
    // fixtures (clock pinned inside the cert validity window) and assert the
    // payload BCS + hash are well-formed and stable. This is the on-chain trust
    // contract the handler binds into NSM `user_data`.
    // ========================================================================

    #[derive(serde::Deserialize)]
    struct AppleFixture {
        attestation_object_hex: String,
        key_id_hex: String,
        challenge_hex: String,
        app_id: String,
        production: bool,
    }

    fn load_apple_fixture() -> Option<AppleFixture> {
        let raw =
            fs::read_to_string("../attest-apple/tests/fixtures/dev_iphone_001.json").ok()?;
        serde_json::from_str(&raw).ok()
    }

    /// Hex-encode the Google sample EC TEE chain (leaf-first) from PEM.
    fn load_android_chain_hex() -> Option<Vec<String>> {
        let mut out = Vec::new();
        for i in 0..4 {
            let path = format!("../attest-android/tests/fixtures/ec_tee_cert{i}.pem");
            let pem_str = fs::read_to_string(&path).ok()?;
            let der = pem::parse(&pem_str).ok()?.into_contents();
            out.push(hex::encode(der));
        }
        Some(out)
    }

    /// Clock pinned inside the Apple fixture leaf's validity window
    /// (notBefore 2026-05-18, notAfter 2026-05-21).
    const APPLE_FIXTURE_CLOCK_MS: u64 = 1_779_203_019_000;

    #[test]
    fn apple_binding_seam_matches_handler() {
        let Some(fx) = load_apple_fixture() else {
            return; // fixture absent
        };
        let attestation_object = hex::decode(&fx.attestation_object_hex).unwrap();
        let key_id = hex::decode(&fx.key_id_hex).unwrap();
        let challenge = hex::decode(&fx.challenge_hex).unwrap();

        // Same verifier the handler runs, but with an in-window clock so the
        // success path is reachable in `cargo test`.
        let outcome = attest_apple::verify_app_attest(
            &attestation_object,
            &key_id,
            &challenge,
            &fx.app_id,
            fx.production,
            APPLE_FIXTURE_CLOCK_MS,
        )
        .expect("Apple fixture verifies at in-window clock");

        assert_eq!(outcome.source, attestation_core::sources::APPLE_APP_ATTEST);
        assert_eq!(outcome.challenge, challenge);
        assert_eq!(outcome.attested_value.len(), 65, "P-256 uncompressed pk");

        // Reproduce the handler's ApplePayload → BCS → SHA-256(user_data).
        let payload = ApplePayload {
            attested_value: outcome.attested_value.clone(),
            challenge: outcome.challenge.clone(),
            detail_hash: outcome.detail_hash.clone(),
        };
        let bcs_bytes = bcs::to_bytes(&payload).expect("bcs encode");
        let hash: [u8; 32] = Sha256::digest(&bcs_bytes).into();
        assert!(!bcs_bytes.is_empty());
        assert_eq!(hash.len(), 32);

        // BCS layout is deterministic — re-encoding the same payload is stable.
        let bcs_again = bcs::to_bytes(&ApplePayload {
            attested_value: outcome.attested_value.clone(),
            challenge: outcome.challenge.clone(),
            detail_hash: outcome.detail_hash.clone(),
        })
        .unwrap();
        assert_eq!(bcs_bytes, bcs_again);
    }

    #[test]
    fn android_binding_seam_matches_handler() {
        let Some(chain_hex) = load_android_chain_hex() else {
            return;
        };
        let chain: Vec<Vec<u8>> = chain_hex
            .iter()
            .map(|h| hex::decode(h).unwrap())
            .collect();

        // The Google sample chain's leaf was generated with attestationChallenge
        // = b"abc" (0x616263). The verifier requires exact challenge equality.
        let challenge = b"abc".to_vec();

        // Clock pinned inside the chain's validity window. The Google sample's
        // root cert is valid 2016..2026-05-24; pick a clock inside that.
        let clock_ms: u64 = 1_700_000_000_000; // 2023-11-14, comfortably valid.

        let policy = attest_android::Policy {
            min_security_level: attest_android::SecurityLevel::TrustedEnvironment,
            require_verified_boot: false,
            allowed_self_signed_keys: &[],
            require_device_locked: false,
            status_list: None,
        };

        let outcome = attest_android::verify_attestation(&chain, &challenge, &policy, clock_ms)
            .expect("Android sample chain verifies at in-window clock");

        assert_eq!(outcome.source, attestation_core::sources::ANDROID_KEY_ATTEST);
        assert_eq!(outcome.challenge, challenge);
        assert!(!outcome.attested_value.is_empty(), "leaf SPKI present");

        // Reproduce the handler's AndroidPayload → BCS → SHA-256.
        let payload = AndroidPayload {
            attested_value: outcome.attested_value.clone(),
            challenge: outcome.challenge.clone(),
            detail_hash: outcome.detail_hash.clone(),
        };
        let bcs_bytes = bcs::to_bytes(&payload).expect("bcs encode");
        let hash: [u8; 32] = Sha256::digest(&bcs_bytes).into();
        assert_eq!(hash.len(), 32);
        assert!(!bcs_bytes.is_empty());
    }

    // ---- payload BCS field-order pins --------------------------------------
    //
    // The per-platform `*Payload` structs MUST BCS-encode in the exact field
    // order the Move-side structs reconstruct. Pin that order with golden bytes
    // so an accidental reorder is caught loudly (it would silently break the
    // on-chain user_data check otherwise).

    #[test]
    fn apple_payload_bcs_field_order_is_pinned() {
        let p = ApplePayload {
            attested_value: vec![0xAA, 0xBB],
            challenge: vec![0xCC],
            detail_hash: vec![0xDD, 0xEE, 0xFF],
        };
        let got = bcs::to_bytes(&p).unwrap();
        let expected = [
            0x02, 0xAA, 0xBB, // attested_value
            0x01, 0xCC, // challenge
            0x03, 0xDD, 0xEE, 0xFF, // detail_hash
        ];
        assert_eq!(got, expected, "ApplePayload field order drifted");
    }

    #[test]
    fn assertion_payload_bcs_field_order_is_pinned() {
        let p = AssertionPayload {
            attested_key: vec![0x01, 0x02],
            client_data: vec![0x03],
        };
        let got = bcs::to_bytes(&p).unwrap();
        let expected = [0x02, 0x01, 0x02, 0x01, 0x03];
        assert_eq!(got, expected, "AssertionPayload field order drifted");
    }

    #[test]
    fn android_payload_bcs_field_order_is_pinned() {
        let p = AndroidPayload {
            attested_value: vec![0x10],
            challenge: vec![0x20, 0x21],
            detail_hash: vec![0x30, 0x31, 0x32],
        };
        let got = bcs::to_bytes(&p).unwrap();
        let expected = [
            0x01, 0x10, // attested_value
            0x02, 0x20, 0x21, // challenge
            0x03, 0x30, 0x31, 0x32, // detail_hash
        ];
        assert_eq!(got, expected, "AndroidPayload field order drifted");
    }

    // ---- Ed25519 signing seam ----------------------------------------------
    //
    // The enclave key signs BCS-encoded data the chain later verifies against
    // the enclave pk. The per-request handlers don't surface a signature today
    // (they rely on the NSM doc), but the key in app state is the registration
    // identity, and `/health` publishes it. Exercise the sign/verify roundtrip
    // so the keypair in state is provably usable for Ed25519.

    #[test]
    fn signing_key_roundtrips_over_bcs_outcome() {
        use ed25519_dalek::{Signer, Verifier};

        let state = test_state();
        let outcome = Outcome {
            source: attestation_core::sources::APPLE_APP_ATTEST.to_string(),
            attested_value: vec![0x04; 65],
            challenge: vec![0xAB; 32],
            timestamp_ms: APPLE_FIXTURE_CLOCK_MS,
            detail_hash: vec![0xCD; 32],
        };
        let msg = outcome.to_bcs().expect("bcs encode outcome");

        let sig = state.signing_key.sign(&msg);
        // Verifies under the published verifying key…
        assert!(state.verifying_key.verify(&msg, &sig).is_ok());
        // …and rejects a tampered message.
        let mut tampered = msg.clone();
        tampered[0] ^= 0xFF;
        assert!(state.verifying_key.verify(&tampered, &sig).is_err());
    }

    #[test]
    fn state_verifying_key_derives_from_signing_key() {
        let state = test_state();
        assert_eq!(
            state.verifying_key.to_bytes(),
            state.signing_key.verifying_key().to_bytes(),
        );
    }
}
