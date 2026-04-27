//! Daemon attestation endpoint (UNCERTAINTIES #17).
//!
//! Implements:
//!   * `POST /daemon/attest` — register an ephemeral Ed25519 attestation key
//!     bound to a running daemon process. The matching private key never
//!     leaves the daemon's memory.
//!   * `verify_attestation_header` middleware helper — every sensitive
//!     request from a daemon must carry an `X-Daemon-Attestation` header
//!     signed over `(session_id|ts|jti|method|path|body_sha256)`.

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use chrono::{Duration, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    audit,
    error::AppError,
    models::daemon_session::{
        AttestRequest, AttestResponse, DaemonSession, DAEMON_SESSION_TTL_SECONDS,
    },
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route("/attest", post(attest))
}

fn extract_daemon_jwt(headers: &HeaderMap) -> Result<String, AppError> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Unauthorized("Missing Bearer access_token".into()))
}

fn format_sqlite_timestamp(t: chrono::DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

async fn attest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<AttestRequest>,
) -> Result<Json<AttestResponse>, AppError> {
    let jwt = extract_daemon_jwt(&headers)?;
    let claims: serde_json::Value =
        crate::ed25519_keys::verify_jwt(&state.server_keypair, &jwt)
            .map_err(|_| AppError::Unauthorized("invalid daemon access_token".into()))?;
    let agent_id = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AppError::Unauthorized("daemon access_token missing sub".into()))?
        .to_string();
    if claims.get("aud").and_then(|v| v.as_str()) != Some("cortex-daemon") {
        return Err(AppError::Unauthorized(
            "daemon access_token has wrong audience".into(),
        ));
    }

    if req.attestation_pub.trim().is_empty() {
        return Err(AppError::BadRequest(
            "attestation_pub (base64url Ed25519 public key) is required".into(),
        ));
    }
    if req.binary_sha256.trim().is_empty() {
        return Err(AppError::BadRequest("binary_sha256 is required".into()));
    }

    // Validate the supplied attestation_pub is a real 32-byte Ed25519 key.
    let pub_bytes = B64URL
        .decode(req.attestation_pub.as_bytes())
        .map_err(|_| AppError::BadRequest("attestation_pub is not base64url".into()))?;
    if pub_bytes.len() != 32 {
        return Err(AppError::BadRequest(
            "attestation_pub must decode to 32 bytes".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pub_bytes);
    VerifyingKey::from_bytes(&arr)
        .map_err(|_| AppError::BadRequest("attestation_pub is not a valid Ed25519 key".into()))?;

    // Allowlist check. An empty allowlist table = "not enforced" (warn only).
    let allowed: Option<(i64,)> = sqlx::query_as(
        "SELECT enabled FROM allowed_daemon_versions WHERE binary_sha256 = ?",
    )
    .bind(&req.binary_sha256)
    .fetch_optional(&state.pool)
    .await?;

    let allowlist_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM allowed_daemon_versions")
            .fetch_one(&state.pool)
            .await?;
    let allowlist_enforced = allowlist_count > 0;

    match (allowlist_enforced, allowed) {
        (true, None) => {
            audit::write(
                &state,
                Some(&agent_id),
                None,
                "daemon_attest_rejected",
                Some(&req.binary_sha256),
                "denied",
            )
            .await;
            return Err(AppError::Forbidden {
                code: "binary_not_allowed",
                message: format!(
                    "Daemon binary SHA-256 '{}' is not in allowed_daemon_versions",
                    req.binary_sha256
                ),
                details: None,
            });
        }
        (true, Some((enabled,))) if enabled == 0 => {
            audit::write(
                &state,
                Some(&agent_id),
                None,
                "daemon_attest_rejected",
                Some(&req.binary_sha256),
                "denied",
            )
            .await;
            return Err(AppError::Forbidden {
                code: "binary_disabled",
                message: format!(
                    "Daemon binary SHA-256 '{}' is in the allowlist but disabled",
                    req.binary_sha256
                ),
                details: None,
            });
        }
        _ => {}
    }

    let session_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let expires = now + Duration::seconds(DAEMON_SESSION_TTL_SECONDS);

    sqlx::query(
        "INSERT INTO daemon_sessions (\
            session_id, agent_id, attestation_pub, binary_sha256, daemon_version, \
            daemon_pid, daemon_uid, hostname, expires_at\
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&session_id)
    .bind(&agent_id)
    .bind(&req.attestation_pub)
    .bind(&req.binary_sha256)
    .bind(&req.daemon_version)
    .bind(req.daemon_pid)
    .bind(req.daemon_uid)
    .bind(&req.hostname)
    .bind(format_sqlite_timestamp(expires))
    .execute(&state.pool)
    .await?;

    audit::write(
        &state,
        Some(&agent_id),
        None,
        "daemon_attest",
        Some(&req.binary_sha256),
        "success",
    )
    .await;

    Ok(Json(AttestResponse {
        session_id,
        expires_in: DAEMON_SESSION_TTL_SECONDS,
        allowlist_enforced,
    }))
}

/// Verify the `X-Daemon-Attestation` header on a sensitive request. Header
/// format (base64url segments separated by `.`):
///
///   `session_id . ts . jti . body_sha256_hex . sig`
///
/// The signature is Ed25519 over the canonical message
/// `"{ts}|{jti}|{method}|{path}|{body_sha256}"`. The session is looked up
/// via `session_id` and the public key verified against the registered
/// `attestation_pub`. `jti` is single-use (stored in
/// `daemon_attest_seen_jti`), `ts` must be within ±5 minutes.
///
/// Returns the bound `agent_id` on success — handlers can plumb that into
/// authorization decisions.
pub async fn verify_attestation_header(
    state: &AppState,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String, AppError> {
    let raw = headers
        .get("x-daemon-attestation")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing X-Daemon-Attestation header".into()))?;
    let parts: Vec<&str> = raw.split('.').collect();
    if parts.len() != 5 {
        return Err(AppError::Unauthorized(
            "X-Daemon-Attestation must have 5 dot-separated segments".into(),
        ));
    }
    let session_id = parts[0].to_string();
    let ts: i64 = parts[1]
        .parse()
        .map_err(|_| AppError::Unauthorized("attestation ts is not an integer".into()))?;
    let jti = parts[2].to_string();
    let body_sha256 = parts[3].to_string();
    let sig_b64 = parts[4];

    // Drop replays / clock-skew.
    let now = Utc::now().timestamp();
    if (now - ts).abs() > 300 {
        return Err(AppError::Unauthorized(
            "attestation ts more than 5 minutes from server clock".into(),
        ));
    }

    // Body integrity.
    let mut hasher = Sha256::new();
    hasher.update(body);
    let computed_body_sha = hex::encode(hasher.finalize());
    if !subtle::ConstantTimeEq::ct_eq(computed_body_sha.as_bytes(), body_sha256.as_bytes())
        .unwrap_u8()
        == 1
    {
        // unreachable due to negation, but kept for clarity
    }
    if computed_body_sha != body_sha256 {
        return Err(AppError::Unauthorized(
            "attestation body_sha256 does not match request body".into(),
        ));
    }

    // Session lookup.
    let session: Option<DaemonSession> = sqlx::query_as::<_, DaemonSession>(
        "SELECT session_id, agent_id, attestation_pub, binary_sha256, daemon_version, \
                daemon_pid, daemon_uid, hostname, created_at, expires_at, revoked_at \
         FROM daemon_sessions WHERE session_id = ?",
    )
    .bind(&session_id)
    .fetch_optional(&state.pool)
    .await?;
    let session = session.ok_or_else(|| {
        AppError::Unauthorized("attestation session_id not found".into())
    })?;
    if session.revoked_at.is_some() {
        return Err(AppError::Unauthorized("attestation session revoked".into()));
    }
    if let Ok(exp) = chrono::NaiveDateTime::parse_from_str(&session.expires_at, "%Y-%m-%d %H:%M:%S")
    {
        if exp < Utc::now().naive_utc() {
            return Err(AppError::Unauthorized("attestation session expired".into()));
        }
    }

    // Verify signature.
    let pub_bytes = B64URL
        .decode(session.attestation_pub.as_bytes())
        .map_err(|_| AppError::Unauthorized("stored attestation_pub corrupt".into()))?;
    if pub_bytes.len() != 32 {
        return Err(AppError::Unauthorized(
            "stored attestation_pub wrong length".into(),
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pub_bytes);
    let verifying = VerifyingKey::from_bytes(&arr)
        .map_err(|_| AppError::Unauthorized("stored attestation_pub invalid".into()))?;
    let sig_bytes = B64URL
        .decode(sig_b64.as_bytes())
        .map_err(|_| AppError::Unauthorized("attestation sig is not base64url".into()))?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|_| AppError::Unauthorized("attestation sig wrong length".into()))?;

    let message = format!("{}|{}|{}|{}|{}", ts, jti, method, path, body_sha256);
    verifying
        .verify(message.as_bytes(), &sig)
        .map_err(|_| AppError::Unauthorized("attestation signature did not verify".into()))?;

    // Single-use jti.
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO daemon_attest_seen_jti (jti) VALUES (?)",
    )
    .bind(&jti)
    .execute(&state.pool)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(AppError::Unauthorized(
            "attestation jti already seen — replay rejected".into(),
        ));
    }

    // Best-effort: prune jtis older than 10 minutes — keeps the table small
    // without contention since the query is unconditional.
    let _ = sqlx::query(
        "DELETE FROM daemon_attest_seen_jti WHERE seen_at < datetime('now', '-10 minutes')",
    )
    .execute(&state.pool)
    .await;

    Ok(session.agent_id)
}
