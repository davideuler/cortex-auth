//! `daemon_sessions` and `allowed_daemon_versions` — per-process
//! attestation registry for cortex-daemon.
//!
//! At startup the daemon generates an ephemeral Ed25519 keypair (the private
//! key never leaves the daemon process), POSTs the public key + binary
//! SHA-256 + version to `/daemon/attest`, and gets back a `session_id`.
//! Every subsequent sensitive HTTP request from the daemon carries an
//! `X-Daemon-Attestation` header signed by the ephemeral private key over
//! `(session_id, ts, jti, method, path, body_sha256, auth_token_id)` —
//! pinning the request and its Authorization bearer to that specific running
//! daemon process.

use serde::{Deserialize, Serialize};

/// A daemon session lives this long before the daemon must re-attest.
pub const DAEMON_SESSION_TTL_SECONDS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DaemonSession {
    pub session_id: String,
    pub agent_id: String,
    pub attestation_pub: String,
    pub binary_sha256: String,
    pub daemon_version: Option<String>,
    pub daemon_pid: Option<i64>,
    pub daemon_uid: Option<i64>,
    pub hostname: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AttestRequest {
    pub attestation_pub: String,
    pub binary_sha256: String,
    pub daemon_version: Option<String>,
    pub daemon_pid: Option<i64>,
    pub daemon_uid: Option<i64>,
    pub hostname: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AttestResponse {
    pub session_id: String,
    pub expires_in: i64,
    /// Whether the binary SHA-256 is in the allowlist. When false the request
    /// is rejected (response is 403). Operators can disable enforcement by
    /// leaving `allowed_daemon_versions` empty.
    pub allowlist_enforced: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct AllowedDaemonVersion {
    pub binary_sha256: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub enabled: i64,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateAllowedDaemonVersion {
    pub binary_sha256: String,
    pub version: Option<String>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}
