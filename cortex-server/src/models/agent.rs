use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Agent {
    pub id: String,
    pub agent_id: String,
    pub jwt_secret_encrypted: String,
    pub wrapped_dek: Option<String>,
    pub kek_version: i64,
    pub description: Option<String>,
    pub namespace: String,
    pub created_at: String,
    /// (#13) base64url-encoded Ed25519 public key. When non-NULL, the
    /// /agent/discover handler verifies `auth_proof` as an Ed25519 signature
    /// over `ts || nonce || agent_id || path` instead of decoding the legacy
    /// HMAC-SHA256 JWT in `jwt_secret_encrypted`.
    pub agent_pub: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateAgentRequest {
    pub agent_id: String,
    /// Legacy HMAC secret. Optional now that agents can register with an
    /// Ed25519 public key only — but must supply *something* (HS256 or
    /// agent_pub) so the agent has at least one auth path.
    #[serde(default)]
    pub jwt_secret: Option<String>,
    /// (#13) Base64url-encoded Ed25519 public key. The matching private key
    /// stays on the agent's machine and is never uploaded.
    #[serde(default)]
    pub agent_pub: Option<String>,
    pub description: Option<String>,
    pub namespace: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AgentListItem {
    pub id: String,
    pub agent_id: String,
    pub description: Option<String>,
    pub namespace: String,
    pub created_at: String,
    pub has_pubkey: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentClaims {
    pub sub: String,
    pub iat: u64,
    pub exp: Option<u64>,
}
