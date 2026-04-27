use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Agent {
    pub id: String,
    pub agent_id: String,
    pub description: Option<String>,
    pub namespace: String,
    pub created_at: String,
    /// (#13) base64url-encoded Ed25519 public key. The `/agent/discover`
    /// handler verifies `auth_proof` as an Ed25519 signature over
    /// `ts || nonce || agent_id || path`.
    pub agent_pub: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateAgentRequest {
    pub agent_id: String,
    /// (#13) Base64url-encoded Ed25519 public key. The matching private key
    /// stays on the agent's machine and is never uploaded.
    pub agent_pub: String,
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
