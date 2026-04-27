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
}

#[derive(Debug, Deserialize)]
pub struct CreateAgentRequest {
    pub agent_id: String,
    pub jwt_secret: String,
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
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AgentClaims {
    pub sub: String,
    pub iat: u64,
    pub exp: Option<u64>,
}
