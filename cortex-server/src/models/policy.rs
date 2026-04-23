use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Policy {
    pub id: String,
    pub policy_name: String,
    pub agent_pattern: String,
    pub allowed_paths: String,
    pub denied_paths: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreatePolicyRequest {
    pub policy_name: String,
    pub agent_pattern: String,
    pub allowed_paths: Vec<String>,
    pub denied_paths: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct PolicyDetail {
    pub id: String,
    pub policy_name: String,
    pub agent_pattern: String,
    pub allowed_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub created_at: String,
}

impl Policy {
    pub fn to_detail(&self) -> PolicyDetail {
        PolicyDetail {
            id: self.id.clone(),
            policy_name: self.policy_name.clone(),
            agent_pattern: self.agent_pattern.clone(),
            allowed_paths: serde_json::from_str(&self.allowed_paths).unwrap_or_default(),
            denied_paths: serde_json::from_str(&self.denied_paths).unwrap_or_default(),
            created_at: self.created_at.clone(),
        }
    }
}
