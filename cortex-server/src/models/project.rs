use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Default project token lifetime in minutes (14 days = 20160 minutes).
/// Project tokens carry an explicit scope, so a longer lifetime is acceptable
/// — the blast radius of a leaked token is bounded by the scope.
pub const DEFAULT_TOKEN_TTL_MINUTES: i64 = 14 * 24 * 60;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Project {
    pub id: String,
    pub project_name: String,
    pub project_token_hash: String,
    pub env_mappings: String,
    pub namespace: String,
    /// JSON array of secret key_paths the token is allowed to read. The
    /// /agent/discover handler computes the scope from the .env file the
    /// caller submits and freezes it on the row; later /project/secrets
    /// requests filter their result to this scope.
    pub scope: String,
    pub created_at: String,
    pub updated_at: String,
    pub token_expires_at: Option<String>,
    pub token_revoked_at: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DiscoverContext {
    pub project_name: String,
    pub file_content: String,
}

#[derive(Debug, Deserialize)]
pub struct DiscoverRequest {
    pub agent_id: String,
    pub auth_proof: String,
    pub context: DiscoverContext,
    pub regenerate_token: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct DiscoverResponse {
    pub mapped_keys: HashMap<String, String>,
    pub full_matched: bool,
    pub project_token: String,
    pub token_expires_at: String,
    pub token_ttl_seconds: i64,
    pub unmatched_keys: Vec<String>,
    pub namespace: String,
    /// Secret key_paths this project_token is allowed to read.
    pub scope: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct SecretsResponse {
    pub env_vars: HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct ProjectListItem {
    pub id: String,
    pub project_name: String,
    pub env_mappings: HashMap<String, String>,
    pub namespace: String,
    pub scope: Vec<String>,
    pub created_at: String,
    pub token_expires_at: Option<String>,
    pub token_revoked_at: Option<String>,
    pub token_status: String,
}

impl Project {
    pub fn get_env_mappings(&self) -> HashMap<String, String> {
        serde_json::from_str(&self.env_mappings).unwrap_or_default()
    }

    pub fn get_scope(&self) -> Vec<String> {
        serde_json::from_str(&self.scope).unwrap_or_default()
    }

    /// Returns one of: "active", "expired", "revoked".
    pub fn token_status(&self) -> &'static str {
        if self.token_revoked_at.is_some() {
            return "revoked";
        }
        if let Some(exp) = &self.token_expires_at {
            if let Ok(exp_dt) = chrono::NaiveDateTime::parse_from_str(exp, "%Y-%m-%d %H:%M:%S") {
                let now = chrono::Utc::now().naive_utc();
                if exp_dt <= now {
                    return "expired";
                }
            }
        }
        "active"
    }
}

pub fn parse_env_file(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            line.split('=').next().map(|k| k.trim().to_string())
        })
        .filter(|k| !k.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_env_file() {
        let content = "OPENAI_API_KEY=\nDASHSCOPE_API_KEY=\n# comment\nEMPTY=\n";
        let keys = parse_env_file(content);
        assert_eq!(keys, vec!["OPENAI_API_KEY", "DASHSCOPE_API_KEY", "EMPTY"]);
    }

    #[test]
    fn test_parse_env_file_with_values() {
        let content = "KEY1=value1\nKEY2=value2";
        let keys = parse_env_file(content);
        assert_eq!(keys, vec!["KEY1", "KEY2"]);
    }
}
