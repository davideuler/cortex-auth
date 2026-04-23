use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Project {
    pub id: String,
    pub project_name: String,
    pub project_token_hash: String,
    pub env_mappings: String,
    pub namespace: String,
    pub created_at: String,
    pub updated_at: String,
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
    pub unmatched_keys: Vec<String>,
    pub namespace: String,
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
    pub created_at: String,
}

impl Project {
    pub fn get_env_mappings(&self) -> HashMap<String, String> {
        serde_json::from_str(&self.env_mappings).unwrap_or_default()
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
