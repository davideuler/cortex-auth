use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ProjectSecretGrant {
    pub id: String,
    pub project_name: String,
    pub secret_id: String,
    pub env_var_name: Option<String>,
    pub granted_by: String,
    pub granted_at: String,
}

impl ProjectSecretGrant {
    /// Resolve the effective env-var name for this grant. Falls back to the
    /// last path segment of `secret_key_path` uppercased when `env_var_name`
    /// is not set.
    pub fn effective_env_var(&self, secret_key_path: &str) -> String {
        if let Some(v) = self.env_var_name.as_deref().filter(|v| !v.is_empty()) {
            return v.to_uppercase();
        }
        secret_key_path
            .rsplit('/')
            .next()
            .unwrap_or(secret_key_path)
            .to_uppercase()
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateGrantRequest {
    /// ID of the secret to grant (from GET /admin/secrets).
    pub secret_id: String,
    /// Env-var name to inject the secret under. Optional — defaults to the
    /// secret's key_path last segment uppercased.
    pub env_var_name: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GrantDetail {
    pub id: String,
    pub project_name: String,
    pub secret_id: String,
    pub secret_key_path: String,
    pub secret_namespace: String,
    pub env_var_name: String,
    pub granted_by: String,
    pub granted_at: String,
}
