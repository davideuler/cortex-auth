use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Secret {
    pub id: String,
    pub key_path: String,
    pub secret_type: String,
    pub encrypted_value: String,
    pub wrapped_dek: Option<String>,
    pub kek_version: i64,
    pub description: Option<String>,
    pub namespace: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateSecretRequest {
    pub key_path: String,
    pub secret_type: String,
    pub value: String,
    pub description: Option<String>,
    pub namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateSecretRequest {
    pub value: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SecretListItem {
    pub id: String,
    pub key_path: String,
    pub secret_type: String,
    pub description: Option<String>,
    pub namespace: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct SecretDetail {
    pub id: String,
    pub key_path: String,
    pub secret_type: String,
    pub value: String,
    pub description: Option<String>,
    pub namespace: String,
    pub created_at: String,
    pub updated_at: String,
}

impl Secret {
    pub fn is_valid_type(t: &str) -> bool {
        matches!(t, "KEY_VALUE" | "JSON_CONFIG" | "TEMPLATE_CONFIG")
    }
}
