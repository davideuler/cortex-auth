use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct NotificationChannel {
    pub id: String,
    pub channel_type: String,
    pub name: String,
    pub config_ciphertext: String,
    pub config_wrapped_dek: String,
    pub kek_version: i64,
    pub enabled: i64,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize)]
pub struct NotificationChannelListItem {
    pub id: String,
    pub channel_type: String,
    pub name: String,
    pub enabled: bool,
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateNotificationChannelRequest {
    pub channel_type: String,
    pub name: String,
    pub config: serde_json::Value,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    pub description: Option<String>,
}

fn default_enabled() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct UpdateNotificationChannelRequest {
    pub config: Option<serde_json::Value>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
}

pub fn is_valid_channel_type(t: &str) -> bool {
    matches!(t, "email" | "slack" | "telegram" | "discord")
}
