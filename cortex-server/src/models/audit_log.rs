use serde::Serialize;

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AuditLog {
    pub id: String,
    pub agent_id: Option<String>,
    pub project_name: Option<String>,
    pub action: String,
    pub resource_path: Option<String>,
    pub status: String,
    pub timestamp: String,
}
