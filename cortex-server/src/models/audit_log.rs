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
    pub caller_pid: Option<i64>,
    pub caller_binary_sha256: Option<String>,
    pub caller_argv_hash: Option<String>,
    pub caller_cwd: Option<String>,
    pub caller_git_commit: Option<String>,
    pub source_ip: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub prev_hash: Option<String>,
    pub entry_mac: Option<String>,
}
