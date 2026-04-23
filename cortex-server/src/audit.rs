use uuid::Uuid;

use crate::state::AppState;

pub async fn write(
    state: &AppState,
    agent_id: Option<&str>,
    project_name: Option<&str>,
    action: &str,
    resource_path: Option<&str>,
    status: &str,
) {
    let id = Uuid::new_v4().to_string();
    let _ = sqlx::query(
        "INSERT INTO audit_logs (id, agent_id, project_name, action, resource_path, status) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(agent_id)
    .bind(project_name)
    .bind(action)
    .bind(resource_path)
    .bind(status)
    .execute(&state.pool)
    .await;
}
