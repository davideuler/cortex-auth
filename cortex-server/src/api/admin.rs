use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    audit,
    config::parse_hex_key,
    crypto,
    error::AppError,
    models::{
        agent::{AgentListItem, CreateAgentRequest},
        audit_log::AuditLog,
        policy::{CreatePolicyRequest, PolicyDetail},
        project::ProjectListItem,
        secret::{CreateSecretRequest, SecretDetail, SecretListItem, UpdateSecretRequest},
    },
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/secrets", get(list_secrets).post(create_secret))
        .route(
            "/secrets/:id",
            get(get_secret).put(update_secret).delete(delete_secret),
        )
        .route("/agents", get(list_agents).post(create_agent))
        .route("/agents/:agent_id", delete(delete_agent))
        .route("/policies", get(list_policies).post(create_policy))
        .route("/policies/:id", delete(delete_policy))
        .route("/projects", get(list_projects))
        .route("/projects/:project_name/revoke", post(revoke_project_token))
        .route("/audit-logs", get(list_audit_logs))
        .route("/rotate-key", post(rotate_key))
}

fn check_admin_token(headers: &HeaderMap, expected: &str) -> Result<(), AppError> {
    let token = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing X-Admin-Token header".into()))?;
    if token != expected {
        return Err(AppError::Unauthorized("Invalid admin token".into()));
    }
    Ok(())
}

const SECRET_SELECT: &str =
    "SELECT id, key_path, secret_type, encrypted_value, description, namespace, created_at, updated_at FROM secrets";
const AGENT_SELECT: &str =
    "SELECT id, agent_id, jwt_secret_encrypted, description, namespace, created_at FROM agents";

async fn list_secrets(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<SecretListItem>>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let rows = sqlx::query_as::<_, crate::models::secret::Secret>(
        &format!("{} ORDER BY key_path", SECRET_SELECT),
    )
    .fetch_all(&state.pool)
    .await?;

    let items = rows
        .into_iter()
        .map(|s| SecretListItem {
            id: s.id,
            key_path: s.key_path,
            secret_type: s.secret_type,
            description: s.description,
            namespace: s.namespace,
            created_at: s.created_at,
        })
        .collect();

    Ok(Json(items))
}

async fn create_secret(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateSecretRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    if !crate::models::secret::Secret::is_valid_type(&req.secret_type) {
        return Err(AppError::BadRequest(format!(
            "Invalid secret_type '{}'. Must be KEY_VALUE, JSON_CONFIG, or TEMPLATE_CONFIG",
            req.secret_type
        )));
    }

    let namespace = req.namespace.unwrap_or_else(|| "default".to_string());
    let id = Uuid::new_v4().to_string();
    let encrypted = crypto::encrypt(&req.value, &state.config.encryption_key)
        .map_err(AppError::Internal)?;

    sqlx::query(
        "INSERT INTO secrets (id, key_path, secret_type, encrypted_value, description, namespace) VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.key_path)
    .bind(&req.secret_type)
    .bind(&encrypted)
    .bind(&req.description)
    .bind(&namespace)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint") {
            AppError::Conflict(format!(
                "Secret with key_path '{}' already exists",
                req.key_path
            ))
        } else {
            AppError::Database(e)
        }
    })?;

    audit::write(
        &state,
        None,
        None,
        "create_secret",
        Some(&req.key_path),
        "success",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "key_path": req.key_path, "namespace": namespace })),
    ))
}

async fn get_secret(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SecretDetail>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let secret = sqlx::query_as::<_, crate::models::secret::Secret>(
        &format!("{} WHERE id = ?", SECRET_SELECT),
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Secret '{}' not found", id)))?;

    let value = crypto::decrypt(&secret.encrypted_value, &state.config.encryption_key)
        .map_err(AppError::Internal)?;

    Ok(Json(SecretDetail {
        id: secret.id,
        key_path: secret.key_path,
        secret_type: secret.secret_type,
        value,
        description: secret.description,
        namespace: secret.namespace,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
    }))
}

async fn update_secret(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateSecretRequest>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let existing = sqlx::query_as::<_, crate::models::secret::Secret>(
        &format!("{} WHERE id = ?", SECRET_SELECT),
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Secret '{}' not found", id)))?;

    let new_encrypted = if let Some(new_value) = &req.value {
        crypto::encrypt(new_value, &state.config.encryption_key).map_err(AppError::Internal)?
    } else {
        existing.encrypted_value.clone()
    };

    let new_description = req.description.or(existing.description);

    sqlx::query(
        "UPDATE secrets SET encrypted_value = ?, description = ?, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(&new_encrypted)
    .bind(&new_description)
    .bind(&id)
    .execute(&state.pool)
    .await?;

    audit::write(
        &state,
        None,
        None,
        "update_secret",
        Some(&existing.key_path),
        "success",
    )
    .await;

    Ok(Json(json!({ "updated": true, "id": id })))
}

async fn delete_secret(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let secret = sqlx::query_as::<_, crate::models::secret::Secret>(
        &format!("{} WHERE id = ?", SECRET_SELECT),
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Secret '{}' not found", id)))?;

    sqlx::query("DELETE FROM secrets WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;

    audit::write(
        &state,
        None,
        None,
        "delete_secret",
        Some(&secret.key_path),
        "success",
    )
    .await;

    Ok(Json(json!({ "deleted": true })))
}

async fn list_agents(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<AgentListItem>>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let rows = sqlx::query_as::<_, crate::models::agent::Agent>(
        &format!("{} ORDER BY created_at", AGENT_SELECT),
    )
    .fetch_all(&state.pool)
    .await?;

    let items = rows
        .into_iter()
        .map(|a| AgentListItem {
            id: a.id,
            agent_id: a.agent_id,
            description: a.description,
            namespace: a.namespace,
            created_at: a.created_at,
        })
        .collect();

    Ok(Json(items))
}

async fn create_agent(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateAgentRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let namespace = req.namespace.unwrap_or_else(|| "default".to_string());
    let id = Uuid::new_v4().to_string();
    let encrypted_secret = crypto::encrypt(&req.jwt_secret, &state.config.encryption_key)
        .map_err(AppError::Internal)?;

    sqlx::query(
        "INSERT INTO agents (id, agent_id, jwt_secret_encrypted, description, namespace) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.agent_id)
    .bind(&encrypted_secret)
    .bind(&req.description)
    .bind(&namespace)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint") {
            AppError::Conflict(format!("Agent '{}' already exists", req.agent_id))
        } else {
            AppError::Database(e)
        }
    })?;

    audit::write(
        &state,
        Some(&req.agent_id),
        None,
        "create_agent",
        None,
        "success",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "agent_id": req.agent_id, "namespace": namespace })),
    ))
}

async fn delete_agent(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let result = sqlx::query("DELETE FROM agents WHERE agent_id = ?")
        .bind(&agent_id)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "Agent '{}' not found",
            agent_id
        )));
    }

    audit::write(&state, Some(&agent_id), None, "delete_agent", None, "success").await;

    Ok(Json(json!({ "deleted": true })))
}

async fn list_policies(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<PolicyDetail>>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let rows = sqlx::query_as::<_, crate::models::policy::Policy>(
        "SELECT id, policy_name, agent_pattern, allowed_paths, denied_paths, created_at FROM policies ORDER BY created_at",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows.into_iter().map(|p| p.to_detail()).collect()))
}

async fn create_policy(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreatePolicyRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let id = Uuid::new_v4().to_string();
    let allowed = serde_json::to_string(&req.allowed_paths).unwrap();
    let denied = serde_json::to_string(&req.denied_paths.unwrap_or_default()).unwrap();

    sqlx::query(
        "INSERT INTO policies (id, policy_name, agent_pattern, allowed_paths, denied_paths) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.policy_name)
    .bind(&req.agent_pattern)
    .bind(&allowed)
    .bind(&denied)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint") {
            AppError::Conflict(format!("Policy '{}' already exists", req.policy_name))
        } else {
            AppError::Database(e)
        }
    })?;

    audit::write(
        &state,
        None,
        None,
        "create_policy",
        Some(&req.policy_name),
        "success",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "policy_name": req.policy_name })),
    ))
}

async fn delete_policy(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let result = sqlx::query("DELETE FROM policies WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("Policy '{}' not found", id)));
    }

    audit::write(&state, None, None, "delete_policy", Some(&id), "success").await;

    Ok(Json(json!({ "deleted": true })))
}

async fn list_projects(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<ProjectListItem>>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let rows = sqlx::query_as::<_, crate::models::project::Project>(
        "SELECT id, project_name, project_token_hash, env_mappings, namespace, created_at, updated_at, token_expires_at, token_revoked_at FROM projects ORDER BY created_at",
    )
    .fetch_all(&state.pool)
    .await?;

    let items = rows
        .into_iter()
        .map(|p| ProjectListItem {
            id: p.id.clone(),
            project_name: p.project_name.clone(),
            env_mappings: p.get_env_mappings(),
            namespace: p.namespace.clone(),
            created_at: p.created_at.clone(),
            token_expires_at: p.token_expires_at.clone(),
            token_revoked_at: p.token_revoked_at.clone(),
            token_status: p.token_status().to_string(),
        })
        .collect();

    Ok(Json(items))
}

async fn revoke_project_token(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(project_name): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let result = sqlx::query(
        "UPDATE projects SET token_revoked_at = datetime('now'), updated_at = datetime('now') WHERE project_name = ? AND token_revoked_at IS NULL",
    )
    .bind(&project_name)
    .execute(&state.pool)
    .await?;

    if result.rows_affected() == 0 {
        // Distinguish "not found" from "already revoked".
        let exists: Option<(String,)> =
            sqlx::query_as("SELECT project_name FROM projects WHERE project_name = ?")
                .bind(&project_name)
                .fetch_optional(&state.pool)
                .await?;
        if exists.is_none() {
            return Err(AppError::NotFound(format!(
                "Project '{}' not found",
                project_name
            )));
        }
        return Ok(Json(json!({
            "revoked": true,
            "project_name": project_name,
            "already_revoked": true,
        })));
    }

    audit::write(
        &state,
        None,
        Some(&project_name),
        "revoke_project_token",
        Some(&project_name),
        "success",
    )
    .await;

    Ok(Json(json!({
        "revoked": true,
        "project_name": project_name,
    })))
}

async fn list_audit_logs(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<AuditLog>>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let logs = sqlx::query_as::<_, AuditLog>(
        "SELECT id, agent_id, project_name, action, resource_path, status, timestamp FROM audit_logs ORDER BY timestamp DESC LIMIT 1000",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(logs))
}

#[derive(Debug, Deserialize)]
struct RotateKeyRequest {
    new_encryption_key: String,
}

async fn rotate_key(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<RotateKeyRequest>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let new_key = parse_hex_key(&req.new_encryption_key)
        .map_err(|e| AppError::BadRequest(format!("Invalid new_encryption_key: {}", e)))?;

    let secrets = sqlx::query_as::<_, crate::models::secret::Secret>(SECRET_SELECT)
        .fetch_all(&state.pool)
        .await?;

    let agents = sqlx::query_as::<_, crate::models::agent::Agent>(AGENT_SELECT)
        .fetch_all(&state.pool)
        .await?;

    let mut tx = state.pool.begin().await?;

    for secret in &secrets {
        let plaintext = crypto::decrypt(&secret.encrypted_value, &state.config.encryption_key)
            .map_err(AppError::Internal)?;
        let re_encrypted = crypto::encrypt(&plaintext, &new_key).map_err(AppError::Internal)?;
        sqlx::query(
            "UPDATE secrets SET encrypted_value = ?, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(&re_encrypted)
        .bind(&secret.id)
        .execute(&mut *tx)
        .await?;
    }

    for agent in &agents {
        let plaintext =
            crypto::decrypt(&agent.jwt_secret_encrypted, &state.config.encryption_key)
                .map_err(AppError::Internal)?;
        let re_encrypted = crypto::encrypt(&plaintext, &new_key).map_err(AppError::Internal)?;
        sqlx::query("UPDATE agents SET jwt_secret_encrypted = ? WHERE id = ?")
            .bind(&re_encrypted)
            .bind(&agent.id)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;

    audit::write(&state, None, None, "rotate_key", None, "success").await;

    Ok(Json(json!({
        "rotated": true,
        "secrets_updated": secrets.len(),
        "agents_updated": agents.len(),
        "message": "Key rotation complete. Update ENCRYPTION_KEY env var and restart server."
    })))
}
