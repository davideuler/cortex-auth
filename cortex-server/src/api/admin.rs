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
    crypto,
    error::AppError,
    models::{
        agent::{AgentListItem, CreateAgentRequest},
        audit_log::AuditLog,
        namespace::{CreateNamespaceRequest, Namespace},
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
        .route("/namespaces", get(list_namespaces).post(create_namespace))
        .route("/namespaces/:name", delete(delete_namespace))
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
    "SELECT id, key_path, secret_type, encrypted_value, wrapped_dek, kek_version, description, namespace, is_honey_token, created_at, updated_at FROM secrets";
const AGENT_SELECT: &str =
    "SELECT id, agent_id, jwt_secret_encrypted, wrapped_dek, kek_version, description, namespace, created_at FROM agents";

async fn ensure_namespace_exists(state: &AppState, name: &str) -> Result<(), AppError> {
    sqlx::query("INSERT OR IGNORE INTO namespaces (name) VALUES (?)")
        .bind(name)
        .execute(&state.pool)
        .await?;
    Ok(())
}

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
            is_honey_token: s.is_honey_token != 0,
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
    ensure_namespace_exists(&state, &namespace).await?;

    let id = Uuid::new_v4().to_string();
    let envelope = crypto::seal_envelope(&req.value, &state.kek).map_err(AppError::Internal)?;

    sqlx::query(
        "INSERT INTO secrets (id, key_path, secret_type, encrypted_value, wrapped_dek, kek_version, description, namespace, is_honey_token) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.key_path)
    .bind(&req.secret_type)
    .bind(&envelope.body_ciphertext)
    .bind(&envelope.wrapped_dek)
    .bind(&req.description)
    .bind(&namespace)
    .bind(if req.is_honey_token { 1_i64 } else { 0_i64 })
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

    let wrapped = secret
        .wrapped_dek
        .as_deref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Secret missing wrapped_dek")))?;
    let value = crypto::open_envelope(&secret.encrypted_value, wrapped, &state.kek)
        .map_err(AppError::Internal)?;

    Ok(Json(SecretDetail {
        id: secret.id,
        key_path: secret.key_path,
        secret_type: secret.secret_type,
        value,
        description: secret.description,
        namespace: secret.namespace,
        is_honey_token: secret.is_honey_token != 0,
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

    let (new_body, new_wrapped) = if let Some(new_value) = &req.value {
        let env = crypto::seal_envelope(new_value, &state.kek).map_err(AppError::Internal)?;
        (env.body_ciphertext, env.wrapped_dek)
    } else {
        (
            existing.encrypted_value.clone(),
            existing
                .wrapped_dek
                .clone()
                .ok_or_else(|| AppError::Internal(anyhow::anyhow!("Existing secret missing wrapped_dek")))?,
        )
    };

    let new_description = req.description.or(existing.description);
    let new_honey: i64 = match req.is_honey_token {
        Some(true) => 1,
        Some(false) => 0,
        None => existing.is_honey_token,
    };

    sqlx::query(
        "UPDATE secrets SET encrypted_value = ?, wrapped_dek = ?, description = ?, is_honey_token = ?, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(&new_body)
    .bind(&new_wrapped)
    .bind(&new_description)
    .bind(new_honey)
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
    ensure_namespace_exists(&state, &namespace).await?;

    let id = Uuid::new_v4().to_string();
    let envelope =
        crypto::seal_envelope(&req.jwt_secret, &state.kek).map_err(AppError::Internal)?;

    sqlx::query(
        "INSERT INTO agents (id, agent_id, jwt_secret_encrypted, wrapped_dek, kek_version, description, namespace) VALUES (?, ?, ?, ?, 1, ?, ?)",
    )
    .bind(&id)
    .bind(&req.agent_id)
    .bind(&envelope.body_ciphertext)
    .bind(&envelope.wrapped_dek)
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
        "SELECT id, project_name, project_token_hash, env_mappings, namespace, scope, created_at, updated_at, token_expires_at, token_revoked_at FROM projects ORDER BY created_at",
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
            scope: p.get_scope(),
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

async fn list_namespaces(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<Namespace>>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let rows = sqlx::query_as::<_, Namespace>(
        "SELECT name, description, created_at FROM namespaces ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows))
}

async fn create_namespace(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateNamespaceRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let name = req.name.trim();
    if name.is_empty() {
        return Err(AppError::BadRequest("namespace name cannot be empty".into()));
    }

    sqlx::query("INSERT INTO namespaces (name, description) VALUES (?, ?)")
        .bind(name)
        .bind(&req.description)
        .execute(&state.pool)
        .await
        .map_err(|e| {
            if e.to_string().contains("UNIQUE constraint") {
                AppError::Conflict(format!("Namespace '{}' already exists", name))
            } else {
                AppError::Database(e)
            }
        })?;

    audit::write(&state, None, None, "create_namespace", Some(name), "success").await;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "name": name, "description": req.description })),
    ))
}

async fn delete_namespace(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    if name == "default" {
        return Err(AppError::BadRequest(
            "Cannot delete the 'default' namespace".into(),
        ));
    }

    // Refuse if any rows still reference the namespace; otherwise the orphaned
    // rows would survive in a phantom namespace and confuse listing/auditing.
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM secrets WHERE namespace = ?), \
                (SELECT COUNT(*) FROM agents WHERE namespace = ?), \
                (SELECT COUNT(*) FROM projects WHERE namespace = ?)",
    )
    .bind(&name)
    .bind(&name)
    .bind(&name)
    .fetch_one(&state.pool)
    .await?;

    if counts.0 + counts.1 + counts.2 > 0 {
        return Err(AppError::Conflict(format!(
            "Namespace '{}' is in use (secrets={}, agents={}, projects={})",
            name, counts.0, counts.1, counts.2
        )));
    }

    let result = sqlx::query("DELETE FROM namespaces WHERE name = ?")
        .bind(&name)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("Namespace '{}' not found", name)));
    }

    audit::write(&state, None, None, "delete_namespace", Some(&name), "success").await;
    Ok(Json(json!({ "deleted": true, "name": name })))
}

async fn list_audit_logs(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<AuditLog>>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let logs = sqlx::query_as::<_, AuditLog>(
        "SELECT id, agent_id, project_name, action, resource_path, status, timestamp, \
                caller_pid, caller_binary_sha256, caller_argv_hash, caller_cwd, caller_git_commit, \
                source_ip, hostname, os, prev_hash, entry_mac \
         FROM audit_logs ORDER BY timestamp DESC LIMIT 1000",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(logs))
}

#[derive(Debug, Deserialize)]
struct RotateKekRequest {
    new_kek_password: String,
}

/// Rotate the KEK by re-deriving from a new operator password and re-wrapping
/// every per-row DEK. Body ciphertexts (encrypted with the random per-row DEK)
/// are untouched, so this is O(rows) wraps — never an O(rows) re-encryption.
async fn rotate_key(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<RotateKekRequest>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.config.admin_token)?;

    let new_password = req.new_kek_password.trim();
    if new_password.is_empty() {
        return Err(AppError::BadRequest("new_kek_password cannot be empty".into()));
    }

    let new_salt = crypto::random_salt();
    let new_kek =
        crypto::derive_kek(new_password, &new_salt).map_err(AppError::Internal)?;

    let secrets = sqlx::query_as::<_, crate::models::secret::Secret>(SECRET_SELECT)
        .fetch_all(&state.pool)
        .await?;
    let agents = sqlx::query_as::<_, crate::models::agent::Agent>(AGENT_SELECT)
        .fetch_all(&state.pool)
        .await?;

    let new_kek_version: i64 = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE((SELECT kek_version FROM kek_metadata WHERE id = 1), 1) + 1",
    )
    .fetch_one(&state.pool)
    .await?;

    let mut tx = state.pool.begin().await?;

    for s in &secrets {
        let wrapped = s
            .wrapped_dek
            .as_deref()
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("secret missing wrapped_dek")))?;
        let plaintext = crypto::open_envelope(&s.encrypted_value, wrapped, &state.kek)
            .map_err(AppError::Internal)?;
        let env = crypto::seal_envelope(&plaintext, &new_kek).map_err(AppError::Internal)?;
        sqlx::query(
            "UPDATE secrets SET encrypted_value = ?, wrapped_dek = ?, kek_version = ?, updated_at = datetime('now') WHERE id = ?",
        )
        .bind(&env.body_ciphertext)
        .bind(&env.wrapped_dek)
        .bind(new_kek_version)
        .bind(&s.id)
        .execute(&mut *tx)
        .await?;
    }

    for a in &agents {
        let wrapped = a
            .wrapped_dek
            .as_deref()
            .ok_or_else(|| AppError::Internal(anyhow::anyhow!("agent missing wrapped_dek")))?;
        let plaintext = crypto::open_envelope(&a.jwt_secret_encrypted, wrapped, &state.kek)
            .map_err(AppError::Internal)?;
        let env = crypto::seal_envelope(&plaintext, &new_kek).map_err(AppError::Internal)?;
        sqlx::query(
            "UPDATE agents SET jwt_secret_encrypted = ?, wrapped_dek = ?, kek_version = ? WHERE id = ?",
        )
        .bind(&env.body_ciphertext)
        .bind(&env.wrapped_dek)
        .bind(new_kek_version)
        .bind(&a.id)
        .execute(&mut *tx)
        .await?;
    }

    let new_sentinel = crypto::seal_sentinel(&new_kek).map_err(AppError::Internal)?;
    let new_salt_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &new_salt);
    sqlx::query(
        "UPDATE kek_metadata SET salt = ?, sentinel_ciphertext = ?, kek_version = ?, updated_at = datetime('now') WHERE id = 1",
    )
    .bind(&new_salt_b64)
    .bind(&new_sentinel)
    .bind(new_kek_version)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    audit::write(&state, None, None, "rotate_kek", None, "success").await;

    Ok(Json(json!({
        "rotated": true,
        "secrets_rewrapped": secrets.len(),
        "agents_rewrapped": agents.len(),
        "new_kek_version": new_kek_version,
        "message": "KEK rotated. Restart the server with the NEW operator password to reload the KEK into memory."
    })))
}
