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
        daemon_session::{AllowedDaemonVersion, CreateAllowedDaemonVersion},
        namespace::{CreateNamespaceRequest, Namespace},
        notification::{
            is_valid_channel_type, CreateNotificationChannelRequest, NotificationChannel,
            NotificationChannelListItem, UpdateNotificationChannelRequest,
        },
        pending_grant::{
            ApproveGrantRequest, PendingGrant, PendingGrantListItem, AUTO_APPROVAL_WINDOW_DAYS,
        },
        policy::{CreatePolicyRequest, PolicyDetail},
        project::ProjectListItem,
        project_secret_grant::{CreateGrantRequest, GrantDetail},
        secret::{CreateSecretRequest, SecretDetail, SecretListItem, UpdateSecretRequest},
    },
    notifications,
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
        .route(
            "/projects/:project_name/grants",
            get(list_project_grants).post(create_project_grant),
        )
        .route(
            "/projects/:project_name/grants/:grant_id",
            delete(delete_project_grant),
        )
        .route("/namespaces", get(list_namespaces).post(create_namespace))
        .route("/namespaces/:name", delete(delete_namespace))
        .route("/audit-logs", get(list_audit_logs))
        .route("/rotate-key", post(rotate_key))
        .route(
            "/notification-channels",
            get(list_notification_channels).post(create_notification_channel),
        )
        .route(
            "/notification-channels/:id",
            axum::routing::put(update_notification_channel)
                .delete(delete_notification_channel),
        )
        .route(
            "/notification-channels/:id/test",
            post(test_notification_channel),
        )
        .route("/shamir/generate", post(generate_shamir_shares))
        .route("/devices", get(list_devices))
        .route("/devices/:agent_id", delete(delete_device))
        .route("/web/device/approve", post(web_device_approve))
        .route("/pending-grants", get(list_pending_grants))
        .route("/pending-grants/:id/approve", post(approve_pending_grant))
        .route("/pending-grants/:id/deny", post(deny_pending_grant))
        .route("/pending-grants/:id", delete(delete_pending_grant))
        .route(
            "/allowed-daemon-versions",
            get(list_allowed_daemon_versions).post(create_allowed_daemon_version),
        )
        .route(
            "/allowed-daemon-versions/:sha",
            delete(delete_allowed_daemon_version),
        )
        .route("/daemon-sessions", get(list_daemon_sessions))
}

fn check_admin_token(headers: &HeaderMap, expected_hash: &str) -> Result<(), AppError> {
    let token = headers
        .get("x-admin-token")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::Unauthorized("Missing X-Admin-Token header".into()))?;
    if !crypto::verify_token(token, expected_hash) {
        return Err(AppError::Unauthorized("Invalid admin token".into()));
    }
    Ok(())
}

const SECRET_SELECT: &str =
    "SELECT id, key_path, secret_type, encrypted_value, wrapped_dek, kek_version, description, namespace, is_honey_token, created_at, updated_at FROM secrets";
const AGENT_SELECT: &str =
    "SELECT id, agent_id, description, namespace, created_at, agent_pub FROM agents";

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

    if !crate::models::secret::Secret::is_valid_type(&req.secret_type) {
        return Err(AppError::BadRequest(format!(
            "Invalid secret_type '{}'. Must be KEY_VALUE, JSON_CONFIG, or TEMPLATE_CONFIG",
            req.secret_type
        )));
    }

    let namespace = req.namespace.unwrap_or_else(|| "default".to_string());
    ensure_namespace_exists(&state, &namespace).await?;

    // Honey-token collision check: warn if a real (non-honey) secret already
    // exists with the same key_path in the same namespace. Having both a real
    // and a honey secret at the same path confuses policy evaluation and
    // defeats the purpose of the decoy.
    if req.is_honey_token {
        let collision: Option<(String,)> = sqlx::query_as(
            "SELECT id FROM secrets WHERE key_path = ? AND namespace = ? AND is_honey_token = 0",
        )
        .bind(&req.key_path)
        .bind(&namespace)
        .fetch_optional(&state.pool)
        .await?;
        if collision.is_some() {
            return Err(AppError::Conflict(format!(
                "A real (non-honey) secret at key_path '{}' in namespace '{}' already exists. \
                 Rename the honey token or delete/rename the real secret first to avoid \
                 collision. Pass a different key_path to proceed.",
                req.key_path, namespace
            )));
        }
    }

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
            has_pubkey: !a.agent_pub.is_empty(),
        })
        .collect();

    Ok(Json(items))
}

async fn create_agent(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateAgentRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    if req.agent_pub.trim().is_empty() {
        return Err(AppError::BadRequest(
            "agent_pub (base64url-encoded Ed25519 public key) is required".into(),
        ));
    }

    let namespace = req.namespace.unwrap_or_else(|| "default".to_string());
    ensure_namespace_exists(&state, &namespace).await?;

    let id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO agents (id, agent_id, description, namespace, agent_pub) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(&req.agent_id)
    .bind(&req.description)
    .bind(&namespace)
    .bind(&req.agent_pub)
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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

    let rows = sqlx::query_as::<_, crate::models::project::Project>(
        "SELECT id, project_name, project_token_hash, env_mappings, namespace, scope, created_at, updated_at, token_expires_at, token_revoked_at, signed_token_jti, agent_id FROM projects ORDER BY created_at",
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
    check_admin_token(&headers, &state.admin_token_hash)?;

    // Copy signed token's JTI to per-JTI revocation list so EdDSA JWT
    // bearers are also blocked before their exp.
    let jti_row: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT signed_token_jti FROM projects WHERE project_name = ?",
    )
    .bind(&project_name)
    .fetch_optional(&state.pool)
    .await?;
    if let Some((Some(jti),)) = jti_row {
        let _ = sqlx::query("INSERT OR IGNORE INTO revoked_token_jti (jti) VALUES (?)")
        .bind(&jti)
        .execute(&state.pool)
        .await;
    }

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
    check_admin_token(&headers, &state.admin_token_hash)?;

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
        "new_kek_version": new_kek_version,
        "message": "KEK rotated. Restart the server with the NEW operator password to reload the KEK into memory."
    })))
}

// ─── Notification channels ─────────────────────────────────────────────────

const NOTIFICATION_SELECT: &str = "SELECT id, channel_type, name, config_ciphertext, \
    config_wrapped_dek, kek_version, enabled, description, created_at, updated_at \
    FROM notification_channels";

async fn list_notification_channels(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<NotificationChannelListItem>>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let rows = sqlx::query_as::<_, NotificationChannel>(
        &format!("{} ORDER BY created_at", NOTIFICATION_SELECT),
    )
    .fetch_all(&state.pool)
    .await?;

    let items = rows
        .into_iter()
        .map(|c| NotificationChannelListItem {
            id: c.id,
            channel_type: c.channel_type,
            name: c.name,
            enabled: c.enabled != 0,
            description: c.description,
            created_at: c.created_at,
            updated_at: c.updated_at,
        })
        .collect();

    Ok(Json(items))
}

async fn create_notification_channel(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateNotificationChannelRequest>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    if !is_valid_channel_type(&req.channel_type) {
        return Err(AppError::BadRequest(format!(
            "Invalid channel_type '{}'. Must be email, slack, telegram, or discord",
            req.channel_type
        )));
    }
    if req.name.trim().is_empty() {
        return Err(AppError::BadRequest("name cannot be empty".into()));
    }

    let config_str = serde_json::to_string(&req.config)
        .map_err(|e| AppError::BadRequest(format!("config must be JSON: {}", e)))?;

    let envelope = crypto::seal_envelope(&config_str, &state.kek).map_err(AppError::Internal)?;
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO notification_channels \
            (id, channel_type, name, config_ciphertext, config_wrapped_dek, kek_version, enabled, description) \
         VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
    )
    .bind(&id)
    .bind(&req.channel_type)
    .bind(&req.name)
    .bind(&envelope.body_ciphertext)
    .bind(&envelope.wrapped_dek)
    .bind(if req.enabled { 1_i64 } else { 0_i64 })
    .bind(&req.description)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint") {
            AppError::Conflict(format!("Channel '{}' already exists", req.name))
        } else {
            AppError::Database(e)
        }
    })?;

    audit::write(&state, None, None, "create_notification_channel", Some(&req.name), "success").await;

    Ok((
        StatusCode::CREATED,
        Json(json!({ "id": id, "name": req.name, "channel_type": req.channel_type })),
    ))
}

async fn update_notification_channel(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateNotificationChannelRequest>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let existing = sqlx::query_as::<_, NotificationChannel>(
        &format!("{} WHERE id = ?", NOTIFICATION_SELECT),
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Channel '{}' not found", id)))?;

    let (new_body, new_wrapped) = if let Some(cfg) = &req.config {
        let s = serde_json::to_string(cfg)
            .map_err(|e| AppError::BadRequest(format!("config must be JSON: {}", e)))?;
        let env = crypto::seal_envelope(&s, &state.kek).map_err(AppError::Internal)?;
        (env.body_ciphertext, env.wrapped_dek)
    } else {
        (existing.config_ciphertext.clone(), existing.config_wrapped_dek.clone())
    };

    let new_enabled: i64 = match req.enabled {
        Some(true) => 1,
        Some(false) => 0,
        None => existing.enabled,
    };
    let new_description = req.description.or(existing.description);

    sqlx::query(
        "UPDATE notification_channels SET config_ciphertext = ?, config_wrapped_dek = ?, \
         enabled = ?, description = ?, updated_at = datetime('now') WHERE id = ?",
    )
    .bind(&new_body)
    .bind(&new_wrapped)
    .bind(new_enabled)
    .bind(&new_description)
    .bind(&id)
    .execute(&state.pool)
    .await?;

    audit::write(&state, None, None, "update_notification_channel", Some(&existing.name), "success").await;
    Ok(Json(json!({ "updated": true, "id": id })))
}

async fn delete_notification_channel(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let row: Option<(String,)> =
        sqlx::query_as("SELECT name FROM notification_channels WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.pool)
            .await?;
    let name = row
        .map(|r| r.0)
        .ok_or_else(|| AppError::NotFound(format!("Channel '{}' not found", id)))?;

    sqlx::query("DELETE FROM notification_channels WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;

    audit::write(&state, None, None, "delete_notification_channel", Some(&name), "success").await;
    Ok(Json(json!({ "deleted": true })))
}

async fn test_notification_channel(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let row: Option<(String,)> =
        sqlx::query_as("SELECT name FROM notification_channels WHERE id = ?")
            .bind(&id)
            .fetch_optional(&state.pool)
            .await?;
    let name = row
        .map(|r| r.0)
        .ok_or_else(|| AppError::NotFound(format!("Channel '{}' not found", id)))?;

    notifications::dispatch(
        &state,
        notifications::NotificationEvent::RecoveryBoot {
            hostname: Some(format!("test-from-channel:{}", name)),
        },
    );

    Ok(Json(json!({ "queued": true, "name": name })))
}

// ─── Shamir share generation (#15) ─────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ShamirGenerateRequest {
    threshold: u8,
    shares: u8,
}

async fn generate_shamir_shares(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<ShamirGenerateRequest>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    if req.threshold < 2 || req.threshold > req.shares || req.shares > 200 {
        return Err(AppError::BadRequest(
            "threshold must be >=2, threshold <= shares, shares <= 200".into(),
        ));
    }

    let shares = crate::shamir::split(state.kek.as_bytes(), req.threshold, req.shares)
        .map_err(AppError::Internal)?;

    audit::write(&state, None, None, "shamir_generate", None, "success").await;

    Ok(Json(json!({
        "threshold": req.threshold,
        "shares_count": req.shares,
        "shares": shares,
        "warning": "Distribute these shares to operators NOW and DO NOT store them. \
                    The server does not retain a copy. To recover, set CORTEX_RECOVERY_MODE=1 \
                    and supply any threshold-many shares on stdin at boot."
    })))
}

// ─── Device authorization (#16) — admin-side endpoints ────────────────────

#[derive(Debug, Deserialize)]
struct WebDeviceApproveRequest {
    user_code: String,
    /// agent_id to bind this device to. The pending device must be approved
    /// before the daemon's polling /device/token call returns 200.
    agent_id: String,
}

async fn web_device_approve(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<WebDeviceApproveRequest>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let user_code = req.user_code.trim().to_uppercase();
    let agent_id = req.agent_id.trim().to_string();

    let updated = sqlx::query(
        "UPDATE pending_devices SET status = 'approved', agent_id = ?, approved_at = datetime('now') \
         WHERE user_code = ? AND status = 'pending'",
    )
    .bind(&agent_id)
    .bind(&user_code)
    .execute(&state.pool)
    .await?;

    if updated.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "No pending device with user_code '{}'",
            user_code
        )));
    }

    audit::write(&state, Some(&agent_id), None, "device_approve", Some(&user_code), "success").await;
    Ok(Json(json!({ "approved": true, "user_code": user_code, "agent_id": agent_id })))
}

async fn list_devices(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<Value>>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    type DeviceRow = (String, String, String, Option<String>, String, Option<String>);
    let rows: Vec<DeviceRow> =
        sqlx::query_as(
            "SELECT id, user_code, status, agent_id, created_at, approved_at \
             FROM pending_devices ORDER BY created_at DESC LIMIT 200",
        )
        .fetch_all(&state.pool)
        .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, uc, st, ag, ct, ap)| {
                json!({
                    "id": id,
                    "user_code": uc,
                    "status": st,
                    "agent_id": ag,
                    "created_at": ct,
                    "approved_at": ap,
                })
            })
            .collect(),
    ))
}

async fn delete_device(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(agent_id): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let result = sqlx::query("DELETE FROM pending_devices WHERE agent_id = ?")
        .bind(&agent_id)
        .execute(&state.pool)
        .await?;

    audit::write(&state, Some(&agent_id), None, "device_delete", None, "success").await;
    Ok(Json(json!({ "deleted": true, "rows": result.rows_affected() })))
}

// ─── Pending grants (UNCERTAINTIES #16 — first-access approval) ──────────

const PENDING_GRANT_SELECT: &str =
    "SELECT id, agent_id, project_name, namespace, requested_keys, approved_keys, \
            status, requested_at, decided_at, decided_by, auto_approval_until, source_ip \
     FROM pending_grants";

async fn list_pending_grants(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<PendingGrantListItem>>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let rows = sqlx::query_as::<_, PendingGrant>(
        &format!("{} ORDER BY requested_at DESC LIMIT 500", PENDING_GRANT_SELECT),
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows.into_iter().map(Into::into).collect()))
}

async fn approve_pending_grant(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<ApproveGrantRequest>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let row = sqlx::query_as::<_, PendingGrant>(
        &format!("{} WHERE id = ?", PENDING_GRANT_SELECT),
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("pending_grant '{}' not found", id)))?;

    if row.status != "pending" {
        return Err(AppError::Conflict(format!(
            "pending_grant '{}' is already {}",
            id, row.status
        )));
    }

    // Default to approving exactly the requested set; allow narrowing.
    let requested = row.requested_keys_vec();
    let approved: Vec<String> = match req.approved_keys {
        Some(list) => {
            let req_set: std::collections::HashSet<&str> =
                requested.iter().map(|s| s.as_str()).collect();
            for k in &list {
                if !req_set.contains(k.as_str()) {
                    return Err(AppError::BadRequest(format!(
                        "approved_keys contains '{}' which was not in requested_keys",
                        k
                    )));
                }
            }
            list
        }
        None => requested.clone(),
    };
    let approved_json = serde_json::to_string(&approved).unwrap();

    let until =
        chrono::Utc::now() + chrono::Duration::days(AUTO_APPROVAL_WINDOW_DAYS);
    let until_str = until.format("%Y-%m-%d %H:%M:%S").to_string();

    sqlx::query(
        "UPDATE pending_grants SET status = 'approved', approved_keys = ?, \
            decided_at = datetime('now'), decided_by = 'admin', auto_approval_until = ? \
         WHERE id = ?",
    )
    .bind(&approved_json)
    .bind(&until_str)
    .bind(&id)
    .execute(&state.pool)
    .await?;

    audit::write(
        &state,
        Some(&row.agent_id),
        Some(&row.project_name),
        "pending_grant_approve",
        Some(&id),
        "success",
    )
    .await;

    Ok(Json(json!({
        "approved": true,
        "id": id,
        "approved_keys": approved,
        "auto_approval_until": until_str,
    })))
}

async fn deny_pending_grant(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let row = sqlx::query_as::<_, PendingGrant>(
        &format!("{} WHERE id = ?", PENDING_GRANT_SELECT),
    )
    .bind(&id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("pending_grant '{}' not found", id)))?;

    if row.status != "pending" {
        return Err(AppError::Conflict(format!(
            "pending_grant '{}' is already {}",
            id, row.status
        )));
    }

    sqlx::query(
        "UPDATE pending_grants SET status = 'denied', decided_at = datetime('now'), \
                                   decided_by = 'admin' WHERE id = ?",
    )
    .bind(&id)
    .execute(&state.pool)
    .await?;

    audit::write(
        &state,
        Some(&row.agent_id),
        Some(&row.project_name),
        "pending_grant_deny",
        Some(&id),
        "denied",
    )
    .await;

    Ok(Json(json!({"denied": true, "id": id})))
}

async fn delete_pending_grant(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let result = sqlx::query("DELETE FROM pending_grants WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!("pending_grant '{}' not found", id)));
    }

    audit::write(&state, None, None, "pending_grant_delete", Some(&id), "success").await;
    Ok(Json(json!({"deleted": true, "id": id})))
}

// ─── allowed_daemon_versions / daemon_sessions (#17) ────────────────────

async fn list_allowed_daemon_versions(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<AllowedDaemonVersion>>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let rows = sqlx::query_as::<_, AllowedDaemonVersion>(
        "SELECT binary_sha256, version, description, enabled, created_at \
         FROM allowed_daemon_versions ORDER BY created_at DESC",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(rows))
}

async fn create_allowed_daemon_version(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(req): Json<CreateAllowedDaemonVersion>,
) -> Result<(StatusCode, Json<Value>), AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let sha = req.binary_sha256.trim().to_lowercase();
    if sha.len() != 64 || !sha.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(AppError::BadRequest(
            "binary_sha256 must be 64 hex characters".into(),
        ));
    }

    let enabled: i64 = if req.enabled.unwrap_or(true) { 1 } else { 0 };

    sqlx::query(
        "INSERT INTO allowed_daemon_versions (binary_sha256, version, description, enabled) \
         VALUES (?, ?, ?, ?)",
    )
    .bind(&sha)
    .bind(&req.version)
    .bind(&req.description)
    .bind(enabled)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint") {
            AppError::Conflict(format!(
                "binary_sha256 '{}' already in allowlist",
                sha
            ))
        } else {
            AppError::Database(e)
        }
    })?;

    audit::write(
        &state,
        None,
        None,
        "allowed_daemon_version_add",
        Some(&sha),
        "success",
    )
    .await;

    Ok((
        StatusCode::CREATED,
        Json(json!({"binary_sha256": sha, "enabled": enabled == 1})),
    ))
}

async fn delete_allowed_daemon_version(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(sha): Path<String>,
) -> Result<Json<Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let result = sqlx::query("DELETE FROM allowed_daemon_versions WHERE binary_sha256 = ?")
        .bind(&sha)
        .execute(&state.pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "binary_sha256 '{}' not in allowlist",
            sha
        )));
    }

    audit::write(
        &state,
        None,
        None,
        "allowed_daemon_version_remove",
        Some(&sha),
        "success",
    )
    .await;
    Ok(Json(json!({"deleted": true})))
}

async fn list_daemon_sessions(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<Value>>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    type DaemonSessionRow = (
        String,
        String,
        String,
        Option<String>,
        Option<i64>,
        Option<i64>,
        Option<String>,
        String,
        String,
        Option<String>,
    );
    let rows: Vec<DaemonSessionRow> = sqlx::query_as(
        "SELECT session_id, agent_id, binary_sha256, daemon_version, daemon_pid, \
                daemon_uid, hostname, created_at, expires_at, revoked_at \
         FROM daemon_sessions ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(
                |(sid, ag, sha, ver, pid, uid, host, created, exp, rev)| {
                    json!({
                        "session_id": sid,
                        "agent_id": ag,
                        "binary_sha256": sha,
                        "daemon_version": ver,
                        "daemon_pid": pid,
                        "daemon_uid": uid,
                        "hostname": host,
                        "created_at": created,
                        "expires_at": exp,
                        "revoked_at": rev,
                    })
                },
            )
            .collect(),
    ))
}



// ─── Project-secret grants (#11 ACL) ─────────────────────────────────────

async fn list_project_grants(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(project_name): Path<String>,
) -> Result<Json<Vec<GrantDetail>>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let rows: Vec<(String, String, Option<String>, String, String, String)> = sqlx::query_as(
        "SELECT g.id, s.key_path, g.env_var_name, g.granted_by, g.granted_at, s.namespace \
         FROM project_secret_grants g \
         JOIN secrets s ON s.id = g.secret_id \
         WHERE g.project_name = ? \
         ORDER BY g.granted_at DESC",
    )
    .bind(&project_name)
    .fetch_all(&state.pool)
    .await?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, key_path, env_var, granted_by, granted_at, ns)| {
                let env_var_name = env_var
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| {
                        key_path
                            .rsplit('/')
                            .next()
                            .unwrap_or(&key_path)
                            .to_uppercase()
                    });
                GrantDetail {
                    id,
                    project_name: project_name.clone(),
                    secret_id: String::new(), // omitted from list for brevity
                    secret_key_path: key_path,
                    secret_namespace: ns,
                    env_var_name,
                    granted_by,
                    granted_at,
                }
            })
            .collect(),
    ))
}

async fn create_project_grant(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(project_name): Path<String>,
    Json(req): Json<CreateGrantRequest>,
) -> Result<(axum::http::StatusCode, Json<serde_json::Value>), AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    // Verify secret exists.
    let secret_row: Option<(String, String)> =
        sqlx::query_as("SELECT id, key_path FROM secrets WHERE id = ?")
            .bind(&req.secret_id)
            .fetch_optional(&state.pool)
            .await?;
    let (secret_id, key_path) = secret_row.ok_or_else(|| {
        AppError::NotFound(format!("Secret '{}' not found", req.secret_id))
    })?;

    // Grants can be staged before the first discover creates the project row.

    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO project_secret_grants (id, project_name, secret_id, env_var_name, granted_by) \
         VALUES (?, ?, ?, ?, 'admin')",
    )
    .bind(&id)
    .bind(&project_name)
    .bind(&secret_id)
    .bind(&req.env_var_name)
    .execute(&state.pool)
    .await
    .map_err(|e| {
        if e.to_string().contains("UNIQUE constraint") {
            AppError::Conflict(format!(
                "Grant for secret '{}' already exists on project '{}'",
                secret_id, project_name
            ))
        } else {
            AppError::Database(e)
        }
    })?;

    audit::write(
        &state,
        None,
        Some(&project_name),
        "create_project_grant",
        Some(&key_path),
        "success",
    )
    .await;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(serde_json::json!({
            "id": id,
            "project_name": project_name,
            "secret_id": secret_id,
            "secret_key_path": key_path,
            "env_var_name": req.env_var_name,
        })),
    ))
}

async fn delete_project_grant(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((project_name, grant_id)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_admin_token(&headers, &state.admin_token_hash)?;

    let result =
        sqlx::query("DELETE FROM project_secret_grants WHERE id = ? AND project_name = ?")
            .bind(&grant_id)
            .bind(&project_name)
            .execute(&state.pool)
            .await?;

    if result.rows_affected() == 0 {
        return Err(AppError::NotFound(format!(
            "Grant '{}' not found on project '{}'",
            grant_id, project_name
        )));
    }

    audit::write(
        &state,
        None,
        Some(&project_name),
        "delete_project_grant",
        Some(&grant_id),
        "success",
    )
    .await;

    Ok(Json(serde_json::json!({ "deleted": true, "id": grant_id })))
}
