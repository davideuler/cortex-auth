use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    audit,
    crypto,
    error::AppError,
    models::{
        agent::{Agent, AgentClaims},
        policy::Policy,
        project::{
            parse_env_file, DiscoverRequest, DiscoverResponse, SecretsResponse,
            DEFAULT_TOKEN_TTL_MINUTES,
        },
    },
    state::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/discover", post(discover))
}

pub fn project_router() -> Router<AppState> {
    Router::new()
        .route("/secrets/:project_name", get(get_secrets))
        .route("/config/:project_name/:app_name", get(get_config))
}

const PROJECT_SELECT: &str = "SELECT id, project_name, project_token_hash, env_mappings, namespace, created_at, updated_at, token_expires_at, token_revoked_at FROM projects";

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Unauthorized("Missing or invalid Authorization header".into()))
}

fn agent_matches_pattern(agent_id: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return agent_id.starts_with(prefix);
    }
    agent_id == pattern
}

fn path_matches_pattern(path: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    path == pattern
}

fn path_allowed_by_policies(path: &str, matching_policies: &[Policy]) -> bool {
    if matching_policies.is_empty() {
        return true;
    }

    let denied: Vec<String> = matching_policies
        .iter()
        .flat_map(|p| serde_json::from_str::<Vec<String>>(&p.denied_paths).unwrap_or_default())
        .collect();

    if denied.iter().any(|pat| path_matches_pattern(path, pat)) {
        return false;
    }

    let allowed: Vec<String> = matching_policies
        .iter()
        .flat_map(|p| serde_json::from_str::<Vec<String>>(&p.allowed_paths).unwrap_or_default())
        .collect();

    if allowed.is_empty() {
        return true;
    }

    allowed.iter().any(|pat| path_matches_pattern(path, pat))
}

/// SQLite-friendly format matching `datetime('now')` output ("YYYY-MM-DD HH:MM:SS").
fn format_sqlite_timestamp(t: chrono::DateTime<Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
}

async fn discover(
    State(state): State<AppState>,
    Json(req): Json<DiscoverRequest>,
) -> Result<Json<DiscoverResponse>, AppError> {
    let agent = sqlx::query_as::<_, Agent>(
        "SELECT id, agent_id, jwt_secret_encrypted, description, namespace, created_at FROM agents WHERE agent_id = ?",
    )
    .bind(&req.agent_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Unknown agent_id".into()))?;

    let jwt_secret = crypto::decrypt(&agent.jwt_secret_encrypted, &state.config.encryption_key)
        .map_err(AppError::Internal)?;

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let token_data = decode::<AgentClaims>(
        &req.auth_proof,
        &DecodingKey::from_secret(jwt_secret.as_bytes()),
        &validation,
    )
    .map_err(|_| AppError::Unauthorized("Invalid auth_proof JWT".into()))?;

    if token_data.claims.sub != req.agent_id {
        return Err(AppError::Unauthorized(
            "JWT subject does not match agent_id".into(),
        ));
    }

    let agent_id = agent.agent_id.clone();
    let namespace = agent.namespace.clone();

    let project_name = &req.context.project_name;
    let env_keys = parse_env_file(&req.context.file_content);

    let all_policies = sqlx::query_as::<_, Policy>(
        "SELECT id, policy_name, agent_pattern, allowed_paths, denied_paths, created_at FROM policies",
    )
    .fetch_all(&state.pool)
    .await?;

    let matching_policies: Vec<Policy> = all_policies
        .into_iter()
        .filter(|p| agent_matches_pattern(&agent_id, &p.agent_pattern))
        .collect();

    let secrets = sqlx::query_as::<_, crate::models::secret::Secret>(
        "SELECT id, key_path, secret_type, encrypted_value, description, namespace, created_at, updated_at FROM secrets WHERE secret_type = 'KEY_VALUE' AND namespace = ?",
    )
    .bind(&namespace)
    .fetch_all(&state.pool)
    .await?;

    let secret_map: HashMap<String, String> = secrets
        .iter()
        .filter(|s| path_allowed_by_policies(&s.key_path, &matching_policies))
        .map(|s| (s.key_path.to_lowercase().replace('/', "_"), s.key_path.clone()))
        .collect();

    let mut mapped_keys: HashMap<String, String> = HashMap::new();
    let mut unmatched: Vec<String> = Vec::new();

    for env_key in &env_keys {
        let normalized = env_key.to_lowercase();
        if let Some(secret_path) = secret_map.get(&normalized) {
            mapped_keys.insert(env_key.clone(), secret_path.clone());
        } else {
            unmatched.push(env_key.clone());
        }
    }

    let full_matched = unmatched.is_empty() && !env_keys.is_empty();

    let existing = sqlx::query_as::<_, crate::models::project::Project>(
        &format!("{} WHERE project_name = ?", PROJECT_SELECT),
    )
    .bind(project_name)
    .fetch_optional(&state.pool)
    .await?;

    let now = Utc::now();
    let expires_at = now + Duration::minutes(DEFAULT_TOKEN_TTL_MINUTES);
    let expires_at_str = format_sqlite_timestamp(expires_at);

    let project_token = if let Some(existing_proj) = &existing {
        // Auto-rotate when caller explicitly asks, OR when the existing token is
        // already expired/revoked. This means an agent re-running discover after
        // a 120-minute idle window seamlessly receives a fresh token.
        let status = existing_proj.token_status();
        let auto_rotate = status == "expired" || status == "revoked";

        if req.regenerate_token.unwrap_or(false) || auto_rotate {
            let token = crypto::generate_token();
            let hash = crypto::hash_token(&token);
            let mappings_json = serde_json::to_string(&mapped_keys).unwrap();

            sqlx::query(
                "UPDATE projects SET project_token_hash = ?, env_mappings = ?, namespace = ?, token_expires_at = ?, token_revoked_at = NULL, updated_at = datetime('now') WHERE project_name = ?",
            )
            .bind(&hash)
            .bind(&mappings_json)
            .bind(&namespace)
            .bind(&expires_at_str)
            .bind(project_name)
            .execute(&state.pool)
            .await?;

            audit::write(
                &state,
                Some(&agent_id),
                Some(project_name),
                if auto_rotate && !req.regenerate_token.unwrap_or(false) {
                    "auto_rotate_token"
                } else {
                    "rotate_token"
                },
                Some(project_name),
                "success",
            )
            .await;

            token
        } else {
            return Err(AppError::Conflict(
                "Project already registered with an active token. Pass regenerate_token=true to rotate, or wait for it to expire."
                    .into(),
            ));
        }
    } else {
        let token = crypto::generate_token();
        let hash = crypto::hash_token(&token);
        let id = Uuid::new_v4().to_string();
        let mappings_json = serde_json::to_string(&mapped_keys).unwrap();

        sqlx::query(
            "INSERT INTO projects (id, project_name, project_token_hash, env_mappings, namespace, token_expires_at) VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(project_name)
        .bind(&hash)
        .bind(&mappings_json)
        .bind(&namespace)
        .bind(&expires_at_str)
        .execute(&state.pool)
        .await?;

        token
    };

    audit::write(
        &state,
        Some(&agent_id),
        Some(project_name),
        "discover",
        Some(project_name),
        "success",
    )
    .await;

    Ok(Json(DiscoverResponse {
        mapped_keys,
        full_matched,
        project_token,
        token_expires_at: expires_at_str,
        token_ttl_seconds: DEFAULT_TOKEN_TTL_MINUTES * 60,
        unmatched_keys: unmatched,
        namespace,
    }))
}

async fn get_project_by_token(
    state: &AppState,
    project_name: &str,
    token: &str,
) -> Result<crate::models::project::Project, AppError> {
    let project = sqlx::query_as::<_, crate::models::project::Project>(
        &format!("{} WHERE project_name = ?", PROJECT_SELECT),
    )
    .bind(project_name)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Project '{}' not found", project_name)))?;

    if !crypto::verify_token(token, &project.project_token_hash) {
        return Err(AppError::Unauthorized("Invalid project token".into()));
    }

    // Reject revoked tokens before checking expiration so the caller gets the
    // most actionable error code.
    if project.token_revoked_at.is_some() {
        audit::write(
            state,
            None,
            Some(project_name),
            "token_validation",
            Some(project_name),
            "revoked",
        )
        .await;
        return Err(AppError::token_revoked());
    }

    if project.token_status() == "expired" {
        audit::write(
            state,
            None,
            Some(project_name),
            "token_validation",
            Some(project_name),
            "expired",
        )
        .await;
        return Err(AppError::token_expired());
    }

    Ok(project)
}

async fn get_secrets(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(project_name): Path<String>,
) -> Result<Json<SecretsResponse>, AppError> {
    let token = extract_bearer_token(&headers)?;
    let project = get_project_by_token(&state, &project_name, &token).await?;

    let mappings = project.get_env_mappings();
    let mut env_vars: HashMap<String, String> = HashMap::new();

    for (env_var, secret_path) in &mappings {
        let secret = sqlx::query_as::<_, crate::models::secret::Secret>(
            "SELECT id, key_path, secret_type, encrypted_value, description, namespace, created_at, updated_at FROM secrets WHERE key_path = ? AND secret_type = 'KEY_VALUE' AND namespace = ?",
        )
        .bind(secret_path.as_str())
        .bind(&project.namespace)
        .fetch_optional(&state.pool)
        .await?;

        if let Some(s) = secret {
            if let Ok(val) = crypto::decrypt(&s.encrypted_value, &state.config.encryption_key) {
                env_vars.insert(env_var.clone(), val);
            }
        }
    }

    audit::write(
        &state,
        None,
        Some(&project_name),
        "get_secrets",
        Some(&project_name),
        "success",
    )
    .await;

    Ok(Json(SecretsResponse { env_vars }))
}

async fn get_config(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((project_name, app_name)): Path<(String, String)>,
) -> Result<String, AppError> {
    let token = extract_bearer_token(&headers)?;
    let project = get_project_by_token(&state, &project_name, &token).await?;

    let template_secret = sqlx::query_as::<_, crate::models::secret::Secret>(
        "SELECT id, key_path, secret_type, encrypted_value, description, namespace, created_at, updated_at FROM secrets WHERE key_path = ? AND secret_type = 'TEMPLATE_CONFIG' AND namespace = ?",
    )
    .bind(&app_name)
    .bind(&project.namespace)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Template '{}' not found", app_name)))?;

    let template_content =
        crypto::decrypt(&template_secret.encrypted_value, &state.config.encryption_key)
            .map_err(AppError::Internal)?;

    let mappings = project.get_env_mappings();
    let mut context: HashMap<String, String> = HashMap::new();
    for secret_path in mappings.values() {
        let secret = sqlx::query_as::<_, crate::models::secret::Secret>(
            "SELECT id, key_path, secret_type, encrypted_value, description, namespace, created_at, updated_at FROM secrets WHERE key_path = ? AND secret_type = 'KEY_VALUE' AND namespace = ?",
        )
        .bind(secret_path.as_str())
        .bind(&project.namespace)
        .fetch_optional(&state.pool)
        .await?;

        if let Some(s) = secret {
            if let Ok(val) = crypto::decrypt(&s.encrypted_value, &state.config.encryption_key) {
                let normalized = secret_path.replace('/', "_");
                context.insert(secret_path.clone(), val.clone());
                context.insert(normalized, val);
            }
        }
    }

    let handlebars = handlebars::Handlebars::new();
    let rendered = handlebars
        .render_template(&template_content, &context)
        .map_err(|e| AppError::Internal(anyhow::anyhow!("Template render failed: {}", e)))?;

    audit::write(
        &state,
        None,
        Some(&project_name),
        "get_config",
        Some(&app_name),
        "success",
    )
    .await;

    Ok(rendered)
}
