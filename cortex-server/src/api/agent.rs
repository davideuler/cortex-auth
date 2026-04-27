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

const PROJECT_SELECT: &str = "SELECT id, project_name, project_token_hash, env_mappings, namespace, scope, created_at, updated_at, token_expires_at, token_revoked_at FROM projects";
const SECRET_SELECT_FULL: &str = "SELECT id, key_path, secret_type, encrypted_value, wrapped_dek, kek_version, description, namespace, is_honey_token, created_at, updated_at FROM secrets";
const AGENT_SELECT_FULL: &str =
    "SELECT id, agent_id, jwt_secret_encrypted, wrapped_dek, kek_version, description, namespace, created_at FROM agents";

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Unauthorized("Missing or invalid Authorization header".into()))
}

/// Extract caller metadata from optional `X-Cortex-Caller-*` headers. The CLI
/// is expected to populate these so audit rows record exactly which process
/// fetched a secret. All fields are advisory — a malicious caller can lie,
/// but the audit row still pins down the network identity (source IP, agent
/// session) that signed the request.
fn extract_caller_context(headers: &HeaderMap) -> crate::audit::CallerContext {
    fn h(headers: &HeaderMap, name: &str) -> Option<String> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }
    fn h_int(headers: &HeaderMap, name: &str) -> Option<i64> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok())
    }
    crate::audit::CallerContext {
        caller_pid: h_int(headers, "x-cortex-caller-pid"),
        caller_binary_sha256: h(headers, "x-cortex-caller-binary-sha256"),
        caller_argv_hash: h(headers, "x-cortex-caller-argv-hash"),
        caller_cwd: h(headers, "x-cortex-caller-cwd"),
        caller_git_commit: h(headers, "x-cortex-caller-git-commit"),
        source_ip: h(headers, "x-forwarded-for").or_else(|| h(headers, "x-real-ip")),
        hostname: h(headers, "x-cortex-hostname"),
        os: h(headers, "x-cortex-os"),
    }
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

fn open_secret_value(
    state: &AppState,
    s: &crate::models::secret::Secret,
) -> Option<String> {
    let wrapped = s.wrapped_dek.as_deref()?;
    crypto::open_envelope(&s.encrypted_value, wrapped, &state.kek).ok()
}

async fn discover(
    State(state): State<AppState>,
    Json(req): Json<DiscoverRequest>,
) -> Result<Json<DiscoverResponse>, AppError> {
    let agent = sqlx::query_as::<_, Agent>(
        &format!("{} WHERE agent_id = ?", AGENT_SELECT_FULL),
    )
    .bind(&req.agent_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Unknown agent_id".into()))?;

    let wrapped = agent
        .wrapped_dek
        .as_deref()
        .ok_or_else(|| AppError::Internal(anyhow::anyhow!("agent missing wrapped_dek")))?;
    let jwt_secret = crypto::open_envelope(&agent.jwt_secret_encrypted, wrapped, &state.kek)
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
        &format!(
            "{} WHERE secret_type = 'KEY_VALUE' AND namespace = ?",
            SECRET_SELECT_FULL
        ),
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

    // Scope = the set of secret key_paths this token will be allowed to read.
    // Frozen at discover time so re-issuing with new env_mappings cannot
    // implicitly broaden access without going through discover again.
    let scope_paths: Vec<String> = {
        let mut v: Vec<String> = mapped_keys.values().cloned().collect();
        v.sort();
        v.dedup();
        v
    };
    let scope_json = serde_json::to_string(&scope_paths).unwrap();

    let project_token = if let Some(existing_proj) = &existing {
        let status = existing_proj.token_status();
        let auto_rotate = status == "expired" || status == "revoked";

        if req.regenerate_token.unwrap_or(false) || auto_rotate {
            let token = crypto::generate_token();
            let hash = crypto::hash_token(&token);
            let mappings_json = serde_json::to_string(&mapped_keys).unwrap();

            sqlx::query(
                "UPDATE projects SET project_token_hash = ?, env_mappings = ?, namespace = ?, scope = ?, token_expires_at = ?, token_revoked_at = NULL, updated_at = datetime('now') WHERE project_name = ?",
            )
            .bind(&hash)
            .bind(&mappings_json)
            .bind(&namespace)
            .bind(&scope_json)
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
            "INSERT INTO projects (id, project_name, project_token_hash, env_mappings, namespace, scope, token_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(project_name)
        .bind(&hash)
        .bind(&mappings_json)
        .bind(&namespace)
        .bind(&scope_json)
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
        scope: scope_paths,
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
    let caller = extract_caller_context(&headers);
    let project = get_project_by_token(&state, &project_name, &token).await?;

    let mappings = project.get_env_mappings();
    let scope = project.get_scope();
    let scope_set: std::collections::HashSet<&str> =
        scope.iter().map(|s| s.as_str()).collect();
    let mut env_vars: HashMap<String, String> = HashMap::new();

    for (env_var, secret_path) in &mappings {
        // Enforce the frozen-at-discover scope. Empty scope means "legacy
        // project predating the scope column" — fall back to env_mappings.
        if !scope_set.is_empty() && !scope_set.contains(secret_path.as_str()) {
            continue;
        }

        let secret = sqlx::query_as::<_, crate::models::secret::Secret>(
            &format!(
                "{} WHERE key_path = ? AND secret_type = 'KEY_VALUE' AND namespace = ?",
                SECRET_SELECT_FULL
            ),
        )
        .bind(secret_path.as_str())
        .bind(&project.namespace)
        .fetch_optional(&state.pool)
        .await?;

        if let Some(s) = secret {
            if s.is_honey() {
                trigger_honey_token_alarm(&state, &project_name, &s.key_path).await;
                return Err(AppError::Unauthorized(
                    "Secret access denied".into(),
                ));
            }
            if let Some(val) = open_secret_value(&state, &s) {
                env_vars.insert(env_var.clone(), val);
            }
        }
    }

    audit::write_with_context(
        &state,
        None,
        Some(&project_name),
        "get_secrets",
        Some(&project_name),
        "success",
        &caller,
    )
    .await;

    Ok(Json(SecretsResponse { env_vars }))
}

/// Honey-tokens are decoy secrets that should never be retrieved by a
/// legitimate caller. Reading one is a 100% attack signal: we revoke the
/// project's token immediately and write a high-priority alarm to the audit
/// log. The response to the caller is a generic 401 so they cannot tell
/// whether the secret exists or is a decoy.
async fn trigger_honey_token_alarm(state: &AppState, project_name: &str, key_path: &str) {
    let _ = sqlx::query(
        "UPDATE projects SET token_revoked_at = datetime('now'), updated_at = datetime('now') WHERE project_name = ? AND token_revoked_at IS NULL",
    )
    .bind(project_name)
    .execute(&state.pool)
    .await;

    audit::write(
        state,
        None,
        Some(project_name),
        "honey_token_access",
        Some(key_path),
        "alarm",
    )
    .await;

    tracing::warn!(
        project = %project_name,
        key_path = %key_path,
        "ALARM: honey-token accessed; project token revoked"
    );
}

async fn get_config(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((project_name, app_name)): Path<(String, String)>,
) -> Result<String, AppError> {
    let token = extract_bearer_token(&headers)?;
    let caller = extract_caller_context(&headers);
    let project = get_project_by_token(&state, &project_name, &token).await?;

    let template_secret = sqlx::query_as::<_, crate::models::secret::Secret>(
        &format!(
            "{} WHERE key_path = ? AND secret_type = 'TEMPLATE_CONFIG' AND namespace = ?",
            SECRET_SELECT_FULL
        ),
    )
    .bind(&app_name)
    .bind(&project.namespace)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Template '{}' not found", app_name)))?;

    let template_content = open_secret_value(&state, &template_secret).ok_or_else(|| {
        AppError::Internal(anyhow::anyhow!("Failed to decrypt template body"))
    })?;

    let mappings = project.get_env_mappings();
    let scope = project.get_scope();
    let scope_set: std::collections::HashSet<&str> =
        scope.iter().map(|s| s.as_str()).collect();
    let mut context: HashMap<String, String> = HashMap::new();
    for secret_path in mappings.values() {
        if !scope_set.is_empty() && !scope_set.contains(secret_path.as_str()) {
            continue;
        }
        let secret = sqlx::query_as::<_, crate::models::secret::Secret>(
            &format!(
                "{} WHERE key_path = ? AND secret_type = 'KEY_VALUE' AND namespace = ?",
                SECRET_SELECT_FULL
            ),
        )
        .bind(secret_path.as_str())
        .bind(&project.namespace)
        .fetch_optional(&state.pool)
        .await?;

        if let Some(s) = secret {
            if s.is_honey() {
                trigger_honey_token_alarm(&state, &project_name, &s.key_path).await;
                return Err(AppError::Unauthorized("Secret access denied".into()));
            }
            if let Some(val) = open_secret_value(&state, &s) {
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

    audit::write_with_context(
        &state,
        None,
        Some(&project_name),
        "get_config",
        Some(&app_name),
        "success",
        &caller,
    )
    .await;

    Ok(rendered)
}
