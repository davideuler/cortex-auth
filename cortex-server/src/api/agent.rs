use axum::{
    body::Bytes,
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    audit,
    crypto,
    error::AppError,
    models::{
        agent::Agent,
        pending_grant::{PendingGrant, AUTO_APPROVAL_WINDOW_DAYS},
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

const PROJECT_SELECT: &str = "SELECT id, project_name, project_token_hash, env_mappings, \
    namespace, scope, created_at, updated_at, token_expires_at, token_revoked_at, signed_token_jti, \
    agent_id FROM projects";
const SECRET_SELECT_FULL: &str = "SELECT id, key_path, secret_type, encrypted_value, wrapped_dek, \
    kek_version, description, namespace, is_honey_token, created_at, updated_at FROM secrets";
const AGENT_SELECT_FULL: &str =
    "SELECT id, agent_id, description, namespace, created_at, agent_pub FROM agents";

fn extract_bearer_token(headers: &HeaderMap) -> Result<String, AppError> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string())
        .ok_or_else(|| AppError::Unauthorized("Missing or invalid Authorization header".into()))
}

/// Extract caller metadata from optional `X-Cortex-Caller-*` headers.
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

fn extract_source_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string()
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

/// Returns (policy_name_or_"", allowed) for audit logging.
fn path_decision_by_policies(path: &str, matching_policies: &[Policy]) -> (String, bool) {
    if matching_policies.is_empty() {
        return (String::new(), true);
    }
    for p in matching_policies {
        let denied: Vec<String> =
            serde_json::from_str(&p.denied_paths).unwrap_or_default();
        if denied.iter().any(|pat| path_matches_pattern(path, pat)) {
            return (p.policy_name.clone(), false);
        }
    }
    let has_any_allow = matching_policies.iter().any(|p| {
        let allowed: Vec<String> =
            serde_json::from_str(&p.allowed_paths).unwrap_or_default();
        !allowed.is_empty()
    });
    if !has_any_allow {
        return (String::new(), true);
    }
    for p in matching_policies {
        let allowed: Vec<String> =
            serde_json::from_str(&p.allowed_paths).unwrap_or_default();
        if allowed.iter().any(|pat| path_matches_pattern(path, pat)) {
            return (p.policy_name.clone(), true);
        }
    }
    (String::new(), false)
}

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
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<DiscoverResponse>, AppError> {
    let req: DiscoverRequest = serde_json::from_slice(&body)
        .map_err(|e| AppError::BadRequest(format!("Invalid discover JSON: {}", e)))?;

    // ── Rate limiting: 5 /agent/discover per minute per source IP ────────
    let source_ip = extract_source_ip(&headers);
    if !state
        .rate_limiter
        .check(&format!("discover:{}", source_ip), 5, 60)
    {
        return Err(AppError::TooManyRequests(
            "Rate limit: 5 /agent/discover requests per minute per IP".into(),
        ));
    }

    let agent = sqlx::query_as::<_, Agent>(
        &format!("{} WHERE agent_id = ?", AGENT_SELECT_FULL),
    )
    .bind(&req.agent_id)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::Unauthorized("Unknown agent_id".into()))?;

    // ── Ed25519 auth_proof ────────────────────────────────────────────────
    let ts = req
        .ts
        .ok_or_else(|| AppError::Unauthorized("ts required for auth_proof".into()))?;
    let nonce = req
        .nonce
        .as_deref()
        .ok_or_else(|| AppError::Unauthorized("nonce required for auth_proof".into()))?;
    let now = Utc::now().timestamp();
    if (now - ts).abs() > 300 {
        return Err(AppError::Unauthorized(
            "auth_proof ts is more than 5 minutes from server clock".into(),
        ));
    }
    let message = format!("{}|{}|{}|/agent/discover", ts, nonce, req.agent_id);
    crate::ed25519_keys::verify_agent_signature(
        &agent.agent_pub,
        message.as_bytes(),
        &req.auth_proof,
    )
    .map_err(|_| AppError::Unauthorized("Invalid Ed25519 auth_proof".into()))?;

    if state.config.require_request_signing {
        let attested_agent_id = crate::api::daemon::verify_attestation_header(
            &state,
            &headers,
            "POST",
            "/agent/discover",
            &body,
            &format!("agent:{}", req.agent_id),
        )
        .await?;
        if attested_agent_id != req.agent_id {
            return Err(AppError::Unauthorized(
                "daemon attestation agent_id does not match discover agent_id".into(),
            ));
        }
    }

    // ── Nonce replay protection ───────────────────────────────────────────
    {
        let cache_key = format!("{}:{}", req.agent_id, nonce);
        let mut cache = state
            .nonce_cache
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !cache.check_and_insert(cache_key, ts) {
            return Err(AppError::Unauthorized(
                "Nonce replay detected — reuse of (agent_id, nonce) within the 5-minute window"
                    .into(),
            ));
        }
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

    // ── Build env_mappings ────────────────────────────────────────────────
    // Explicit ACL only: env vars are mapped from project_secret_grants.
    // Name-based matching is intentionally not used as an authorization
    // boundary.

    let grant_rows: Vec<(String, Option<String>)> = sqlx::query_as(
        "SELECT s.key_path, g.env_var_name \
         FROM project_secret_grants g \
         JOIN secrets s ON s.id = g.secret_id \
         WHERE g.project_name = ? AND s.namespace = ?",
    )
    .bind(project_name)
    .bind(&namespace)
    .fetch_all(&state.pool)
    .await?;

    let mut mapped_keys: HashMap<String, String> = HashMap::new();
    let mut unmatched: Vec<String> = Vec::new();

    let grant_map: HashMap<String, String> = grant_rows
        .iter()
        .map(|(key_path, env_var)| {
            let var = env_var
                .as_deref()
                .filter(|v| !v.is_empty())
                .map(|v| v.to_uppercase())
                .unwrap_or_else(|| {
                    key_path
                        .rsplit('/')
                        .next()
                        .unwrap_or(key_path.as_str())
                        .to_uppercase()
                });
            (var, key_path.clone())
        })
        .collect();

    for env_key in &env_keys {
        let upper = env_key.to_uppercase();
        if let Some(secret_path) = grant_map.get(&upper) {
            if path_allowed_by_policies(secret_path, &matching_policies) {
                mapped_keys.insert(env_key.clone(), secret_path.clone());
            } else {
                unmatched.push(env_key.clone());
            }
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

    if let Some(existing_proj) = &existing {
        match existing_proj.agent_id.as_deref() {
            Some(owner_agent) if owner_agent == agent_id => {}
            Some(_) => {
                return Err(AppError::Forbidden {
                    code: "project_agent_mismatch",
                    message: format!(
                        "Project '{}' is bound to a different agent.",
                        project_name
                    ),
                    details: None,
                });
            }
            None => {
                return Err(AppError::Forbidden {
                    code: "project_no_agent_binding",
                    message: format!(
                        "Project '{}' exists but has no bound agent. An admin must \
                         bind it via migration or re-creation before it can be discovered.",
                        project_name
                    ),
                    details: None,
                });
            }
        }
    }

    let now = Utc::now();
    let expires_at = now + Duration::minutes(DEFAULT_TOKEN_TTL_MINUTES);
    let expires_at_str = format_sqlite_timestamp(expires_at);

    let scope_paths: Vec<String> = {
        let mut v: Vec<String> = mapped_keys.values().cloned().collect();
        v.sort();
        v.dedup();
        v
    };
    let scope_json = serde_json::to_string(&scope_paths).unwrap();

    // ── First-access human approval ───────────────────────────────────────
    if !scope_paths.is_empty() {
        let source_ip_opt = Some(source_ip.clone()).filter(|s| s != "unknown");

        match check_or_create_pending_grant(
            &state,
            &agent_id,
            project_name,
            &namespace,
            &scope_paths,
            source_ip_opt,
        )
        .await?
        {
            PendingGrantOutcome::Approved => {}
            PendingGrantOutcome::Pending {
                grant_id,
                requested_keys,
                already_pending,
            } => {
                let action = if already_pending {
                    "discover_pending_existing"
                } else {
                    "discover_pending_new"
                };
                audit::write(
                    &state,
                    Some(&agent_id),
                    Some(project_name),
                    action,
                    Some(project_name),
                    "pending",
                )
                .await;
                return Err(AppError::Forbidden {
                    code: "pending_approval",
                    message: format!(
                        "First-time access for agent '{}' to project '{}' is awaiting human \
                         approval at /admin/pending-grants/{}.",
                        agent_id, project_name, grant_id
                    ),
                    details: Some(serde_json::json!({
                        "grant_id": grant_id,
                        "requested_keys": requested_keys,
                        "agent_id": agent_id,
                        "project_name": project_name,
                    })),
                });
            }
            PendingGrantOutcome::Denied => {
                audit::write(
                    &state,
                    Some(&agent_id),
                    Some(project_name),
                    "discover_denied",
                    Some(project_name),
                    "denied",
                )
                .await;
                return Err(AppError::Forbidden {
                    code: "grant_denied",
                    message: "Access for this (agent, project) was explicitly denied.".into(),
                    details: None,
                });
            }
        }
    }

    // ── Issue / rotate project token ──────────────────────────────────────
    let new_jti = Uuid::new_v4().to_string();

    let project_token = if let Some(existing_proj) = &existing {
        let status = existing_proj.token_status();
        let auto_rotate = status == "expired" || status == "revoked";

        if req.regenerate_token.unwrap_or(false) || auto_rotate {
            let token = crypto::generate_token();
            let hash = crypto::hash_token(&token);
            let mappings_json = serde_json::to_string(&mapped_keys).unwrap();

            sqlx::query(
                "UPDATE projects SET project_token_hash = ?, env_mappings = ?, namespace = ?, \
                 scope = ?, token_expires_at = ?, token_revoked_at = NULL, signed_token_jti = ?, \
                 agent_id = ?, updated_at = datetime('now') WHERE project_name = ?",
            )
            .bind(&hash)
            .bind(&mappings_json)
            .bind(&namespace)
            .bind(&scope_json)
            .bind(&expires_at_str)
            .bind(&new_jti)
            .bind(&agent_id)
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
                "Project already registered with an active token. Pass regenerate_token=true \
                 to rotate, or wait for it to expire."
                    .into(),
            ));
        }
    } else {
        let token = crypto::generate_token();
        let hash = crypto::hash_token(&token);
        let id = Uuid::new_v4().to_string();
        let mappings_json = serde_json::to_string(&mapped_keys).unwrap();

        sqlx::query(
            "INSERT INTO projects (id, project_name, agent_id, project_token_hash, env_mappings, \
             namespace, scope, token_expires_at, signed_token_jti) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(project_name)
        .bind(&agent_id)
        .bind(&hash)
        .bind(&mappings_json)
        .bind(&namespace)
        .bind(&scope_json)
        .bind(&expires_at_str)
        .bind(&new_jti)
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

    let signed_project_token = if req.signed_token {
        let claims = serde_json::json!({
            "iss": "cortex-auth",
            "sub": project_name,
            "aud": "cortex-cli",
            "iat": Utc::now().timestamp(),
            "exp": expires_at.timestamp(),
            "jti": new_jti,
            "scope": scope_paths,
            "namespace": namespace,
            "project_id": project_name,
        });
        Some(
            crate::ed25519_keys::sign_jwt(&state.server_keypair, &claims)
                .map_err(AppError::Internal)?,
        )
    } else {
        None
    };

    Ok(Json(DiscoverResponse {
        mapped_keys,
        full_matched,
        project_token,
        token_expires_at: expires_at_str,
        token_ttl_seconds: DEFAULT_TOKEN_TTL_MINUTES * 60,
        unmatched_keys: unmatched,
        namespace,
        scope: scope_paths,
        signed_project_token,
    }))
}

enum PendingGrantOutcome {
    Approved,
    Pending {
        grant_id: String,
        requested_keys: Vec<String>,
        already_pending: bool,
    },
    Denied,
}

async fn check_or_create_pending_grant(
    state: &AppState,
    agent_id: &str,
    project_name: &str,
    namespace: &str,
    requested_keys: &[String],
    source_ip: Option<String>,
) -> Result<PendingGrantOutcome, AppError> {
    let existing: Vec<PendingGrant> = sqlx::query_as::<_, PendingGrant>(
        "SELECT id, agent_id, project_name, namespace, requested_keys, approved_keys, \
                status, requested_at, decided_at, decided_by, auto_approval_until, source_ip \
         FROM pending_grants \
         WHERE agent_id = ? AND project_name = ? AND namespace = ? \
         ORDER BY requested_at DESC",
    )
    .bind(agent_id)
    .bind(project_name)
    .bind(namespace)
    .fetch_all(&state.pool)
    .await?;

    if existing.iter().any(|g| g.covers(requested_keys)) {
        return Ok(PendingGrantOutcome::Approved);
    }

    if existing
        .iter()
        .any(|g| g.status == "denied" && g.decided_at.is_some())
    {
        return Ok(PendingGrantOutcome::Denied);
    }

    if let Some(pending) = existing.iter().find(|g| g.status == "pending") {
        return Ok(PendingGrantOutcome::Pending {
            grant_id: pending.id.clone(),
            requested_keys: pending.requested_keys_vec(),
            already_pending: true,
        });
    }

    let id = Uuid::new_v4().to_string();
    let requested_json = serde_json::to_string(requested_keys).unwrap_or_else(|_| "[]".into());
    sqlx::query(
        "INSERT INTO pending_grants (id, agent_id, project_name, namespace, requested_keys, \
                                     status, source_ip) \
         VALUES (?, ?, ?, ?, ?, 'pending', ?)",
    )
    .bind(&id)
    .bind(agent_id)
    .bind(project_name)
    .bind(namespace)
    .bind(&requested_json)
    .bind(source_ip.as_deref())
    .execute(&state.pool)
    .await?;

    crate::notifications::dispatch(
        state,
        crate::notifications::NotificationEvent::PendingGrant {
            grant_id: id.clone(),
            agent_id: agent_id.to_string(),
            project_name: project_name.to_string(),
            requested_keys: requested_keys.to_vec(),
            source_ip,
        },
    );

    Ok(PendingGrantOutcome::Pending {
        grant_id: id,
        requested_keys: requested_keys.to_vec(),
        already_pending: false,
    })
}

const _AUTO_APPROVAL_WINDOW_DAYS: i64 = AUTO_APPROVAL_WINDOW_DAYS;

struct VerifiedProject {
    project: crate::models::project::Project,
    auth_token_id: String,
}

async fn get_project_by_token(
    state: &AppState,
    project_name: &str,
    token: &str,
) -> Result<VerifiedProject, AppError> {
    let project = sqlx::query_as::<_, crate::models::project::Project>(
        &format!("{} WHERE project_name = ?", PROJECT_SELECT),
    )
    .bind(project_name)
    .fetch_optional(&state.pool)
    .await?
    .ok_or_else(|| AppError::NotFound(format!("Project '{}' not found", project_name)))?;

    let mut auth_token_id = crypto::hash_token(token);
    let token_ok = if token.matches('.').count() == 2 {
        match crate::ed25519_keys::verify_jwt::<serde_json::Value>(&state.server_keypair, token) {
            Ok(claims) => {
                let exp = claims.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
                if exp != 0 && exp < Utc::now().timestamp() {
                    return Err(AppError::token_expired());
                }
                let sub = claims.get("sub").and_then(|v| v.as_str()).unwrap_or("");
                if sub != project_name {
                    return Err(AppError::Unauthorized("token sub != project".into()));
                }
                if let Some(jti) = claims.get("jti").and_then(|v| v.as_str()) {
                    auth_token_id = jti.to_string();
                    let revoked: Option<(String,)> = sqlx::query_as(
                        "SELECT jti FROM revoked_token_jti WHERE jti = ?",
                    )
                    .bind(jti)
                    .fetch_optional(&state.pool)
                    .await?;
                    if revoked.is_some() {
                        return Err(AppError::token_revoked());
                    }
                }
                true
            }
            Err(_) => false,
        }
    } else {
        crypto::verify_token(token, &project.project_token_hash)
    };

    if !token_ok {
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

    Ok(VerifiedProject {
        project,
        auth_token_id,
    })
}

async fn get_secrets(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(project_name): Path<String>,
) -> Result<Json<SecretsResponse>, AppError> {
    let token = extract_bearer_token(&headers)?;
    let caller = extract_caller_context(&headers);

    let verified = get_project_by_token(&state, &project_name, &token).await?;
    let project = verified.project;

    if state.config.require_request_signing {
        let attested_agent_id = crate::api::daemon::verify_attestation_header(
            &state,
            &headers,
            "GET",
            &format!("/project/secrets/{}", project_name),
            &[],
            &verified.auth_token_id,
        )
        .await?;
        match project.agent_id.as_deref() {
            Some(owner_agent) if owner_agent == attested_agent_id => {}
            Some(_) => {
                return Err(AppError::Unauthorized(
                    "daemon attestation agent_id does not match project owner".into(),
                ));
            }
            None => {
                return Err(AppError::Unauthorized(
                    "project has no bound agent_id; rediscover the project before access".into(),
                ));
            }
        }
    }

    // ── Load policies keyed to the project_name ───────────────────────────
    // Policies are evaluated per-path on every fetch so access can be
    // tightened without waiting for the next discover cycle.
    let all_policies = sqlx::query_as::<_, Policy>(
        "SELECT id, policy_name, agent_pattern, allowed_paths, denied_paths, created_at \
         FROM policies",
    )
    .fetch_all(&state.pool)
    .await?;

    // Match policies against project_name as the subject identifier.
    let matching_policies: Vec<Policy> = all_policies
        .into_iter()
        .filter(|p| agent_matches_pattern(&project_name, &p.agent_pattern))
        .collect();

    let mappings = project.get_env_mappings();
    let scope = project.get_scope();
    let scope_set: std::collections::HashSet<&str> =
        scope.iter().map(|s| s.as_str()).collect();
    let mut env_vars: HashMap<String, String> = HashMap::new();

    for (env_var, secret_path) in &mappings {
        if !scope_set.is_empty() && !scope_set.contains(secret_path.as_str()) {
            continue;
        }

        // ── Per-path policy evaluation with audit ─────────────────────
        let (policy_name, allowed) =
            path_decision_by_policies(secret_path, &matching_policies);
        if !allowed {
            audit::write(
                &state,
                None,
                Some(&project_name),
                "policy_decision",
                Some(secret_path),
                &format!("denied:policy={}", policy_name),
            )
            .await;
            continue;
        }
        if !policy_name.is_empty() {
            audit::write(
                &state,
                None,
                Some(&project_name),
                "policy_decision",
                Some(secret_path),
                &format!("allowed:policy={}", policy_name),
            )
            .await;
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
                trigger_honey_token_alarm(
                    &state,
                    &project_name,
                    &s.key_path,
                    caller.source_ip.clone(),
                )
                .await;
                return Err(AppError::Unauthorized("Secret access denied".into()));
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

async fn trigger_honey_token_alarm(
    state: &AppState,
    project_name: &str,
    key_path: &str,
    source_ip: Option<String>,
) {
    let _ = sqlx::query(
        "UPDATE projects SET token_revoked_at = datetime('now'), updated_at = datetime('now') \
         WHERE project_name = ? AND token_revoked_at IS NULL",
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

    crate::notifications::dispatch(
        state,
        crate::notifications::NotificationEvent::HoneyTokenAccess {
            project_name: project_name.to_string(),
            key_path: key_path.to_string(),
            source_ip,
        },
    );
}

async fn get_config(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((project_name, app_name)): Path<(String, String)>,
) -> Result<String, AppError> {
    let token = extract_bearer_token(&headers)?;
    let caller = extract_caller_context(&headers);

    let verified = get_project_by_token(&state, &project_name, &token).await?;
    let project = verified.project;

    if state.config.require_request_signing {
        let attested_agent_id = crate::api::daemon::verify_attestation_header(
            &state,
            &headers,
            "GET",
            &format!("/project/config/{}/{}", project_name, app_name),
            &[],
            &verified.auth_token_id,
        )
        .await?;
        match project.agent_id.as_deref() {
            Some(owner_agent) if owner_agent == attested_agent_id => {}
            Some(_) => {
                return Err(AppError::Unauthorized(
                    "daemon attestation agent_id does not match project owner".into(),
                ));
            }
            None => {
                return Err(AppError::Unauthorized(
                    "project has no bound agent_id; rediscover the project before access".into(),
                ));
            }
        }
    }

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
                trigger_honey_token_alarm(
                    &state,
                    &project_name,
                    &s.key_path,
                    caller.source_ip.clone(),
                )
                .await;
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

// ─── JWKS endpoint ─────────────────────────────────────────────────────────

pub async fn jwks(
    State(state): State<AppState>,
) -> Result<Json<crate::ed25519_keys::JwkSet>, AppError> {
    let set = crate::ed25519_keys::list_jwks(&state.pool, &state.kek)
        .await
        .map_err(AppError::Internal)?;
    Ok(Json(set))
}

// ─── Device Authorization Grant (RFC 8628) ─────────────────────────────────

#[derive(serde::Deserialize)]
pub struct DeviceAuthorizeRequest {
    pub client_id: Option<String>,
}

pub async fn device_authorize(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(_req): Json<DeviceAuthorizeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Rate limit: 1 /device/authorize per minute per IP.
    let ip = extract_source_ip(&headers);
    if !state.rate_limiter.check(&format!("device_authorize:{}", ip), 1, 60) {
        return Err(AppError::TooManyRequests(
            "Rate limit: 1 /device/authorize per minute per IP".into(),
        ));
    }

    let device_code = crypto::generate_token();
    let user_code = generate_user_code();
    let id = Uuid::new_v4().to_string();
    let expires = Utc::now() + Duration::minutes(10);
    let expires_str = format_sqlite_timestamp(expires);

    sqlx::query(
        "INSERT INTO pending_devices (id, device_code, user_code, status, expires_at) \
         VALUES (?, ?, ?, 'pending', ?)",
    )
    .bind(&id)
    .bind(&device_code)
    .bind(&user_code)
    .bind(&expires_str)
    .execute(&state.pool)
    .await?;

    #[derive(serde::Serialize)]
    struct DeviceAuthorizeResponse {
        device_code: String,
        user_code: String,
        verification_uri: String,
        expires_in: i64,
        interval: i64,
    }

    let resp = DeviceAuthorizeResponse {
        device_code,
        user_code: user_code.clone(),
        verification_uri: "/device".to_string(),
        expires_in: 600,
        interval: 5,
    };

    audit::write(&state, None, None, "device_authorize", Some(&user_code), "success").await;
    Ok(Json(serde_json::to_value(resp).unwrap()))
}

#[derive(serde::Deserialize)]
pub struct DeviceTokenRequest {
    pub device_code: String,
    pub grant_type: Option<String>,
}

pub async fn device_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeviceTokenRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Rate limit: 5 /device/token polls per minute per device_code.
    let rl_key = format!("device_token:{}", &req.device_code[..req.device_code.len().min(16)]);
    if !state.rate_limiter.check(&rl_key, 5, 60) {
        return Err(AppError::TooManyRequests(
            "Rate limit: 5 /device/token polls per minute per device_code".into(),
        ));
    }

    let _ = headers; // headers available for future use

    let row: Option<(String, Option<String>, String)> = sqlx::query_as(
        "SELECT status, agent_id, expires_at FROM pending_devices WHERE device_code = ?",
    )
    .bind(&req.device_code)
    .fetch_optional(&state.pool)
    .await?;
    let (status, agent_id, expires_at) =
        row.ok_or_else(|| AppError::Unauthorized("Unknown device_code".into()))?;

    let exp = chrono::NaiveDateTime::parse_from_str(&expires_at, "%Y-%m-%d %H:%M:%S")
        .map(|n| chrono::DateTime::<Utc>::from_naive_utc_and_offset(n, Utc))
        .ok();
    if exp.map(|t| t < Utc::now()).unwrap_or(false) {
        return Err(AppError::Unauthorized("device_code expired".into()));
    }

    match status.as_str() {
        "pending" => Err(AppError::TokenError {
            code: "authorization_pending",
            message: "Approval still pending".into(),
        }),
        "denied" => Err(AppError::Unauthorized("Approval denied".into())),
        "approved" => {
            let agent_id = agent_id.ok_or_else(|| {
                AppError::Internal(anyhow::anyhow!("approved row has no agent_id"))
            })?;
            let claims = serde_json::json!({
                "iss": "cortex-auth",
                "sub": agent_id,
                "aud": "cortex-daemon",
                "iat": Utc::now().timestamp(),
                "exp": (Utc::now() + Duration::days(30)).timestamp(),
                "jti": Uuid::new_v4().to_string(),
                "scope": "daemon",
            });
            let access_token = crate::ed25519_keys::sign_jwt(&state.server_keypair, &claims)
                .map_err(AppError::Internal)?;

            audit::write(
                &state,
                Some(&agent_id),
                None,
                "device_token_issue",
                None,
                "success",
            )
            .await;

            Ok(Json(serde_json::json!({
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": 30 * 86400,
                "kid": state.server_keypair.kid,
            })))
        }
        other => Err(AppError::Unauthorized(format!("status={}", other))),
    }
}

pub async fn device_approval_page() -> axum::response::Html<&'static str> {
    axum::response::Html(
        r#"<!doctype html>
<meta charset="utf-8">
<title>CortexAuth — approve device</title>
<style>body{font-family:system-ui;max-width:520px;margin:48px auto;padding:0 16px;color:#1a202c}
input,button{font-size:14px;padding:8px 12px;width:100%;box-sizing:border-box;margin:6px 0}
button{background:#4f8ef7;color:#fff;border:none;border-radius:4px;cursor:pointer}
.note{color:#718096;font-size:13px}</style>
<h1>Approve a CortexAuth device</h1>
<p class="note">Paste the user code shown by <code>cortex-cli daemon login</code>, then assign it to an agent.</p>
<input id="user_code" placeholder="USER-CODE" autocomplete="off">
<input id="agent_id" placeholder="agent_id (must already be registered)">
<input id="admin_token" type="password" placeholder="X-Admin-Token (until SSO lands)">
<button onclick="approve()">Approve</button>
<pre id="out" class="note"></pre>
<script>
async function approve() {
  const r = await fetch('/admin/web/device/approve', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-Admin-Token': document.getElementById('admin_token').value},
    body: JSON.stringify({
      user_code: document.getElementById('user_code').value.trim(),
      agent_id: document.getElementById('agent_id').value.trim(),
    })
  });
  document.getElementById('out').textContent = await r.text();
}
</script>"#,
    )
}

fn generate_user_code() -> String {
    use rand::Rng;
    const ALPH: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    let mut pick = |n: usize| -> String {
        (0..n)
            .map(|_| ALPH[rng.gen_range(0..ALPH.len())] as char)
            .collect()
    };
    format!("{}-{}", pick(4), pick(4))
}
