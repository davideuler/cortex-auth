//! Tamper-evident audit log.
//!
//! Each row is HMAC-SHA256-chained to the previous row using a key derived
//! from the KEK. Any deletion or reorder of rows breaks the chain — verified
//! by replaying entries in `verify_chain`. Caller metadata (PID, binary
//! sha256, argv hash, cwd, git commit, source IP, hostname, OS) is recorded
//! alongside the action so a forensic reviewer can answer "which exact
//! process took this secret?".

use serde::Serialize;
use uuid::Uuid;

use crate::state::AppState;

/// Optional caller context attached to a single audit row. Populated by the
/// HTTP handler from request headers / connection info; missing fields stay
/// NULL.
#[derive(Default, Clone, Debug)]
pub struct CallerContext {
    pub caller_pid: Option<i64>,
    pub caller_binary_sha256: Option<String>,
    pub caller_argv_hash: Option<String>,
    pub caller_cwd: Option<String>,
    pub caller_git_commit: Option<String>,
    pub source_ip: Option<String>,
    pub hostname: Option<String>,
    pub os: Option<String>,
}

/// Canonical-JSON payload that the chain MAC covers. The field order is
/// fixed so the same row always produces the same MAC.
#[derive(Serialize)]
struct ChainPayload<'a> {
    id: &'a str,
    agent_id: Option<&'a str>,
    project_name: Option<&'a str>,
    action: &'a str,
    resource_path: Option<&'a str>,
    status: &'a str,
    caller_pid: Option<i64>,
    caller_binary_sha256: Option<&'a str>,
    caller_argv_hash: Option<&'a str>,
    caller_cwd: Option<&'a str>,
    caller_git_commit: Option<&'a str>,
    source_ip: Option<&'a str>,
    hostname: Option<&'a str>,
    os: Option<&'a str>,
}

pub async fn write(
    state: &AppState,
    agent_id: Option<&str>,
    project_name: Option<&str>,
    action: &str,
    resource_path: Option<&str>,
    status: &str,
) {
    write_with_context(state, agent_id, project_name, action, resource_path, status, &CallerContext::default()).await
}

pub async fn write_with_context(
    state: &AppState,
    agent_id: Option<&str>,
    project_name: Option<&str>,
    action: &str,
    resource_path: Option<&str>,
    status: &str,
    ctx: &CallerContext,
) {
    let id = Uuid::new_v4().to_string();

    // Serialize all audit appends so the (read prev, compute mac, insert,
    // update tail) sequence is atomic with respect to other writers.
    let _guard = state.audit_mutex.lock().await;

    let prev: String = sqlx::query_scalar::<_, String>(
        "SELECT tail_mac FROM audit_mac_state WHERE id = 1",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();

    let payload = ChainPayload {
        id: &id,
        agent_id,
        project_name,
        action,
        resource_path,
        status,
        caller_pid: ctx.caller_pid,
        caller_binary_sha256: ctx.caller_binary_sha256.as_deref(),
        caller_argv_hash: ctx.caller_argv_hash.as_deref(),
        caller_cwd: ctx.caller_cwd.as_deref(),
        caller_git_commit: ctx.caller_git_commit.as_deref(),
        source_ip: ctx.source_ip.as_deref(),
        hostname: ctx.hostname.as_deref(),
        os: ctx.os.as_deref(),
    };
    let payload_json = serde_json::to_string(&payload).unwrap_or_default();
    let entry_mac = crate::crypto::audit_chain_mac(&state.audit_mac_key, &prev, &payload_json);

    let mut tx = match state.pool.begin().await {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("audit log: failed to begin tx: {}", e);
            return;
        }
    };

    let insert_res = sqlx::query(
        "INSERT INTO audit_logs (\
            id, agent_id, project_name, action, resource_path, status, \
            caller_pid, caller_binary_sha256, caller_argv_hash, caller_cwd, caller_git_commit, \
            source_ip, hostname, os, prev_hash, entry_mac\
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&id)
    .bind(agent_id)
    .bind(project_name)
    .bind(action)
    .bind(resource_path)
    .bind(status)
    .bind(ctx.caller_pid)
    .bind(ctx.caller_binary_sha256.as_deref())
    .bind(ctx.caller_argv_hash.as_deref())
    .bind(ctx.caller_cwd.as_deref())
    .bind(ctx.caller_git_commit.as_deref())
    .bind(ctx.source_ip.as_deref())
    .bind(ctx.hostname.as_deref())
    .bind(ctx.os.as_deref())
    .bind(&prev)
    .bind(&entry_mac)
    .execute(&mut *tx)
    .await;

    if let Err(e) = insert_res {
        tracing::warn!("audit log: insert failed: {}", e);
        return;
    }

    if let Err(e) = sqlx::query(
        "UPDATE audit_mac_state SET tail_mac = ?, updated_at = datetime('now') WHERE id = 1",
    )
    .bind(&entry_mac)
    .execute(&mut *tx)
    .await
    {
        tracing::warn!("audit log: tail update failed: {}", e);
        return;
    }

    if let Err(e) = tx.commit().await {
        tracing::warn!("audit log: commit failed: {}", e);
    }
}
