//! cortex-daemon — hardened long-running token-holding agent process.
//!
//! ## Startup sequence
//! 1. `prctl(PR_SET_DUMPABLE, 0)` + `mlockall` to prevent ptrace / swap exposure
//! 2. Load `~/.cortex/daemon-session.json` (JWT + server URL from `daemon login`)
//! 3. Decode JWT `sub` claim → agent_id; load `~/.cortex/agent-<id>.key`
//! 4. Compute own binary SHA-256 from `/proc/self/exe`
//! 5. Generate ephemeral Ed25519 attestation keypair (private key never written to disk)
//! 6. `POST /daemon/attest` → session_id bound to this process's ephemeral key
//! 7. Bind `~/.cortex/agent.sock` (mode 0600); enforce SO_PEERCRED per connection
//!
//! ## Socket protocol (line-delimited JSON, one request per connection)
//! * `{"cmd":"status"}` → `{"ok":true,"session":{...},"attest_session_id":"..."}`
//! * `{"cmd":"run","program":"<bin>","args":[...],"project":"<name>","url":"<server>"[,"env_file":"..."]}`
//!   → daemon discovers/refreshes project token internally, spawns child with secrets
//!   → `{"ok":true,"exit_code":N}` on success
//!   → `{"ok":false,"error_code":"pending_approval","grant_id":"...","requested_keys":[...]}` when awaiting approval

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine as _};
use ed25519_dalek::{Signer, SigningKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::RwLock;

const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Ephemeral per-process state — created at startup, never written to disk.
struct AttestCtx {
    /// Ephemeral signing key for X-Daemon-Attestation headers.
    attest_key: SigningKey,
    /// Session ID returned by /daemon/attest.
    session_id: String,
    /// Canonical server URL (no trailing slash).
    server_url: String,
    /// Agent identity (decoded from daemon access_token sub claim).
    agent_id: String,
    /// Agent Ed25519 signing key (loaded from ~/.cortex/agent-<id>.key).
    agent_key: SigningKey,
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct CachedToken {
    token: String,
    expires_at: String,
}

type TokenCache = Arc<RwLock<HashMap<String, CachedToken>>>;

#[derive(serde::Serialize, serde::Deserialize)]
struct DaemonSessionFile {
    access_token: String,
    expires_in: i64,
    server_url: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    harden_process();
    tracing_subscriber::fmt::init();

    let sess_path = session_path();
    let sess_json = std::fs::read_to_string(&sess_path).with_context(|| {
        format!(
            "No daemon session at {}. Run `cortex-cli daemon login` first.",
            sess_path.display()
        )
    })?;
    let sess: DaemonSessionFile =
        serde_json::from_str(&sess_json).context("Failed to parse daemon-session.json")?;

    let server_url = sess.server_url.trim_end_matches('/').to_string();
    let agent_id =
        decode_jwt_sub(&sess.access_token).context("Cannot decode agent_id from access_token")?;
    tracing::info!("agent_id={} server={}", agent_id, server_url);

    let key_path = default_priv_key_path(&agent_id);
    let priv_b64 = std::fs::read_to_string(&key_path)
        .with_context(|| format!("Cannot read agent key {}", key_path.display()))?;
    let priv_bytes = B64URL
        .decode(priv_b64.trim().as_bytes())
        .context("agent key is not base64url")?;
    anyhow::ensure!(priv_bytes.len() == 32, "agent key must be 32 bytes");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&priv_bytes);
    let agent_key = SigningKey::from_bytes(&arr);

    let binary_sha256 = compute_binary_sha256()?;
    tracing::info!("binary sha256={}", binary_sha256);

    let attest_key = SigningKey::generate(&mut OsRng);
    let attest_pub = B64URL.encode(attest_key.verifying_key().to_bytes());

    let client = build_http_client();
    let session_id = register_attestation(
        &client,
        &server_url,
        &sess.access_token,
        &attest_pub,
        &binary_sha256,
    )
    .await?;
    tracing::info!("attested session_id={}", session_id);

    let ctx = Arc::new(AttestCtx {
        attest_key,
        session_id,
        server_url,
        agent_id,
        agent_key,
    });

    let cache: TokenCache = Arc::new(RwLock::new(load_token_cache()));

    let sock = sock_path();
    if let Some(p) = sock.parent() {
        std::fs::create_dir_all(p).ok();
    }
    if sock.exists() {
        std::fs::remove_file(&sock).ok();
    }
    let listener =
        UnixListener::bind(&sock).with_context(|| format!("bind {} failed", sock.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600));
    }

    let daemon_uid = unsafe { libc::getuid() };
    tracing::info!("listening on {} (uid={})", sock.display(), daemon_uid);

    loop {
        let (stream, _) = listener.accept().await?;
        #[cfg(target_os = "linux")]
        if let Err(e) = check_peer_uid(&stream, daemon_uid) {
            tracing::warn!("rejected connection: {}", e);
            continue;
        }
        let ctx = Arc::clone(&ctx);
        let cache = Arc::clone(&cache);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, ctx, cache).await {
                tracing::warn!("conn error: {}", e);
            }
        });
    }
}

// ── Socket protocol ─────────────────────────────────────────────────────────

#[derive(serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    Status,
    Run {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        project: String,
        // url is accepted but the daemon uses its own configured server_url
        #[allow(dead_code)]
        url: Option<String>,
        env_file: Option<String>,
    },
}

async fn handle_conn(stream: UnixStream, ctx: Arc<AttestCtx>, cache: TokenCache) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = serde_json::json!({"ok": false, "error": e.to_string()});
            write_half
                .write_all(format!("{}\n", resp).as_bytes())
                .await?;
            return Ok(());
        }
    };

    let resp = match req {
        Request::Status => {
            let sess = std::fs::read_to_string(session_path())
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
            serde_json::json!({
                "ok": true,
                "session": sess,
                "attest_session_id": ctx.session_id,
                "agent_id": ctx.agent_id,
                "server_url": ctx.server_url,
            })
        }
        Request::Run {
            program,
            args,
            project,
            env_file,
            ..
        } => match run_project(&program, &args, &project, env_file.as_deref(), &ctx, &cache).await
        {
            Ok(code) => serde_json::json!({"ok": true, "exit_code": code}),
            Err(RunError::PendingApproval {
                grant_id,
                requested_keys,
            }) => serde_json::json!({
                "ok": false,
                "error_code": "pending_approval",
                "grant_id": grant_id,
                "requested_keys": requested_keys,
                "message": "Admin approval required before this agent can access the project",
            }),
            Err(RunError::Other(e)) => serde_json::json!({"ok": false, "error": e.to_string()}),
        },
    };

    write_half
        .write_all(format!("{}\n", resp).as_bytes())
        .await?;
    Ok(())
}

// ── Run / discover / fetch ───────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
enum RunError {
    #[error("pending admin approval (grant_id={grant_id})")]
    PendingApproval {
        grant_id: String,
        requested_keys: Vec<String>,
    },
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

async fn run_project(
    program: &str,
    args: &[String],
    project: &str,
    env_file: Option<&str>,
    ctx: &AttestCtx,
    cache: &TokenCache,
) -> Result<i32, RunError> {
    let client = build_http_client();
    let token = get_or_discover_token(project, env_file, ctx, cache, &client, false).await?;

    let secrets = match fetch_secrets_attested(&client, project, &token, ctx).await {
        Ok(s) => s,
        Err(e) => {
            // On token auth failure, evict cache and retry once with a fresh discover
            let msg = e.to_string();
            if msg.contains("401") || msg.contains("token_expired") || msg.contains("token_revoked") {
                cache.write().await.remove(project);
                save_token_cache(&*cache.read().await);
                let token2 =
                    get_or_discover_token(project, env_file, ctx, cache, &client, true).await?;
                fetch_secrets_attested(&client, project, &token2, ctx)
                    .await
                    .map_err(RunError::Other)?
            } else {
                return Err(RunError::Other(e));
            }
        }
    };

    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    for (k, v) in &secrets {
        cmd.env(k, v);
    }
    let status = cmd
        .status()
        .await
        .with_context(|| format!("failed to spawn {}", program))
        .map_err(RunError::Other)?;
    Ok(status.code().unwrap_or(-1))
}

async fn get_or_discover_token(
    project: &str,
    env_file: Option<&str>,
    ctx: &AttestCtx,
    cache: &TokenCache,
    client: &reqwest::Client,
    force: bool,
) -> Result<String, RunError> {
    if !force {
        let r = cache.read().await;
        if let Some(ct) = r.get(project) {
            if !is_token_expired(&ct.expires_at) {
                return Ok(ct.token.clone());
            }
        }
    }

    let env_content = match env_file {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("Cannot read env_file {}", path))
            .map_err(RunError::Other)?,
        None => {
            if std::path::Path::new(".env").exists() {
                std::fs::read_to_string(".env")
                    .context("Cannot read .env")
                    .map_err(RunError::Other)?
            } else {
                String::new()
            }
        }
    };

    let result = discover_token_attested(client, project, &env_content, ctx).await?;
    tracing::info!(
        "discovered token for project={} expires_at={}",
        project,
        result.token_expires_at
    );

    let ct = CachedToken {
        token: result.project_token.clone(),
        expires_at: result.token_expires_at,
    };
    {
        let mut w = cache.write().await;
        w.insert(project.to_string(), ct);
        save_token_cache(&w);
    }
    Ok(result.project_token)
}

#[derive(serde::Deserialize)]
struct DiscoverResp {
    project_token: String,
    token_expires_at: String,
    #[serde(default)]
    unmatched_keys: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct ErrorBody {
    error_code: Option<String>,
    details: Option<serde_json::Value>,
}

async fn discover_token_attested(
    client: &reqwest::Client,
    project_name: &str,
    env_content: &str,
    ctx: &AttestCtx,
) -> Result<DiscoverResp, RunError> {
    let ts = chrono::Utc::now().timestamp();
    let mut nonce_bytes = [0u8; 8];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce: String = nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let message = format!("{}|{}|{}|/agent/discover", ts, nonce, ctx.agent_id);
    let sig = ctx.agent_key.sign(message.as_bytes());
    let auth_proof = B64URL.encode(sig.to_bytes());

    let body_val = serde_json::json!({
        "agent_id": ctx.agent_id,
        "auth_proof": auth_proof,
        "ts": ts,
        "nonce": nonce,
        "context": {
            "project_name": project_name,
            "file_content": env_content,
        },
        "regenerate_token": false,
    });
    let body_bytes = serde_json::to_vec(&body_val)
        .context("serialize discover body")
        .map_err(RunError::Other)?;
    let attest = make_attestation_header(ctx, "POST", "/agent/discover", &body_bytes);

    let url = format!("{}/agent/discover", ctx.server_url);
    let resp = client
        .post(&url)
        .header("X-Daemon-Attestation", attest)
        .header("Content-Type", "application/json")
        .body(body_bytes)
        .send()
        .await
        .context("POST /agent/discover failed")
        .map_err(RunError::Other)?;

    let status = resp.status();
    if status == reqwest::StatusCode::FORBIDDEN {
        let body: ErrorBody = resp.json().await.unwrap_or_default();
        if body.error_code.as_deref() == Some("pending_approval") {
            let grant_id = body
                .details
                .as_ref()
                .and_then(|d| d.get("grant_id"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let requested_keys: Vec<String> = body
                .details
                .as_ref()
                .and_then(|d| d.get("requested_keys"))
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();
            return Err(RunError::PendingApproval {
                grant_id,
                requested_keys,
            });
        }
        let code = body.error_code.as_deref().unwrap_or("forbidden");
        return Err(RunError::Other(anyhow::anyhow!(
            "/agent/discover returned 403 ({})",
            code
        )));
    }
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        return Err(RunError::Other(anyhow::anyhow!(
            "/agent/discover returned {}: {}",
            status,
            text
        )));
    }

    let dr: DiscoverResp = resp
        .json()
        .await
        .context("parse /agent/discover response")
        .map_err(RunError::Other)?;
    if !dr.unmatched_keys.is_empty() {
        tracing::warn!("unmatched env keys: {:?}", dr.unmatched_keys);
    }
    Ok(dr)
}

#[derive(serde::Deserialize)]
struct SecretsResp {
    env_vars: HashMap<String, String>,
}

async fn fetch_secrets_attested(
    client: &reqwest::Client,
    project_name: &str,
    token: &str,
    ctx: &AttestCtx,
) -> Result<HashMap<String, String>> {
    let path = format!("/project/secrets/{}", project_name);
    let url = format!("{}{}", ctx.server_url, path);
    let attest = make_attestation_header(ctx, "GET", &path, b"");

    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .header("X-Daemon-Attestation", attest)
        .send()
        .await
        .context("GET /project/secrets failed")?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("GET /project/secrets returned {}: {}", status, text);
    }

    let body: SecretsResp = resp
        .json()
        .await
        .context("parse /project/secrets response")?;
    Ok(body.env_vars)
}

// ── Attestation helpers ──────────────────────────────────────────────────────

fn make_attestation_header(ctx: &AttestCtx, method: &str, path: &str, body: &[u8]) -> String {
    let ts = chrono::Utc::now().timestamp();
    let jti = uuid::Uuid::new_v4().to_string();
    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_sha256 = hex::encode(hasher.finalize());
    let message = format!("{}|{}|{}|{}|{}", ts, jti, method, path, body_sha256);
    let sig = ctx.attest_key.sign(message.as_bytes());
    let sig_b64 = B64URL.encode(sig.to_bytes());
    format!(
        "{}.{}.{}.{}.{}",
        ctx.session_id, ts, jti, body_sha256, sig_b64
    )
}

async fn register_attestation(
    client: &reqwest::Client,
    server_url: &str,
    access_token: &str,
    attestation_pub: &str,
    binary_sha256: &str,
) -> Result<String> {
    let pid = std::process::id() as i64;
    let uid = unsafe { libc::getuid() } as i64;
    let hostname = get_hostname();

    let body = serde_json::json!({
        "attestation_pub": attestation_pub,
        "binary_sha256": binary_sha256,
        "daemon_version": DAEMON_VERSION,
        "daemon_pid": pid,
        "daemon_uid": uid,
        "hostname": hostname,
    });

    let url = format!("{}/daemon/attest", server_url);
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", access_token))
        .json(&body)
        .send()
        .await
        .context("POST /daemon/attest failed")?;

    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("POST /daemon/attest returned {}: {}", status, text);
    }

    let resp_body: serde_json::Value = resp.json().await.context("parse /daemon/attest response")?;
    let session_id = resp_body
        .get("session_id")
        .and_then(|v| v.as_str())
        .context("missing session_id in /daemon/attest response")?
        .to_string();
    Ok(session_id)
}

// ── OS hardening ─────────────────────────────────────────────────────────────

fn harden_process() {
    #[cfg(target_os = "linux")]
    unsafe {
        // Prevent ptrace / /proc/*/mem access and suppress core dumps.
        libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        // Lock all memory pages so private keys cannot be swapped to disk.
        libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE);
    }
}

#[cfg(target_os = "linux")]
fn check_peer_uid(stream: &UnixStream, expected_uid: u32) -> Result<()> {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    let mut ucred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut ucred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    anyhow::ensure!(ret == 0, "getsockopt(SO_PEERCRED) failed");
    anyhow::ensure!(
        ucred.uid == expected_uid,
        "peer uid {} != daemon uid {} — connection rejected",
        ucred.uid,
        expected_uid
    );
    Ok(())
}

// ── Utilities ────────────────────────────────────────────────────────────────

fn decode_jwt_sub(token: &str) -> Result<String> {
    let parts: Vec<&str> = token.split('.').collect();
    anyhow::ensure!(parts.len() >= 2, "JWT must have at least 2 dot-separated parts");
    let payload = B64URL
        .decode(parts[1].as_bytes())
        .context("JWT payload segment is not valid base64url")?;
    let claims: serde_json::Value =
        serde_json::from_slice(&payload).context("JWT payload is not JSON")?;
    claims
        .get("sub")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .context("JWT payload has no 'sub' claim")
}

fn compute_binary_sha256() -> Result<String> {
    let exe = std::fs::read_link("/proc/self/exe").context("/proc/self/exe unreadable")?;
    let mut f = std::fs::File::open(&exe)
        .with_context(|| format!("Cannot open binary {}", exe.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut f, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

fn is_token_expired(expires_at: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    // Try RFC-3339 first, then SQLite-style "YYYY-MM-DD HH:MM:SS"
    if let Ok(exp) = chrono::DateTime::parse_from_rfc3339(expires_at) {
        return exp.timestamp() < now + 60; // 60-second early expiry buffer
    }
    if let Ok(exp) = chrono::NaiveDateTime::parse_from_str(expires_at, "%Y-%m-%d %H:%M:%S") {
        return exp.and_utc().timestamp() < now + 60;
    }
    true // unparseable → treat as expired
}

fn build_http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .expect("failed to build HTTP client")
}

fn get_hostname() -> String {
    unsafe {
        let mut buf = [0u8; 256];
        let ret = libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len());
        if ret == 0 {
            let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
            return String::from_utf8_lossy(&buf[..len]).to_string();
        }
    }
    "unknown".to_string()
}

fn session_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cortex").join("daemon-session.json")
}

fn sock_path() -> PathBuf {
    if let Ok(s) = std::env::var("CORTEX_DAEMON_SOCK") {
        return PathBuf::from(s);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cortex").join("agent.sock")
}

fn default_priv_key_path(agent_id: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".cortex")
        .join(format!("agent-{}.key", agent_id))
}

fn token_cache_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".cortex")
        .join("daemon-projects.json")
}

fn load_token_cache() -> HashMap<String, CachedToken> {
    let path = token_cache_path();
    if !path.exists() {
        return HashMap::new();
    }
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_token_cache(cache: &HashMap<String, CachedToken>) {
    let path = token_cache_path();
    if let Ok(s) = serde_json::to_string_pretty(cache) {
        let _ = std::fs::write(&path, s.as_bytes());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
    }
}
