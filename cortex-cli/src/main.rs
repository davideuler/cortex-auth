use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "cortex-cli",
    about = "CortexAuth CLI — launch processes with injected secrets, or generate auth tokens"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Launch a process with secrets injected from CortexAuth
    Run {
        /// Project name registered in CortexAuth
        #[arg(long, env = "CORTEX_PROJECT")]
        project: String,

        /// Project token for authenticating with CortexAuth.
        /// Optional when --agent-id and --jwt-secret are provided — the CLI
        /// will discover (and auto-rotate) the token transparently.
        #[arg(long, env = "CORTEX_TOKEN")]
        token: Option<String>,

        /// CortexAuth server URL (e.g. http://localhost:3000)
        #[arg(long, env = "CORTEX_URL")]
        url: String,

        /// Agent ID — enables auto-rotation of expired/revoked project tokens.
        #[arg(long, env = "CORTEX_AGENT_ID")]
        agent_id: Option<String>,

        /// Agent JWT secret — required with --agent-id for auto-rotation.
        #[arg(long, env = "CORTEX_JWT_SECRET")]
        jwt_secret: Option<String>,

        /// Path to .env file describing required env-var names (used by discover).
        /// Defaults to "./.env" if it exists.
        #[arg(long, env = "CORTEX_ENV_FILE")]
        env_file: Option<PathBuf>,

        /// Where to persist the auto-rotated project token.
        /// Defaults to "$HOME/.cortex-token-<project>".
        #[arg(long, env = "CORTEX_TOKEN_FILE")]
        token_file: Option<PathBuf>,

        /// Command and arguments to run (separated by --)
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
    },
    /// Generate an auth_proof JWT for use with /agent/discover
    GenToken {
        /// Agent ID registered in CortexAuth
        #[arg(long)]
        agent_id: String,

        /// JWT secret for the agent (as registered via POST /admin/agents)
        #[arg(long)]
        jwt_secret: String,
    },
    /// (#13) Generate a fresh Ed25519 keypair for an agent. Prints the
    /// base64url public key (upload to CortexAuth) and writes the private key
    /// to --priv-key-file (default ~/.cortex/agent-<id>.key).
    GenKey {
        /// Agent ID to label the keypair with.
        #[arg(long)]
        agent_id: String,

        /// Where to write the private key (mode 0600). Defaults to
        /// ~/.cortex/agent-<agent_id>.key.
        #[arg(long)]
        priv_key_file: Option<PathBuf>,
    },
    /// (#13) Sign an Ed25519 auth_proof for /agent/discover. Prints
    /// `{"ts","nonce","auth_proof"}` JSON ready to splice into the request
    /// body alongside `agent_id`.
    SignProof {
        #[arg(long)]
        agent_id: String,
        #[arg(long)]
        priv_key_file: PathBuf,
    },
    /// (#16) cortex-daemon control plane. The actual daemon runs as a
    /// separate `cortex-daemon` binary; these subcommands talk to it over
    /// the Unix socket at ~/.cortex/agent.sock or trigger an OAuth 2.0
    /// device-authorization login against the server.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },
    /// Discover a project and obtain (or rotate) a short-lived project token.
    Discover {
        /// Project name to register/refresh
        #[arg(long, env = "CORTEX_PROJECT")]
        project: String,

        /// CortexAuth server URL
        #[arg(long, env = "CORTEX_URL")]
        url: String,

        /// Agent ID
        #[arg(long, env = "CORTEX_AGENT_ID")]
        agent_id: String,

        /// Agent JWT secret
        #[arg(long, env = "CORTEX_JWT_SECRET")]
        jwt_secret: String,

        /// Path to .env file describing required env-var names. Defaults to "./.env".
        #[arg(long, env = "CORTEX_ENV_FILE")]
        env_file: Option<PathBuf>,

        /// Force rotation even if the existing token is still active.
        #[arg(long)]
        regenerate: bool,
    },
}

#[derive(Subcommand, Debug)]
enum DaemonAction {
    /// Trigger the OAuth 2.0 device-authorization grant against
    /// CortexAuth. Prints a user_code + verification URL — paste them into
    /// the dashboard at /device to approve the daemon.
    Login {
        #[arg(long, env = "CORTEX_URL")]
        url: String,
    },
    /// Print the current daemon session (or "no daemon").
    Status {
        #[arg(long, env = "CORTEX_DAEMON_SOCK")]
        sock: Option<PathBuf>,
    },
    /// Forget the cached access token.
    Logout,
}

#[derive(serde::Deserialize)]
struct SecretsResponse {
    env_vars: HashMap<String, String>,
}

#[derive(serde::Deserialize, Debug)]
struct DiscoverResponse {
    project_token: String,
    token_expires_at: String,
    #[serde(default)]
    token_ttl_seconds: i64,
    #[serde(default)]
    full_matched: bool,
    #[serde(default)]
    unmatched_keys: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct ErrorBody {
    #[serde(default)]
    error_code: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            project,
            token,
            url,
            agent_id,
            jwt_secret,
            env_file,
            token_file,
            cmd,
        } => {
            if cmd.is_empty() {
                anyhow::bail!("No command specified");
            }

            let token_path = token_file.unwrap_or_else(|| default_token_path(&project));

            // 1) Resolve initial token: explicit --token, or saved file.
            let mut current_token = match token {
                Some(t) => t,
                None => read_token_file(&token_path).with_context(|| format!(
                    "No --token provided and no saved token at {}. Pass --token or run `cortex-cli discover`.",
                    token_path.display()
                ))?,
            };

            // 2) Try to fetch secrets. On token_expired/token_revoked, attempt auto-rotation.
            let secrets = match fetch_secrets(&url, &project, &current_token).await {
                Ok(s) => s,
                Err(FetchError::Expired) | Err(FetchError::Revoked) => {
                    let (id, secret) = match (agent_id.as_deref(), jwt_secret.as_deref()) {
                        (Some(id), Some(s)) => (id, s),
                        _ => anyhow::bail!(
                            "Project token has expired or been revoked, but auto-rotation is not configured. \
                             Set --agent-id and --jwt-secret (or CORTEX_AGENT_ID / CORTEX_JWT_SECRET) to enable, \
                             or re-run `cortex-cli discover` manually."
                        ),
                    };
                    eprintln!("[cortex-cli] project token invalid; auto-rotating via /agent/discover");
                    let env_content = load_env_content(env_file.as_deref())?;
                    let resp =
                        discover_project(&url, &project, id, secret, &env_content, true).await?;
                    write_token_file(&token_path, &resp.project_token)?;
                    eprintln!(
                        "[cortex-cli] new project token saved to {} (expires at {})",
                        token_path.display(),
                        resp.token_expires_at
                    );
                    current_token = resp.project_token;
                    fetch_secrets(&url, &project, &current_token)
                        .await
                        .map_err(anyhow::Error::from)?
                }
                Err(other) => return Err(anyhow::Error::from(other)),
            };

            let program = &cmd[0];
            let args = &cmd[1..];

            let mut command = Command::new(program);
            command.args(args);

            for (key, value) in &secrets {
                command.env(key, value);
            }

            // Replace current process with the command (exec)
            let err = command.exec();
            Err(anyhow::anyhow!("Failed to exec '{}': {}", program, err))
        }
        Commands::GenToken { agent_id, jwt_secret } => {
            let token = make_auth_proof(&agent_id, &jwt_secret)?;
            println!("{}", token);
            Ok(())
        }
        Commands::GenKey { agent_id, priv_key_file } => {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
            use ed25519_dalek::SigningKey;
            use rand_core::OsRng;

            let signing = SigningKey::generate(&mut OsRng);
            let priv_b64 = B64.encode(signing.to_bytes());
            let pub_b64 = B64.encode(signing.verifying_key().to_bytes());
            let path = priv_key_file.unwrap_or_else(|| default_priv_key_path(&agent_id));
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            write_priv_key_file(&path, &priv_b64)?;
            eprintln!(
                "[cortex-cli] private key written to {} (mode 0600)",
                path.display()
            );
            eprintln!("[cortex-cli] upload this public key with POST /admin/agents:");
            println!("{}", pub_b64);
            Ok(())
        }
        Commands::SignProof { agent_id, priv_key_file } => {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
            use ed25519_dalek::{Signer, SigningKey};

            let priv_b64 = std::fs::read_to_string(&priv_key_file)
                .with_context(|| format!("Failed to read {}", priv_key_file.display()))?;
            let priv_bytes = B64
                .decode(priv_b64.trim().as_bytes())
                .context("private key file must be base64url")?;
            anyhow::ensure!(priv_bytes.len() == 32, "private key must be 32 bytes");
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&priv_bytes);
            let signing = SigningKey::from_bytes(&arr);

            let ts = chrono::Utc::now().timestamp();
            // 16 hex chars from the system PRNG via getrandom transitively
            // through OsRng. Avoids pulling rand into cortex-cli directly.
            let mut nonce_bytes = [0u8; 8];
            use rand_core::RngCore;
            rand_core::OsRng.fill_bytes(&mut nonce_bytes);
            let nonce: String = nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect();
            let message = format!("{}|{}|{}|/agent/discover", ts, nonce, agent_id);
            let sig = signing.sign(message.as_bytes());
            let auth_proof = B64.encode(sig.to_bytes());

            println!(
                "{}",
                serde_json::json!({"ts": ts, "nonce": nonce, "auth_proof": auth_proof})
            );
            Ok(())
        }
        Commands::Daemon { action } => {
            match action {
                DaemonAction::Login { url } => daemon_login(&url).await,
                DaemonAction::Status { sock } => daemon_status(sock.as_deref()),
                DaemonAction::Logout => daemon_logout(),
            }
        }
        Commands::Discover {
            project,
            url,
            agent_id,
            jwt_secret,
            env_file,
            regenerate,
        } => {
            let env_content = load_env_content(env_file.as_deref())?;
            let resp = discover_project(
                &url,
                &project,
                &agent_id,
                &jwt_secret,
                &env_content,
                regenerate,
            )
            .await?;
            let token_path = default_token_path(&project);
            write_token_file(&token_path, &resp.project_token)?;
            eprintln!(
                "[cortex-cli] project token saved to {} (expires at {}, ttl {}s)",
                token_path.display(),
                resp.token_expires_at,
                resp.token_ttl_seconds
            );
            if !resp.full_matched && !resp.unmatched_keys.is_empty() {
                eprintln!(
                    "[cortex-cli] warning: unmatched env keys: {:?}",
                    resp.unmatched_keys
                );
            }
            // Print plain token to stdout so callers can capture it.
            println!("{}", resp.project_token);
            Ok(())
        }
    }
}

fn make_auth_proof(agent_id: &str, jwt_secret: &str) -> Result<String> {
    use jsonwebtoken::{encode, EncodingKey, Header};
    use serde::Serialize;

    #[derive(Serialize)]
    struct Claims {
        sub: String,
        iat: u64,
    }

    let claims = Claims {
        sub: agent_id.to_string(),
        iat: chrono::Utc::now().timestamp() as u64,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .context("Failed to sign JWT")
}

#[derive(Debug, thiserror::Error)]
enum FetchError {
    #[error("project token has expired")]
    Expired,
    #[error("project token has been revoked")]
    Revoked,
    #[error("authentication failed: invalid project token")]
    InvalidToken,
    #[error("project not found")]
    NotFound,
    #[error("HTTP error: {0}")]
    Other(#[from] anyhow::Error),
}

async fn fetch_secrets(
    base_url: &str,
    project_name: &str,
    token: &str,
) -> Result<HashMap<String, String>, FetchError> {
    let url = format!(
        "{}/project/secrets/{}",
        base_url.trim_end_matches('/'),
        project_name
    );

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .map_err(|e| FetchError::Other(anyhow::anyhow!("HTTP request failed: {}", e)))?;

    let status = response.status();

    if status == reqwest::StatusCode::UNAUTHORIZED {
        let body: ErrorBody = response.json().await.unwrap_or_default();
        return Err(match body.error_code.as_deref() {
            Some("token_expired") => FetchError::Expired,
            Some("token_revoked") => FetchError::Revoked,
            _ => FetchError::InvalidToken,
        });
    }

    if status == reqwest::StatusCode::NOT_FOUND {
        return Err(FetchError::NotFound);
    }

    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(FetchError::Other(anyhow::anyhow!(
            "Server returned {}: {}",
            status,
            body
        )));
    }

    let secrets: SecretsResponse = response
        .json()
        .await
        .map_err(|e| FetchError::Other(anyhow::anyhow!("Failed to parse response: {}", e)))?;
    Ok(secrets.env_vars)
}

async fn discover_project(
    base_url: &str,
    project_name: &str,
    agent_id: &str,
    jwt_secret: &str,
    env_content: &str,
    regenerate: bool,
) -> Result<DiscoverResponse> {
    let auth_proof = make_auth_proof(agent_id, jwt_secret)?;
    let url = format!("{}/agent/discover", base_url.trim_end_matches('/'));

    let body = serde_json::json!({
        "agent_id": agent_id,
        "auth_proof": auth_proof,
        "context": {
            "project_name": project_name,
            "file_content": env_content,
        },
        "regenerate_token": regenerate,
    });

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .context("HTTP request to /agent/discover failed")?;

    let status = response.status();
    if !status.is_success() {
        let text = response.text().await.unwrap_or_default();
        anyhow::bail!("/agent/discover returned {}: {}", status, text);
    }

    response
        .json::<DiscoverResponse>()
        .await
        .context("Failed to parse /agent/discover response")
}

fn default_token_path(project: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(format!(".cortex-token-{}", project))
}

fn read_token_file(path: &std::path::Path) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read token file {}", path.display()))?;
    Ok(content.trim().to_string())
}

fn write_token_file(path: &std::path::Path, token: &str) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)
        .with_context(|| format!("Failed to create token file {}", path.display()))?;
    f.write_all(token.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn default_priv_key_path(agent_id: &str) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cortex").join(format!("agent-{}.key", agent_id))
}

fn write_priv_key_file(path: &std::path::Path, priv_b64: &str) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::File::create(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    f.write_all(priv_b64.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn daemon_session_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cortex").join("daemon-session.json")
}

#[derive(serde::Serialize, serde::Deserialize)]
struct DaemonSession {
    access_token: String,
    expires_in: i64,
    server_url: String,
}

async fn daemon_login(url: &str) -> Result<()> {
    let client = reqwest::Client::new();
    let auth_resp: serde_json::Value = client
        .post(format!("{}/device/authorize", url.trim_end_matches('/')))
        .json(&serde_json::json!({"client_id": "cortex-cli"}))
        .send()
        .await
        .context("device/authorize HTTP request failed")?
        .error_for_status()
        .context("device/authorize returned non-200")?
        .json()
        .await?;
    let device_code = auth_resp
        .get("device_code")
        .and_then(|v| v.as_str())
        .context("missing device_code")?
        .to_string();
    let user_code = auth_resp
        .get("user_code")
        .and_then(|v| v.as_str())
        .context("missing user_code")?;
    let verification_uri = auth_resp
        .get("verification_uri")
        .and_then(|v| v.as_str())
        .unwrap_or("/device");
    let interval = auth_resp.get("interval").and_then(|v| v.as_i64()).unwrap_or(5);

    eprintln!("[cortex-cli] visit {}{} and approve user_code: {}", url.trim_end_matches('/'), verification_uri, user_code);
    eprintln!("[cortex-cli] polling…");

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval as u64)).await;
        let resp = client
            .post(format!("{}/device/token", url.trim_end_matches('/')))
            .json(&serde_json::json!({
                "device_code": device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            }))
            .send()
            .await?;
        let status = resp.status();
        if status.is_success() {
            let body: serde_json::Value = resp.json().await?;
            let access_token = body
                .get("access_token")
                .and_then(|v| v.as_str())
                .context("missing access_token")?
                .to_string();
            let expires_in = body.get("expires_in").and_then(|v| v.as_i64()).unwrap_or(0);
            let session = DaemonSession {
                access_token,
                expires_in,
                server_url: url.to_string(),
            };
            let path = daemon_session_path();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, serde_json::to_string_pretty(&session)?)?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
            eprintln!("[cortex-cli] daemon session saved to {}", path.display());
            return Ok(());
        }
        let body: serde_json::Value = resp.json().await.unwrap_or_default();
        let code = body.get("error_code").and_then(|v| v.as_str()).unwrap_or("");
        if code != "authorization_pending" {
            anyhow::bail!("device/token failed: {}", body);
        }
    }
}

fn daemon_status(_sock: Option<&std::path::Path>) -> Result<()> {
    let path = daemon_session_path();
    if !path.exists() {
        println!("no daemon session at {}", path.display());
        return Ok(());
    }
    let s = std::fs::read_to_string(&path)?;
    let session: DaemonSession = serde_json::from_str(&s)?;
    println!(
        "daemon session @ {} (expires_in={}s)",
        session.server_url, session.expires_in
    );
    Ok(())
}

fn daemon_logout() -> Result<()> {
    let path = daemon_session_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
        eprintln!("[cortex-cli] removed {}", path.display());
    }
    Ok(())
}

fn load_env_content(env_file: Option<&std::path::Path>) -> Result<String> {
    if let Some(path) = env_file {
        return std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read env file {}", path.display()));
    }
    let default = std::path::Path::new(".env");
    if default.exists() {
        return std::fs::read_to_string(default).context("Failed to read ./.env");
    }
    Ok(String::new())
}
