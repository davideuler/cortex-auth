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
