use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

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
    /// Launch a process with secrets injected from CortexAuth via the daemon.
    /// The daemon must be running (`cortex-daemon`); it holds the project token
    /// and injects secrets into the child process. No credentials are passed
    /// through this command — the daemon manages all authentication.
    Run {
        /// Project name registered in CortexAuth
        #[arg(long, env = "CORTEX_PROJECT")]
        project: String,

        /// CortexAuth server URL (e.g. http://localhost:3000)
        #[arg(long, env = "CORTEX_URL")]
        url: String,

        /// Path to .env file describing required env-var names (used by discover).
        /// Defaults to "./.env" if it exists.
        #[arg(long, env = "CORTEX_ENV_FILE")]
        env_file: Option<PathBuf>,

        /// Path to the daemon Unix socket (default: ~/.cortex/agent.sock)
        #[arg(long, env = "CORTEX_DAEMON_SOCK")]
        sock: Option<PathBuf>,

        /// Command and arguments to run (separated by --)
        #[arg(trailing_var_arg = true, required = true)]
        cmd: Vec<String>,
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

        /// Path to the agent's Ed25519 private key (base64url, 32 bytes).
        /// Defaults to ~/.cortex/agent-<agent_id>.key.
        #[arg(long, env = "CORTEX_PRIV_KEY_FILE")]
        priv_key_file: Option<PathBuf>,

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

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            project,
            url,
            env_file,
            sock,
            cmd,
        } => {
            if cmd.is_empty() {
                anyhow::bail!("No command specified");
            }
            let req = serde_json::json!({
                "cmd": "run",
                "program": &cmd[0],
                "args": &cmd[1..],
                "project": project,
                "url": url,
                "env_file": env_file.map(|p| p.display().to_string()),
            });
            let resp = send_daemon_request(&req, sock.as_deref()).await?;
            if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                let code = resp.get("exit_code").and_then(|v| v.as_i64()).unwrap_or(-1);
                std::process::exit(code as i32);
            }
            let error_code = resp.get("error_code").and_then(|v| v.as_str()).unwrap_or("");
            if error_code == "pending_approval" {
                let grant_id = resp
                    .get("grant_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                let keys = resp
                    .get("requested_keys")
                    .map(|v| v.to_string())
                    .unwrap_or_default();
                eprintln!("[cortex-cli] project access pending admin approval");
                eprintln!("[cortex-cli] grant_id: {}", grant_id);
                eprintln!("[cortex-cli] requested_keys: {}", keys);
                eprintln!(
                    "[cortex-cli] approve at the CortexAuth dashboard or with the admin API"
                );
                std::process::exit(1);
            }
            let error = resp
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("daemon returned error");
            anyhow::bail!("daemon run failed: {}", error);
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
            let signed = sign_auth_proof(&agent_id, &priv_key_file)?;
            println!(
                "{}",
                serde_json::json!({
                    "ts": signed.ts,
                    "nonce": signed.nonce,
                    "auth_proof": signed.auth_proof,
                })
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
            priv_key_file,
            env_file,
            regenerate,
        } => {
            let env_content = load_env_content(env_file.as_deref())?;
            let key_path = priv_key_file.unwrap_or_else(|| default_priv_key_path(&agent_id));
            let resp = discover_project(
                &url,
                &project,
                &agent_id,
                &key_path,
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

struct SignedAuthProof {
    ts: i64,
    nonce: String,
    auth_proof: String,
}

fn sign_auth_proof(agent_id: &str, priv_key_file: &std::path::Path) -> Result<SignedAuthProof> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
    use ed25519_dalek::{Signer, SigningKey};
    use rand_core::RngCore;

    let priv_b64 = std::fs::read_to_string(priv_key_file)
        .with_context(|| format!("Failed to read private key {}", priv_key_file.display()))?;
    let priv_bytes = B64
        .decode(priv_b64.trim().as_bytes())
        .context("private key file must be base64url")?;
    anyhow::ensure!(priv_bytes.len() == 32, "private key must be 32 bytes");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&priv_bytes);
    let signing = SigningKey::from_bytes(&arr);

    let ts = chrono::Utc::now().timestamp();
    let mut nonce_bytes = [0u8; 8];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce: String = nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let message = format!("{}|{}|{}|/agent/discover", ts, nonce, agent_id);
    let sig = signing.sign(message.as_bytes());
    let auth_proof = B64.encode(sig.to_bytes());

    Ok(SignedAuthProof { ts, nonce, auth_proof })
}

async fn send_daemon_request(
    req: &serde_json::Value,
    sock: Option<&std::path::Path>,
) -> Result<serde_json::Value> {
    let sock_path = match sock {
        Some(p) => p.to_path_buf(),
        None => {
            if let Ok(s) = std::env::var("CORTEX_DAEMON_SOCK") {
                std::path::PathBuf::from(s)
            } else {
                let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
                std::path::PathBuf::from(home)
                    .join(".cortex")
                    .join("agent.sock")
            }
        }
    };
    let stream = UnixStream::connect(&sock_path).await.with_context(|| {
        format!(
            "Cannot connect to daemon socket {}. Is cortex-daemon running? \
             Start it with: cortex-daemon",
            sock_path.display()
        )
    })?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    write_half
        .write_all(format!("{}\n", serde_json::to_string(req)?).as_bytes())
        .await?;
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let resp: serde_json::Value =
        serde_json::from_str(line.trim()).context("daemon returned invalid JSON")?;
    Ok(resp)
}

async fn discover_project(
    base_url: &str,
    project_name: &str,
    agent_id: &str,
    priv_key_file: &std::path::Path,
    env_content: &str,
    regenerate: bool,
) -> Result<DiscoverResponse> {
    let signed = sign_auth_proof(agent_id, priv_key_file)?;
    let url = format!("{}/agent/discover", base_url.trim_end_matches('/'));

    let body = serde_json::json!({
        "agent_id": agent_id,
        "auth_proof": signed.auth_proof,
        "ts": signed.ts,
        "nonce": signed.nonce,
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
    let mut options = std::fs::OpenOptions::new();
    options.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut f = options.open(path)
        .with_context(|| format!("Failed to create {}", path.display()))?;
    f.write_all(priv_b64.as_bytes())?;
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
