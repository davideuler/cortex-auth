//! cortex-daemon — long-running session holder.
//!
//! Today this is a **scaffolding** implementation of UPDATED_DESIGN.md §9.
//! It listens on `~/.cortex/agent.sock` and exposes a single line-oriented
//! JSON protocol over the socket: one request per connection, one response.
//!
//! Supported commands (as JSON objects on a single line):
//!   * `{"cmd":"status"}` → `{"ok":true,"session":<DaemonSession or null>}`
//!   * `{"cmd":"run","program":"python","args":["main.py"],"project":"<name>","token":"<project_token>","url":"<server>"}`
//!     → spawns the program with secrets injected as env vars; replies
//!       `{"ok":true,"exit_code":N}` after the child exits. The raw secrets
//!       never cross the socket back to the caller — they stay in the child
//!       process environment, exactly as in `cortex-cli run`.
//!
//! NOT yet implemented (tracked in UNCERTAINTIES.md #16):
//!   * Daemon attestation header (#17 in the same doc).
//!   * `inject_template` / `ssh_proxy` socket commands.
//!   * mlockall / PR_SET_DUMPABLE / MemoryDenyWriteExecute hardening.
//!   * Re-issuance of the daemon's signing key from the OAuth access token.

use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let sock_path = sock_path();
    if let Some(parent) = sock_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    if sock_path.exists() {
        std::fs::remove_file(&sock_path).ok();
    }

    let listener = UnixListener::bind(&sock_path)
        .with_context(|| format!("Failed to bind {}", sock_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&sock_path, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!("cortex-daemon listening on {}", sock_path.display());

    loop {
        let (stream, _addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream).await {
                tracing::warn!("connection error: {}", e);
            }
        });
    }
}

fn sock_path() -> PathBuf {
    if let Ok(s) = std::env::var("CORTEX_DAEMON_SOCK") {
        return PathBuf::from(s);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cortex").join("agent.sock")
}

#[derive(serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
enum Request {
    Status,
    Run {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        project: String,
        token: String,
        url: String,
    },
}

async fn handle_conn(stream: UnixStream) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let req: Request = match serde_json::from_str(line.trim()) {
        Ok(r) => r,
        Err(e) => {
            let resp = serde_json::json!({"ok": false, "error": e.to_string()});
            write_half.write_all(format!("{}\n", resp).as_bytes()).await?;
            return Ok(());
        }
    };

    let resp = match req {
        Request::Status => {
            let session_path = session_path();
            let session = if session_path.exists() {
                std::fs::read_to_string(&session_path)
                    .ok()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            } else {
                None
            };
            serde_json::json!({"ok": true, "session": session})
        }
        Request::Run {
            program,
            args,
            project,
            token,
            url,
        } => match exec_with_secrets(&program, &args, &project, &token, &url).await {
            Ok(code) => serde_json::json!({"ok": true, "exit_code": code}),
            Err(e) => serde_json::json!({"ok": false, "error": e.to_string()}),
        },
    };
    write_half.write_all(format!("{}\n", resp).as_bytes()).await?;
    Ok(())
}

fn session_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".cortex").join("daemon-session.json")
}

async fn exec_with_secrets(
    program: &str,
    args: &[String],
    project: &str,
    token: &str,
    url: &str,
) -> Result<i32> {
    let secrets = fetch_secrets(url, project, token).await?;
    let mut cmd = tokio::process::Command::new(program);
    cmd.args(args);
    for (k, v) in &secrets {
        cmd.env(k, v);
    }
    let status = cmd.status().await?;
    Ok(status.code().unwrap_or(-1))
}

#[derive(serde::Deserialize)]
struct SecretsResponse {
    env_vars: HashMap<String, String>,
}

async fn fetch_secrets(
    base_url: &str,
    project_name: &str,
    token: &str,
) -> Result<HashMap<String, String>> {
    let url = format!(
        "{}/project/secrets/{}",
        base_url.trim_end_matches('/'),
        project_name
    );
    let resp = reqwest::Client::new()
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .context("HTTP request failed")?
        .error_for_status()
        .context("server returned non-2xx")?;
    let body: SecretsResponse = resp.json().await?;
    Ok(body.env_vars)
}
