use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(
    name = "cortex-cli",
    about = "Launch a process with secrets injected from CortexAuth",
    long_about = "Fetches secrets from a CortexAuth server and launches the specified command \
                  with those secrets injected as environment variables. Secrets are never \
                  printed to stdout or stderr."
)]
struct Cli {
    /// Project name registered in CortexAuth
    #[arg(long, env = "CORTEX_PROJECT")]
    project: String,

    /// Project token for authenticating with CortexAuth
    #[arg(long, env = "CORTEX_TOKEN")]
    token: String,

    /// CortexAuth server URL (e.g. http://localhost:3000)
    #[arg(long, env = "CORTEX_URL")]
    url: String,

    /// Command and arguments to run (separated by --)
    #[arg(trailing_var_arg = true, required = true)]
    command: Vec<String>,
}

#[derive(serde::Deserialize)]
struct SecretsResponse {
    env_vars: HashMap<String, String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let secrets = fetch_secrets(&cli.url, &cli.project, &cli.token)
        .await
        .context("Failed to fetch secrets from CortexAuth")?;

    if cli.command.is_empty() {
        anyhow::bail!("No command specified");
    }

    let program = &cli.command[0];
    let args = &cli.command[1..];

    let mut cmd = Command::new(program);
    cmd.args(args);

    // Inject secrets into environment
    for (key, value) in &secrets {
        cmd.env(key, value);
    }

    // Replace current process with the command (exec)
    let err = cmd.exec();
    // exec only returns on error
    Err(anyhow::anyhow!("Failed to exec '{}': {}", program, err))
}

async fn fetch_secrets(
    base_url: &str,
    project_name: &str,
    token: &str,
) -> Result<HashMap<String, String>> {
    let url = format!("{}/agent/secrets/{}", base_url.trim_end_matches('/'), project_name);

    let client = reqwest::Client::new();
    let response = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .context("HTTP request failed")?;

    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        anyhow::bail!("Authentication failed: invalid or expired project token");
    }

    if response.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!("Project '{}' not found on CortexAuth server", project_name);
    }

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Server returned {}: {}", status, body);
    }

    let secrets: SecretsResponse = response.json().await.context("Failed to parse response")?;
    Ok(secrets.env_vars)
}
