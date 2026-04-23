use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::collections::HashMap;
use std::os::unix::process::CommandExt;
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

        /// Project token for authenticating with CortexAuth
        #[arg(long, env = "CORTEX_TOKEN")]
        token: String,

        /// CortexAuth server URL (e.g. http://localhost:3000)
        #[arg(long, env = "CORTEX_URL")]
        url: String,

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
}

#[derive(serde::Deserialize)]
struct SecretsResponse {
    env_vars: HashMap<String, String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run { project, token, url, cmd } => {
            let secrets = fetch_secrets(&url, &project, &token)
                .await
                .context("Failed to fetch secrets from CortexAuth")?;

            if cmd.is_empty() {
                anyhow::bail!("No command specified");
            }

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

async fn fetch_secrets(
    base_url: &str,
    project_name: &str,
    token: &str,
) -> Result<HashMap<String, String>> {
    let url = format!("{}/project/secrets/{}", base_url.trim_end_matches('/'), project_name);

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
