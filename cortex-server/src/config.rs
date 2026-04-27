use anyhow::{Context, Result};

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub database_url: String,
    pub admin_token: String,
    pub port: u16,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://cortex-auth.db".to_string());

        let admin_token =
            std::env::var("ADMIN_TOKEN").context("ADMIN_TOKEN env var is required")?;

        let port = std::env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()
            .context("PORT must be a valid port number")?;

        let tls_cert_file = std::env::var("TLS_CERT_FILE").ok();
        let tls_key_file = std::env::var("TLS_KEY_FILE").ok();

        Ok(AppConfig {
            database_url,
            admin_token,
            port,
            tls_cert_file,
            tls_key_file,
        })
    }

    pub fn test_config() -> Self {
        AppConfig {
            database_url: "sqlite::memory:".to_string(),
            admin_token: "test-admin-token".to_string(),
            port: 3000,
            tls_cert_file: None,
            tls_key_file: None,
        }
    }
}

/// Read the operator KEK password from $CORTEX_KEK_PASSWORD if set, otherwise
/// prompt the operator interactively on stdin (echo disabled). Whitespace is
/// stripped on both sides.
pub fn read_kek_password() -> Result<String> {
    if let Ok(p) = std::env::var("CORTEX_KEK_PASSWORD") {
        let p = p.trim().to_string();
        anyhow::ensure!(!p.is_empty(), "CORTEX_KEK_PASSWORD is set but empty");
        return Ok(p);
    }
    let pwd = rpassword::prompt_password(
        "[cortex-server SEALED] Enter KEK operator password: ",
    )
    .context("Failed to read KEK password from stdin")?;
    let pwd = pwd.trim().to_string();
    anyhow::ensure!(!pwd.is_empty(), "Empty KEK password rejected");
    Ok(pwd)
}

/// True when the operator started the server in Shamir recovery mode.
/// Triggered by `CORTEX_RECOVERY_MODE=1`. In that mode the boot path prompts
/// for `CORTEX_RECOVERY_THRESHOLD` shares on stdin and reconstructs the KEK
/// directly (bypassing the password → Argon2id derivation).
pub fn recovery_mode_requested() -> bool {
    matches!(
        std::env::var("CORTEX_RECOVERY_MODE").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes")
    )
}

/// Interactively prompt the operator for `threshold` Shamir shares, one per
/// line on stdin (echo disabled). Returns the collected shares.
pub fn read_shamir_shares(threshold: u8) -> Result<Vec<String>> {
    eprintln!(
        "[cortex-server RECOVERY] Paste {} Shamir shares (one per line, hidden):",
        threshold
    );
    let mut shares = Vec::with_capacity(threshold as usize);
    for i in 1..=threshold {
        let s = rpassword::prompt_password(format!("  share {} of {}: ", i, threshold))
            .with_context(|| format!("reading share {}", i))?;
        let s = s.trim().to_string();
        anyhow::ensure!(!s.is_empty(), "Empty share rejected");
        shares.push(s);
    }
    Ok(shares)
}

/// Read `CORTEX_RECOVERY_THRESHOLD` from env (required in recovery mode).
pub fn recovery_threshold() -> Result<u8> {
    let raw = std::env::var("CORTEX_RECOVERY_THRESHOLD")
        .context("CORTEX_RECOVERY_THRESHOLD must be set when CORTEX_RECOVERY_MODE=1")?;
    let n: u8 = raw
        .trim()
        .parse()
        .context("CORTEX_RECOVERY_THRESHOLD must be a small integer")?;
    anyhow::ensure!(n >= 2, "threshold must be >= 2");
    Ok(n)
}
