use anyhow::{Context, Result};

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub database_url: String,
    pub encryption_key: [u8; 32],
    pub admin_token: String,
    pub session_secret: String,
    pub port: u16,
    pub tls_cert_file: Option<String>,
    pub tls_key_file: Option<String>,
}

impl AppConfig {
    pub fn from_env() -> Result<Self> {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "sqlite://cortex-auth.db".to_string());

        let encryption_key_hex = std::env::var("ENCRYPTION_KEY")
            .context("ENCRYPTION_KEY env var is required (64 hex chars = 32 bytes)")?;

        let encryption_key = parse_hex_key(&encryption_key_hex)
            .context("ENCRYPTION_KEY must be exactly 64 hex characters")?;

        let admin_token =
            std::env::var("ADMIN_TOKEN").context("ADMIN_TOKEN env var is required")?;

        let session_secret =
            std::env::var("SESSION_SECRET").context("SESSION_SECRET env var is required")?;

        let port = std::env::var("PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse::<u16>()
            .context("PORT must be a valid port number")?;

        let tls_cert_file = std::env::var("TLS_CERT_FILE").ok();
        let tls_key_file = std::env::var("TLS_KEY_FILE").ok();

        Ok(AppConfig {
            database_url,
            encryption_key,
            admin_token,
            session_secret,
            port,
            tls_cert_file,
            tls_key_file,
        })
    }

    pub fn test_config() -> Self {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(b"test_encrypt_key");
        key[16..].copy_from_slice(b"test_encrypt_key");
        AppConfig {
            database_url: "sqlite::memory:".to_string(),
            encryption_key: key,
            admin_token: "test-admin-token".to_string(),
            session_secret: "test-session-secret-32-chars-min".to_string(),
            port: 3000,
            tls_cert_file: None,
            tls_key_file: None,
        }
    }
}

pub fn parse_hex_key(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex).context("Invalid hex string")?;
    if bytes.len() != 32 {
        anyhow::bail!("Key must be 32 bytes, got {}", bytes.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}
