//! Outbound notification dispatcher.
//!
//! Today this is wired to two events:
//!   * honey-token access (high-priority alarm — see api/agent.rs)
//!   * server boot in Shamir recovery mode (see kek.rs)
//!
//! Each enabled `notification_channels` row is rendered to a small JSON
//! payload and pushed to the channel-specific transport in a background
//! tokio task. We never block the calling request handler — if a channel is
//! slow or returns 5xx the dispatcher just logs a `tracing::warn!`.
//!
//! The per-channel config (webhook URLs, bot tokens, SMTP recipients) is
//! envelope-encrypted under the KEK exactly like a regular secret, so
//! losing the DB to an attacker leaks nothing about who gets paged.

use serde::{Deserialize, Serialize};

use crate::{
    crypto,
    models::notification::NotificationChannel,
    state::AppState,
};

/// All events that can trigger an outbound notification.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "event")]
pub enum NotificationEvent {
    /// A request tried to read a `is_honey_token=true` secret. The calling
    /// project token has already been revoked by the time we dispatch.
    HoneyTokenAccess {
        project_name: String,
        key_path: String,
        source_ip: Option<String>,
    },
    /// The server booted via Shamir m-of-n recovery instead of the normal
    /// password unseal flow — operators should know the moment this happens.
    RecoveryBoot { hostname: Option<String> },
}

impl NotificationEvent {
    fn title(&self) -> &'static str {
        match self {
            NotificationEvent::HoneyTokenAccess { .. } => "🚨 CortexAuth honey-token alarm",
            NotificationEvent::RecoveryBoot { .. } => "⚠️ CortexAuth booted in recovery mode",
        }
    }

    fn body(&self) -> String {
        match self {
            NotificationEvent::HoneyTokenAccess { project_name, key_path, source_ip } => {
                format!(
                    "A read attempt against honey-token `{}` was made by project `{}`. \
                     The project's token has been revoked. Source IP: {}.",
                    key_path,
                    project_name,
                    source_ip.as_deref().unwrap_or("unknown"),
                )
            }
            NotificationEvent::RecoveryBoot { hostname } => format!(
                "cortex-server reconstructed its KEK from Shamir shares and is now \
                 UNSEALED on {}. Verify the operators who provided shares match the \
                 expected recovery quorum.",
                hostname.as_deref().unwrap_or("(unknown host)"),
            ),
        }
    }
}

/// Spawn a background task that fans out `event` to every enabled channel.
/// Returns immediately — the caller never waits on slow webhooks.
pub fn dispatch(state: &AppState, event: NotificationEvent) {
    let state = state.clone();
    tokio::spawn(async move {
        if let Err(e) = dispatch_inner(&state, event).await {
            tracing::warn!("notifications: dispatch failed: {}", e);
        }
    });
}

async fn dispatch_inner(state: &AppState, event: NotificationEvent) -> anyhow::Result<()> {
    let channels = sqlx::query_as::<_, NotificationChannel>(
        "SELECT id, channel_type, name, config_ciphertext, config_wrapped_dek, \
                kek_version, enabled, description, created_at, updated_at \
         FROM notification_channels WHERE enabled = 1",
    )
    .fetch_all(&state.pool)
    .await?;

    if channels.is_empty() {
        tracing::debug!("notifications: no enabled channels for event {:?}", event);
        return Ok(());
    }

    for ch in channels {
        let event = event.clone();
        let state = state.clone();
        tokio::spawn(async move {
            match send_to_channel(&state, &ch, &event).await {
                Ok(()) => tracing::info!(
                    channel = %ch.name,
                    channel_type = %ch.channel_type,
                    "notification delivered"
                ),
                Err(e) => tracing::warn!(
                    channel = %ch.name,
                    channel_type = %ch.channel_type,
                    "notification delivery failed: {}",
                    e
                ),
            }
        });
    }
    Ok(())
}

async fn send_to_channel(
    state: &AppState,
    ch: &NotificationChannel,
    event: &NotificationEvent,
) -> anyhow::Result<()> {
    let config_json = crypto::open_envelope(
        &ch.config_ciphertext,
        &ch.config_wrapped_dek,
        &state.kek,
    )?;

    let title = event.title();
    let body = event.body();
    let payload_text = format!("{}\n\n{}", title, body);

    match ch.channel_type.as_str() {
        "slack" => {
            let cfg: SlackConfig = serde_json::from_str(&config_json)?;
            send_slack(&cfg.webhook_url, &payload_text).await
        }
        "discord" => {
            let cfg: DiscordConfig = serde_json::from_str(&config_json)?;
            send_discord(&cfg.webhook_url, &payload_text).await
        }
        "telegram" => {
            let cfg: TelegramConfig = serde_json::from_str(&config_json)?;
            send_telegram(&cfg.bot_token, &cfg.chat_id, &payload_text).await
        }
        "email" => {
            let cfg: EmailConfig = serde_json::from_str(&config_json)?;
            send_email_via_himalaya(&cfg, title, &body).await
        }
        other => anyhow::bail!("unknown channel_type '{}'", other),
    }
}

#[derive(Deserialize)]
struct SlackConfig {
    webhook_url: String,
}

#[derive(Deserialize)]
struct DiscordConfig {
    webhook_url: String,
}

#[derive(Deserialize)]
struct TelegramConfig {
    bot_token: String,
    chat_id: String,
}

#[derive(Deserialize)]
struct EmailConfig {
    to: String,
    /// Optional himalaya account name (`himalaya -a <account> ...`). When
    /// omitted himalaya uses its default account.
    #[serde(default)]
    account: Option<String>,
}

async fn send_slack(webhook_url: &str, text: &str) -> anyhow::Result<()> {
    let resp = reqwest::Client::new()
        .post(webhook_url)
        .json(&serde_json::json!({ "text": text }))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("slack webhook returned {}", resp.status());
    }
    Ok(())
}

async fn send_discord(webhook_url: &str, text: &str) -> anyhow::Result<()> {
    let resp = reqwest::Client::new()
        .post(webhook_url)
        .json(&serde_json::json!({ "content": text }))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("discord webhook returned {}", resp.status());
    }
    Ok(())
}

async fn send_telegram(bot_token: &str, chat_id: &str, text: &str) -> anyhow::Result<()> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token);
    let resp = reqwest::Client::new()
        .post(&url)
        .json(&serde_json::json!({ "chat_id": chat_id, "text": text }))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("telegram returned {}", resp.status());
    }
    Ok(())
}

/// Send via the `himalaya` CLI if it is on PATH. The body is piped to
/// `himalaya message send` on stdin (RFC822 message). Falls back to a
/// warning + no-op if himalaya isn't installed.
async fn send_email_via_himalaya(
    cfg: &EmailConfig,
    subject: &str,
    body: &str,
) -> anyhow::Result<()> {
    if !himalaya_available().await {
        anyhow::bail!(
            "himalaya CLI not found on PATH; install https://pimalaya.org/himalaya/ \
             or remove this email channel"
        );
    }

    let message = format!(
        "From: cortex-auth\r\nTo: {}\r\nSubject: {}\r\n\r\n{}\r\n",
        cfg.to, subject, body
    );

    let mut cmd = tokio::process::Command::new("himalaya");
    if let Some(account) = &cfg.account {
        cmd.arg("-a").arg(account);
    }
    cmd.arg("message").arg("send");
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = cmd.spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(message.as_bytes()).await?;
        stdin.shutdown().await?;
    }
    let output = child.wait_with_output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("himalaya exited with {}: {}", output.status, stderr.trim());
    }
    Ok(())
}

async fn himalaya_available() -> bool {
    tokio::process::Command::new("himalaya")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}
