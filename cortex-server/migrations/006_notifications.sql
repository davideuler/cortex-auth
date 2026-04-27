-- Outbound notification channels (honey-token alarms, recovery-mode boots).
--
-- Channels live in the DB so admins can manage them from the dashboard. The
-- per-channel `config_json` (webhook URLs, bot tokens, SMTP recipients) is
-- itself a secret, so it's stored envelope-encrypted under the KEK exactly
-- like a regular secret value.
--
-- channel_type is one of: email | slack | telegram | discord
--   email    -> uses himalaya-cli (https://pimalaya.org/himalaya/) when the
--               binary is on PATH; the config_json holds {"to": "...", "account": "..."?}
--   slack    -> incoming-webhook URL: {"webhook_url": "https://hooks.slack.com/..."}
--   telegram -> bot API: {"bot_token": "...", "chat_id": "..."}
--   discord  -> incoming-webhook URL: {"webhook_url": "https://discord.com/api/webhooks/..."}

CREATE TABLE IF NOT EXISTS notification_channels (
    id TEXT PRIMARY KEY,
    channel_type TEXT NOT NULL CHECK (channel_type IN ('email','slack','telegram','discord')),
    name TEXT NOT NULL UNIQUE,
    config_ciphertext TEXT NOT NULL,
    config_wrapped_dek TEXT NOT NULL,
    kek_version INTEGER NOT NULL DEFAULT 1,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
