-- Project token lifecycle: short-lived tokens with expiration and manual revocation.
-- expires_at: ISO-8601 UTC timestamp (e.g. "2026-01-01 12:34:56") when the token stops being valid.
-- revoked_at: when set, the token is rejected regardless of expires_at.
ALTER TABLE projects ADD COLUMN token_expires_at TEXT;
ALTER TABLE projects ADD COLUMN token_revoked_at TEXT;

CREATE INDEX IF NOT EXISTS idx_projects_token_expires_at ON projects(token_expires_at);
