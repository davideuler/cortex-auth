-- Admin token storage: a single row holding a SHA-256 hash of the bootstrap
-- admin token. The plaintext token is generated once on first boot, displayed
-- in the server console, and never persisted — only the one-way hash is kept
-- here for subsequent X-Admin-Token verification.

CREATE TABLE IF NOT EXISTS admin_token (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
