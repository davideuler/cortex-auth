-- Envelope encryption + KEK sentinel + namespaces registry.
--
-- The server is unsealed by an operator-supplied KEK password. Each row keeps
-- its own random Data Encryption Key (DEK) wrapped by the in-memory KEK; this
-- column carries the wrapped DEK as `nonce_k || ciphertext_of_DEK`, base64.
-- The body ciphertext (nonce_d || ciphertext_of_value, base64) stays in the
-- existing `encrypted_value` / `jwt_secret_encrypted` column.

CREATE TABLE IF NOT EXISTS kek_metadata (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    salt TEXT NOT NULL,
    sentinel_ciphertext TEXT NOT NULL,
    kek_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS namespaces (
    name TEXT PRIMARY KEY,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO namespaces (name, description) VALUES ('default', 'Default namespace');

ALTER TABLE secrets ADD COLUMN wrapped_dek TEXT;
ALTER TABLE secrets ADD COLUMN kek_version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE agents ADD COLUMN wrapped_dek TEXT;
ALTER TABLE agents ADD COLUMN kek_version INTEGER NOT NULL DEFAULT 1;
