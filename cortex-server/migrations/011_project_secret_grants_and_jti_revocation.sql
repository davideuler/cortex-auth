-- Migration 011: Explicit project-secret grants + per-JTI token revocation
--   + nonce replay index cleanup.
--
-- project_secret_grants replaces the implicit env-name-across-namespace
-- matching in /agent/discover. Secrets are only accessible to a project when
-- an operator has explicitly granted them. The env_var_name column carries
-- the env-var key to inject the secret under (auto-derived from key_path
-- last segment when NULL).
--
-- revoked_token_jti enables per-token revocation for signed EdDSA project
-- tokens. When an admin revokes a project, the signed token's `jti` claim
-- is written here so the verifier rejects it even before `exp`.

CREATE TABLE IF NOT EXISTS project_secret_grants (
    id          TEXT PRIMARY KEY,
    project_name TEXT NOT NULL,
    secret_id   TEXT NOT NULL,
    -- If set, the env-var name under which the secret is injected.
    -- If NULL, the server derives it from the secret's key_path last segment.
    env_var_name TEXT,
    granted_by  TEXT NOT NULL DEFAULT 'admin',
    granted_at  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(project_name, secret_id)
);

CREATE INDEX IF NOT EXISTS idx_psg_project
    ON project_secret_grants (project_name);
CREATE INDEX IF NOT EXISTS idx_psg_secret
    ON project_secret_grants (secret_id);

-- Per-JTI revocation list for signed EdDSA project tokens.
CREATE TABLE IF NOT EXISTS revoked_token_jti (
    jti         TEXT PRIMARY KEY,
    revoked_at  TEXT NOT NULL DEFAULT (datetime('now')),
    reason      TEXT
);

CREATE INDEX IF NOT EXISTS idx_revoked_jti_time
    ON revoked_token_jti (revoked_at);

-- Track the most recently issued signed EdDSA JWT jti per project so that
-- /admin/projects/<n>/revoke can also blacklist it by jti.
ALTER TABLE projects ADD COLUMN signed_token_jti TEXT;
