CREATE TABLE IF NOT EXISTS secrets (
    id TEXT PRIMARY KEY,
    key_path TEXT NOT NULL UNIQUE,
    secret_type TEXT NOT NULL CHECK(secret_type IN ('KEY_VALUE', 'JSON_CONFIG', 'TEMPLATE_CONFIG')),
    encrypted_value TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL UNIQUE,
    jwt_secret_encrypted TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    policy_name TEXT NOT NULL UNIQUE,
    agent_pattern TEXT NOT NULL,
    allowed_paths TEXT NOT NULL DEFAULT '[]',
    denied_paths TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    project_name TEXT NOT NULL UNIQUE,
    project_token_hash TEXT NOT NULL,
    env_mappings TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    agent_id TEXT,
    project_name TEXT,
    action TEXT NOT NULL,
    resource_path TEXT,
    status TEXT NOT NULL DEFAULT 'success',
    timestamp TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_secrets_key_path ON secrets(key_path);
CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id);
CREATE INDEX IF NOT EXISTS idx_projects_project_name ON projects(project_name);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
