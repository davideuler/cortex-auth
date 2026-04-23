ALTER TABLE secrets ADD COLUMN namespace TEXT NOT NULL DEFAULT 'default';
ALTER TABLE agents ADD COLUMN namespace TEXT NOT NULL DEFAULT 'default';
ALTER TABLE projects ADD COLUMN namespace TEXT NOT NULL DEFAULT 'default';

CREATE INDEX IF NOT EXISTS idx_secrets_namespace ON secrets(namespace);
CREATE INDEX IF NOT EXISTS idx_agents_namespace ON agents(namespace);
CREATE INDEX IF NOT EXISTS idx_projects_namespace ON projects(namespace);
