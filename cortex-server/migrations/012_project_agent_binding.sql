-- Bind project tokens to the agent that discovered them. Daemon attestation
-- checks compare daemon_sessions.agent_id against this value on every
-- /project/* request, preventing a valid daemon for one agent from fronting a
-- stolen token for another project.

ALTER TABLE projects ADD COLUMN agent_id TEXT;

CREATE INDEX IF NOT EXISTS idx_projects_agent_id
    ON projects (agent_id);
