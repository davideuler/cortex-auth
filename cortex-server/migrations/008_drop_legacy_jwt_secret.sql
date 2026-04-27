-- Drop the legacy HMAC `jwt_secret` auth path. Every agent must now
-- authenticate via Ed25519 (`agent_pub`); the HMAC-SHA256 JWT branch in
-- `/agent/discover` is gone.
--
-- SQLite has no `ALTER TABLE DROP COLUMN` that's portable across older
-- engine versions, so we recreate the table. Agents that never registered
-- an Ed25519 public key are dropped — they must re-register via
-- `POST /admin/agents` with `agent_pub`.

CREATE TABLE agents_new (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL UNIQUE,
    agent_pub TEXT NOT NULL,
    description TEXT,
    namespace TEXT NOT NULL DEFAULT 'default',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT INTO agents_new (id, agent_id, agent_pub, description, namespace, created_at)
SELECT id, agent_id, agent_pub, description, namespace, created_at
FROM agents
WHERE agent_pub IS NOT NULL;

DROP TABLE agents;
ALTER TABLE agents_new RENAME TO agents;

CREATE INDEX IF NOT EXISTS idx_agents_agent_id ON agents(agent_id);
