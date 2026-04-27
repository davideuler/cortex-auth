-- Security hardening: honey tokens, scoped project tokens, audit log MAC chain
-- and richer caller metadata.
--
-- 1. honey-token flag on secrets — accessing a honey-token signals an attack;
--    the server alerts and revokes the calling project's token.
-- 2. scope on projects — a project token now carries an explicit list of
--    secret key_paths it is allowed to read. The mapping discovered at
--    /agent/discover is recorded as the scope and enforced on every
--    /project/secrets call.
-- 3. audit_logs gains tamper-evident chained MAC + caller metadata
--    (caller_pid, caller_binary_sha256, caller_argv_hash, caller_cwd,
--    caller_git_commit, source_ip, hostname, os). audit_mac_state holds the
--    running tail MAC so that any deletion or reorder is detectable.

ALTER TABLE secrets ADD COLUMN is_honey_token INTEGER NOT NULL DEFAULT 0;

ALTER TABLE projects ADD COLUMN scope TEXT NOT NULL DEFAULT '[]';

ALTER TABLE audit_logs ADD COLUMN caller_pid INTEGER;
ALTER TABLE audit_logs ADD COLUMN caller_binary_sha256 TEXT;
ALTER TABLE audit_logs ADD COLUMN caller_argv_hash TEXT;
ALTER TABLE audit_logs ADD COLUMN caller_cwd TEXT;
ALTER TABLE audit_logs ADD COLUMN caller_git_commit TEXT;
ALTER TABLE audit_logs ADD COLUMN source_ip TEXT;
ALTER TABLE audit_logs ADD COLUMN hostname TEXT;
ALTER TABLE audit_logs ADD COLUMN os TEXT;
ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT;
ALTER TABLE audit_logs ADD COLUMN entry_mac TEXT;

CREATE TABLE IF NOT EXISTS audit_mac_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    tail_mac TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO audit_mac_state (id, tail_mac) VALUES (1, '');
