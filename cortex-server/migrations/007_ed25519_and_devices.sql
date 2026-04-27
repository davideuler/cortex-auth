-- Ed25519 server keypair (#14), agent public keys (#13), and device
-- authorization (#16).
--
-- Server keypair: generated on first boot, persisted envelope-encrypted under
-- the KEK so a DB-only compromise leaks no signing material. `kid` is the JWS
-- header `kid` clients use to look up the public key in /.well-known/jwks.json.
-- Multiple rows with active=0 retain old public keys so historical signed
-- tokens still verify across rotations.
--
-- agents.agent_pub holds the agent's base64url-encoded Ed25519 public key.
-- When present, /agent/discover prefers Ed25519 verification of `auth_proof`
-- over the legacy HMAC-SHA256 JWT path. Agents may register *both* — that's
-- the migration window.
--
-- pending_devices powers the OAuth 2.0 Device Authorization Grant (RFC 8628):
-- the daemon POSTs /device/authorize, gets back device_code+user_code, then
-- polls /device/token. A human approves user_code through the dashboard.
--
-- revoked_token_jti records the `jti` of every project-token JWT that's been
-- revoked. /project/* checks this set on every request.

CREATE TABLE IF NOT EXISTS server_keys (
    kid TEXT PRIMARY KEY,
    signing_key_ciphertext TEXT NOT NULL,
    signing_key_wrapped_dek TEXT NOT NULL,
    kek_version INTEGER NOT NULL DEFAULT 1,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

ALTER TABLE agents ADD COLUMN agent_pub TEXT;

CREATE TABLE IF NOT EXISTS pending_devices (
    id TEXT PRIMARY KEY,
    device_code TEXT NOT NULL UNIQUE,
    user_code TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied','expired')),
    agent_id TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    approved_at TEXT
);

CREATE TABLE IF NOT EXISTS revoked_token_jti (
    jti TEXT PRIMARY KEY,
    revoked_at TEXT NOT NULL DEFAULT (datetime('now'))
);
