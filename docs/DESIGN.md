# CortexAuth — System Design

## Overview

CortexAuth is a lightweight, Rust-based secrets and configuration management
service for AI agents and automated pipelines. It lets projects securely
store API keys and configuration, lets agents discover which secrets they
need, and injects those secrets into running processes without exposing them
in source code, logs, or files.

The full long-form design lives in [UPDATED_DESIGN.md](../UPDATED_DESIGN.md).
This file is the implementation-tracking summary — what is built today, how
it fits together, and what is intentionally deferred.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        cortex-server (axum)                      │
│                                                                  │
│  ┌─────────────────┐   ┌──────────────────┐   ┌──────────────┐ │
│  │   Admin API     │   │   Agent API      │   │  Project API │ │
│  │   /admin/*      │   │  /agent/discover │   │ /project/*   │ │
│  │   X-Admin-Token │   │  Ed25519 / HS256 │   │ Bearer token │ │
│  └─────────────────┘   └──────────────────┘   └──────────────┘ │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                  Dashboard (HTML / JS)                    │   │
│  │   secrets · agents · policies · namespaces · projects     │   │
│  │   audit · notifications · devices · key-rotation · shamir │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                Device Authorization (RFC 8628)            │   │
│  │   /device/authorize · /device/token · /device · /devices  │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                     JWKS endpoint                         │   │
│  │              /.well-known/jwks.json (Ed25519)             │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Storage (SQLite, envelope-encrypted under the KEK)       │   │
│  │  secrets · agents · policies · projects · namespaces      │   │
│  │  audit_logs · audit_mac_state · kek_metadata              │   │
│  │  notification_channels · server_keys · pending_devices    │   │
│  │  revoked_token_jti                                        │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
         ▲                       ▲                  ▲
         │ admin ops             │ runtime ops      │ daemon ops
    ┌────┴────┐             ┌────┴──────┐    ┌──────┴───────┐
    │ Admin   │             │ cortex-cli│    │ cortex-daemon │
    │         │             │ run / discover  Unix socket    │
    └─────────┘             └───────────┘    └───────────────┘
```

## Components

### 1. cortex-server

Axum HTTP service backed by SQLite via sqlx.

#### Secret Storage
- **Envelope encryption.** Every secret has its own random 256-bit DEK; the
  body is AES-256-GCM-encrypted under the DEK, and the DEK itself is
  AES-256-GCM-encrypted under the in-memory KEK. The DEK is zeroized once
  the row is written.
- The KEK lives only in operator memory and the running process — never on
  disk. On boot the server is SEALED until the operator types the password
  on stdin (or sets `CORTEX_KEK_PASSWORD`); a sentinel ciphertext
  cross-checks that the supplied password matches the prior KEK.
- Secret types: `KEY_VALUE`, `JSON_CONFIG`, `TEMPLATE_CONFIG` (handlebars).
- **Honey tokens.** A boolean flag on `secrets`. A read attempt revokes the
  caller's project token, writes an `alarm` audit row, dispatches outbound
  notifications, and returns a generic 401.

#### Authentication Model
- **Admin operations**: static `X-Admin-Token` header (single-shared-secret
  today; per-user RBAC tracked in UNCERTAINTIES #18).
- **Agent discover**: two paths gated by the agent's stored credential
  shape:
  1. **Ed25519 (#13)** — when the agent row has an `agent_pub` column, the
     `auth_proof` is an Ed25519 signature over
     `ts | nonce | agent_id | /agent/discover`. `ts` must be within ±5
     minutes of the server clock.
  2. **HMAC-SHA256 JWT** — legacy path. The agent's `jwt_secret` is stored
     envelope-encrypted; the server decrypts it and verifies the JWT.
- **Project access**: two formats accepted on `/project/*`:
  1. **Hashed random token** — 32 random bytes hex-encoded; SHA-256 hashed
     at rest. This is the default returned by `/agent/discover`.
  2. **EdDSA JWT (#14)** — minted when the discover request passed
     `signed_token: true`. Signed by the server's Ed25519 keypair (kid in
     the JWT header). Verifiers fetch the public key from
     `/.well-known/jwks.json`. Revocation via the `revoked_token_jti` table.

#### Server Ed25519 Keypair
- Generated on first boot, stored envelope-encrypted in `server_keys`.
- Re-wrapped on KEK rotation.
- `/.well-known/jwks.json` exposes every historical public key by `kid` so
  old signed tokens stay verifiable across rotations.

#### KEK Lifecycle
- **Normal boot**: derive KEK = Argon2id(password, salt) → verify sentinel.
- **Rotation**: `POST /admin/rotate-key` derives a fresh KEK, re-wraps every
  per-row DEK, re-wraps the server Ed25519 keypair, and bumps `kek_version`.
  Body ciphertexts are untouched.
- **Recovery (#15)**: when `CORTEX_RECOVERY_MODE=1`, the operator pastes
  `CORTEX_RECOVERY_THRESHOLD`-many Shamir shares on stdin. The server
  reconstructs the KEK, verifies the sentinel, writes a `recovery_boot`
  alarm to the audit log, and dispatches notifications to every enabled
  channel.
- **Share generation**: `POST /admin/shamir/generate` splits the *running*
  KEK into n shares with threshold m and returns them once. The server
  retains nothing — operators are responsible for distribution.

### 2. Audit Log
- Every state-changing call writes an `audit_logs` row.
- Rows are HMAC-SHA256 chained: each row's `entry_mac` covers
  `prev_hash || canonical_payload`. The running tail MAC sits in
  `audit_mac_state`. Any deletion or reorder breaks the chain.
- The audit MAC key is derived from the KEK (HKDF-style, fixed domain
  separator) — leaking it cannot decrypt secrets.
- Optional caller metadata (`caller_pid`, `caller_binary_sha256`,
  `caller_argv_hash`, `caller_cwd`, `caller_git_commit`, `source_ip`,
  `hostname`, `os`) populated from `X-Cortex-Caller-*` request headers.
- Daily cleanup: rows older than 60 days are deleted.

### 3. Outbound Notifications (#12 / #15)
- `notification_channels` table — channel configs (webhook URLs, bot
  tokens, SMTP recipients) are themselves envelope-encrypted under the KEK.
- Channel types:
  - **Slack** — incoming webhook.
  - **Discord** — incoming webhook.
  - **Telegram** — Bot API.
  - **Email** — pipes the message to `himalaya-cli` on stdin (when on
    PATH); errors out cleanly if not installed.
- Triggers:
  - Honey-token access.
  - Server boot in Shamir recovery mode.
- Dispatch is fire-and-forget: each channel is sent in its own tokio task,
  so a slow webhook cannot block the calling request handler.

### 4. Device Authorization (#16)
- `pending_devices` table tracks (device_code, user_code, status, agent_id,
  expires_at). Status is `pending` → `approved` / `denied` / `expired`.
- `POST /device/authorize` — issues device_code + user_code (10-min TTL).
- `POST /device/token` — daemons poll; returns 401
  `error_code=authorization_pending` until approved, then mints an EdDSA
  JWT access token bound to the assigned agent_id.
- `GET /device` — minimal HTML approval form for humans (until SSO lands).
- `POST /admin/web/device/approve` — admin-token-gated (RBAC tracked).
- `GET /admin/devices` and `DELETE /admin/devices/:agent_id` — admin
  visibility / revocation.

### 5. cortex-cli + cortex-daemon
- **cortex-cli run** — fetches `/project/secrets/<name>` and `exec()`s the
  child with the env vars injected. The CLI process is *replaced* by the
  child, so a parent process cannot scrape the env from the CLI's pid.
- **cortex-cli gen-token** — legacy HS256 auth_proof.
- **cortex-cli gen-key** — generates an Ed25519 keypair locally; private
  key is mode 0600 in `~/.cortex/agent-<id>.key`.
- **cortex-cli sign-proof** — signs an Ed25519 auth_proof with the local
  private key.
- **cortex-cli daemon login / status / logout** — OAuth 2.0 device-grant
  client.
- **cortex-daemon** — long-running socket service at `~/.cortex/agent.sock`
  (mode 0600). Single-line JSON protocol: `{"cmd":"status"}` or
  `{"cmd":"run","program":..,"args":..,"project":..,"token":..,"url":..}`.
  Secrets stay in the child process environment and never cross the socket
  back to the caller.

## Data Flow

### Project Setup (Ed25519 path)
```
Admin → POST /admin/secrets {key_path, value, ...}
Agent → cortex-cli gen-key → uploads agent_pub via POST /admin/agents
Agent → cortex-cli sign-proof → POST /agent/discover {agent_id, ts, nonce,
        auth_proof: <ed25519-sig>, context, signed_token: true}
Server → verifies Ed25519 sig → matches env vars → mints EdDSA JWT
       → returns project_token (legacy random) AND signed_project_token
Agent → cortex-cli run --token $signed_project_token -- ./start.sh
```

### Runtime (cortex-cli, no daemon)
```
cortex-cli run --project P --token T --url U -- ./start.sh
→ GET /project/secrets/P (Bearer T)
   - server detects T format (3 dot-separated parts → JWT verification;
     hex random → SHA-256 hash compare)
   - applies frozen scope, decrypts envelopes, returns env vars
→ injects {KEY: value, ...} into env
→ exec("./start.sh") with the injected environment
```

### Runtime (cortex-daemon)
```
cortex-cli daemon login --url U     # OAuth 2.0 device flow
human → /device → approves user_code (binds it to an agent_id)
cortex-daemon                       # listens on ~/.cortex/agent.sock
peer  → echo '{"cmd":"run", ...}' | nc -U ~/.cortex/agent.sock
       daemon spawns the child with secrets injected; exits with the child's code.
```

### Recovery Boot
```
Operators distribute Shamir shares offline.
CORTEX_RECOVERY_MODE=1 CORTEX_RECOVERY_THRESHOLD=3 cortex-server
→ prompts for 3 shares (rpassword, hidden) → reconstructs KEK
→ verifies sentinel → writes recovery_boot alarm row
→ notifications::dispatch(RecoveryBoot)
→ binds :3000
```

## Database Schema

```sql
secrets              (id, key_path, secret_type, encrypted_value, wrapped_dek,
                      kek_version, description, namespace, is_honey_token,
                      created_at, updated_at)
agents               (id, agent_id, jwt_secret_encrypted, wrapped_dek,
                      kek_version, description, namespace, agent_pub, created_at)
policies             (id, policy_name, agent_pattern, allowed_paths,
                      denied_paths, created_at)
projects             (id, project_name, project_token_hash, env_mappings,
                      namespace, scope, token_expires_at, token_revoked_at,
                      created_at, updated_at)
namespaces           (name, description, created_at)
audit_logs           (id, agent_id, project_name, action, resource_path,
                      status, timestamp, caller_pid, caller_binary_sha256,
                      caller_argv_hash, caller_cwd, caller_git_commit,
                      source_ip, hostname, os, prev_hash, entry_mac)
audit_mac_state      (id, tail_mac, updated_at)
kek_metadata         (id, salt, sentinel_ciphertext, kek_version,
                      created_at, updated_at)
notification_channels(id, channel_type, name, config_ciphertext,
                      config_wrapped_dek, kek_version, enabled, description,
                      created_at, updated_at)
server_keys          (kid, signing_key_ciphertext, signing_key_wrapped_dek,
                      kek_version, active, created_at)
pending_devices      (id, device_code, user_code, status, agent_id,
                      expires_at, created_at, approved_at)
revoked_token_jti    (jti, revoked_at)
```

## Security Properties

- All secrets, agent jwt_secrets, notification channel configs, and the
  server signing key are AES-256-GCM-encrypted under per-row DEKs wrapped
  by the in-memory KEK.
- KEK is derived with Argon2id from the operator password (or reconstructed
  from Shamir shares in recovery mode); never persisted to disk.
- Project tokens: SHA-256 hashed (legacy random) OR EdDSA-signed JWT (new).
  Constant-time comparison via `subtle::ConstantTimeEq`.
- Audit log is HMAC-SHA256-chained — tampering is detectable.
- `cortex-cli` uses `exec()`; the parent process is *replaced*.
- `cortex-daemon` keeps the access token in its own process; peers cannot
  extract raw secrets through the socket — the only way to use them is to
  ask the daemon to spawn a child.
- Outbound notifications use rustls for HTTPS endpoints and pipe email via
  himalaya-cli on stdin (no shell expansion of message content).
- TLS terminated in-process when `TLS_CERT_FILE` + `TLS_KEY_FILE` are set.

## Roadmap

What is **implemented today** (this doc): envelope encryption, KEK rotation,
honey tokens, tamper-evident audit log, scoped project tokens, namespaces,
Ed25519 agent identity, Ed25519-signed project tokens with JWKS, Shamir
m-of-n recovery, OAuth 2.0 device authorization, cortex-daemon scaffolding,
notification dispatch (Slack/Discord/Telegram/email-via-himalaya).

What is **deferred** (see [UNCERTAINTIES.md](UNCERTAINTIES.md) #11, #17,
#18, #19, #21):
- `cortex-cli verify-audit` chain-replay tool.
- Daemon attestation header (#17) — per-process attestation key checked
  against an allowed-binaries whitelist.
- Multi-user RBAC for the admin API (#18).
- External anchoring of the audit chain tail (e.g. periodic Git pin).
- CLI population of `X-Cortex-Caller-*` headers (#21).
