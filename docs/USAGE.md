# CortexAuth — Usage Guide

## Quick Start

### 1. Generate the Admin Token

```bash
openssl rand -hex 16
```

The encryption key (KEK) is **not** an environment variable any more — it is derived
from a passphrase you type at server startup.

### 2. Configure Environment

Create a `.env` file (never commit this):

```env
DATABASE_URL=sqlite://cortex-auth.db
ADMIN_TOKEN=<your-admin-token>
PORT=3000
```

### 3. Start the Server

```bash
# Build
cargo build --release

# Run (reads .env automatically via dotenvy). The server boots SEALED and
# prompts for the KEK operator password on stdin; once verified against the
# on-disk sentinel it transitions to UNSEALED and binds :3000.
./target/release/cortex-server
# [cortex-server SEALED] Enter KEK operator password: ********
```

For headless / supervised deployments, supply the password through `CORTEX_KEK_PASSWORD`
instead of stdin (e.g. read it from a secrets manager into the unit's environment).

---

## Admin API Examples

All admin endpoints require the header: `X-Admin-Token: <your-admin-token>`

### Secret Management

#### Create a KEY_VALUE secret
```bash
curl -X POST http://localhost:3000/admin/secrets \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: my-admin-token" \
  -d '{
    "key_path": "openai_api_key",
    "secret_type": "KEY_VALUE",
    "value": "sk-your-openai-key-here",
    "description": "OpenAI API Key"
  }'
# Response: {"id": "uuid", "key_path": "openai_api_key"}
```

#### Create a JSON_CONFIG secret
```bash
curl -X POST http://localhost:3000/admin/secrets \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: my-admin-token" \
  -d '{
    "key_path": "claude_config",
    "secret_type": "JSON_CONFIG",
    "value": "{\"api_key\": \"sk-ant-...\", \"model\": \"claude-opus-4-7\", \"max_tokens\": 8192}"
  }'
```

#### Create a TEMPLATE_CONFIG secret
```bash
curl -X POST http://localhost:3000/admin/secrets \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: my-admin-token" \
  -d '{
    "key_path": "himalaya",
    "secret_type": "TEMPLATE_CONFIG",
    "value": "[smtp]\nserver = smtp.example.com\nport = 587\npassword = {{smtp_password}}\n\n[imap]\nserver = imap.example.com\npassword = {{smtp_password}}"
  }'
```

#### List all secrets (no decrypted values)
```bash
curl http://localhost:3000/admin/secrets \
  -H "X-Admin-Token: my-admin-token"
```

#### Get secret with decrypted value
```bash
curl http://localhost:3000/admin/secrets/<id> \
  -H "X-Admin-Token: my-admin-token"
```

#### Update a secret
```bash
curl -X PUT http://localhost:3000/admin/secrets/<id> \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: my-admin-token" \
  -d '{"value": "new-secret-value"}'
```

#### Delete a secret
```bash
curl -X DELETE http://localhost:3000/admin/secrets/<id> \
  -H "X-Admin-Token: my-admin-token"
```

---

### Agent Management

#### Register an agent
First, generate an Ed25519 keypair on the agent's machine and upload only
the public key — the private key never leaves the agent.

```bash
# Run on the agent's machine. Writes ~/.cortex/agent-<id>.key (mode 0600)
# and prints the base64url public key on stdout.
PUB=$(cortex-cli gen-key --agent-id agent-claude-code-01)

curl -X POST http://localhost:3000/admin/agents \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: my-admin-token" \
  -d "{
    \"agent_id\": \"agent-claude-code-01\",
    \"agent_pub\": \"$PUB\",
    \"description\": \"Claude Code agent on dev machine\"
  }"
```

#### List agents
```bash
curl http://localhost:3000/admin/agents \
  -H "X-Admin-Token: my-admin-token"
```

#### Delete an agent
```bash
curl -X DELETE http://localhost:3000/admin/agents/agent-claude-code-01 \
  -H "X-Admin-Token: my-admin-token"
```

---

### Policy Management

#### Create an access policy
```bash
curl -X POST http://localhost:3000/admin/policies \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: my-admin-token" \
  -d '{
    "policy_name": "developer-agent-policy",
    "agent_pattern": "agent-claude-*",
    "allowed_paths": ["openai_api_key", "dashscope_api_key", "himalaya"],
    "denied_paths": ["production_db_password"]
  }'
```

---

## Agent API Examples

### Project Discovery

Agents call `/agent/discover` directly, authenticating with `agent_id` and an
Ed25519 `auth_proof`. Sign the proof with `cortex-cli sign-proof`:

```bash
PROOF=$(cortex-cli sign-proof \
  --agent-id agent-claude-code-01 \
  --priv-key-file ~/.cortex/agent-agent-claude-code-01.key)
TS=$(echo $PROOF | jq -r .ts)
NONCE=$(echo $PROOF | jq -r .nonce)
SIG=$(echo $PROOF | jq -r .auth_proof)

curl -X POST http://localhost:3000/agent/discover \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"agent-claude-code-01\",
    \"auth_proof\": \"$SIG\",
    \"ts\": $TS,
    \"nonce\": \"$NONCE\",
    \"context\": {
      \"project_name\": \"movie-translator\",
      \"file_content\": \"OPENAI_API_KEY=\nDASHSCOPE_API_KEY=\"
    }
  }"
# Response:
# {
#   "mapped_keys": {"OPENAI_API_KEY": "openai_api_key", "DASHSCOPE_API_KEY": "dashscope_api_key"},
#   "full_matched": true,
#   "project_token": "a1b2c3d4...",
#   "unmatched_keys": []
# }
```

**Save the `project_token`** — it cannot be recovered (only its hash is stored). Pass `"regenerate_token": true` to get a new token.

### Fetch Secrets

```bash
curl http://localhost:3000/project/secrets/movie-translator \
  -H "Authorization: Bearer <project_token>"
# Response: {"env_vars": {"OPENAI_API_KEY": "sk-...", "DASHSCOPE_API_KEY": "dsk-..."}}
```

### Render Config Template

```bash
curl http://localhost:3000/project/config/mail-project/himalaya \
  -H "Authorization: Bearer <project_token>"
# Response: rendered plain-text config file with secrets substituted
```

---

## cortex-cli Usage

### Installation

```bash
cargo build --release
cp target/release/cortex-cli /usr/local/bin/
```

### Sign an auth_proof

Before calling `/agent/discover`, sign an Ed25519 `auth_proof` with the
private key generated by `cortex-cli gen-key`:

```bash
PROOF=$(cortex-cli sign-proof \
  --agent-id my-agent \
  --priv-key-file ~/.cortex/agent-my-agent.key)
# stdout: {"ts":1714248000,"nonce":"...","auth_proof":"<base64url-sig>"}
```

Splice `ts`, `nonce`, and `auth_proof` from `$PROOF` into your discover
request body.

### Launch a process with secrets

`cortex-cli run` no longer accepts `--token`, `--agent-id`, or
`--priv-key-file`. The running `cortex-daemon` (started once after
`cortex-cli daemon login`) holds the project token, auto-rotates it on
expiry, and injects secrets into the child process. The CLI never sees
either the token or the secret values.

```bash
# One-time: register the daemon (OAuth 2.0 device-grant).
cortex-cli daemon login --url http://localhost:3000
# Visit the printed URL on the dashboard to approve the user_code.

# Start the daemon (idempotent; one per user account).
nohup cortex-daemon >/var/log/cortex-daemon.log 2>&1 &

# Launch any process with secrets injected.
cortex-cli run \
  --project my-app \
  --url http://localhost:3000 \
  -- python3 main.py
```

### Using Environment Variables (recommended for CI/CD)

```bash
export CORTEX_PROJECT=my-app
export CORTEX_URL=http://cortex-server:3000

cortex-cli run -- ./start.sh
```

### Help

```bash
cortex-cli --help
cortex-cli run --help
cortex-cli sign-proof --help
```

### How It Works

1. `cortex-cli run` connects to the daemon Unix socket
   (`~/.cortex/agent.sock`).
2. The daemon checks its in-memory + on-disk
   (`~/.cortex/daemon-projects.json`, mode 0600) project-token cache. On
   miss or expiry it calls `/agent/discover` itself, signs the request
   with the agent's Ed25519 private key, and updates the cache.
3. The daemon fetches secrets from `/project/secrets/<project>`,
   forwards an `X-Daemon-Attestation` header signed by an
   ephemeral-per-process Ed25519 key, and spawns the child program with
   the env vars injected.
4. The CLI receives only `{"ok":true,"exit_code":N}` — secret values
   never traverse the socket.
5. If the project requires first-access admin approval, the CLI exits 1
   with a `pending_approval` message including the `grant_id`; approve
   it on the dashboard and re-run.

### Example: Launch a Python agent with secrets

```bash
# .env.example in your project:
# OPENAI_API_KEY=
# ANTHROPIC_API_KEY=

# After setting up secrets in CortexAuth and approving the agent's
# pending grant on the dashboard:
cortex-cli run \
  --project my-ai-agent \
  --url http://cortex:3000 \
  -- python3 -m my_agent.main
```

The child process sees `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` in its
environment without them ever appearing in any configuration file, shell
history, or socket payload.

---

## Ed25519 Agent Identity (#13)

Generate a fresh keypair locally:

```bash
cortex-cli gen-key --agent-id my-agent
# stdout: <base64url public key>
# private key persisted at ~/.cortex/agent-my-agent.key (mode 0600)
```

Register the agent with that public key:

```bash
curl -X POST http://localhost:3000/admin/agents \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"agent_id":"my-agent","agent_pub":"<base64url-pubkey>"}'
```

Sign an `auth_proof` and call `/agent/discover`:

```bash
PROOF=$(cortex-cli sign-proof --agent-id my-agent --priv-key-file ~/.cortex/agent-my-agent.key)
TS=$(echo $PROOF | jq -r .ts)
NONCE=$(echo $PROOF | jq -r .nonce)
SIG=$(echo $PROOF | jq -r .auth_proof)

curl -X POST http://localhost:3000/agent/discover \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"my-agent\",
    \"auth_proof\": \"$SIG\",
    \"ts\": $TS,
    \"nonce\": \"$NONCE\",
    \"context\": {\"project_name\":\"my-app\",\"file_content\":\"OPENAI_API_KEY=\"},
    \"signed_token\": true
  }"
```

The response carries both the random `project_token` and the EdDSA JWT
`signed_project_token`. Pass either to `cortex-cli run --token …`.

---

## Ed25519-Signed Project Tokens (#14)

Pass `signed_token: true` to `/agent/discover` to receive an EdDSA JWT in
`signed_project_token`. The token claims are:

```json
{
  "iss": "cortex-auth", "sub": "<project_name>", "aud": "cortex-cli",
  "iat": 1714248000, "exp": 1715457600,
  "jti": "<uuid>", "scope": ["openai_api_key"],
  "namespace": "default", "project_id": "<project_name>"
}
```

Verifiers fetch the server public key from:

```bash
curl http://localhost:3000/.well-known/jwks.json
# { "keys": [ { "kty":"OKP", "crv":"Ed25519", "kid":"...", "x":"...", "alg":"EdDSA" } ] }
```

The `kid` header on the JWT identifies which JWKS entry to verify against —
old tokens stay verifiable across server keypair rotations.

---

## Notification Channels (#12 / #15)

Honey-token alarms and Shamir recovery boots fan out to every enabled
notification channel.

### Slack / Discord (incoming webhook)

```bash
curl -X POST http://localhost:3000/admin/notification-channels \
  -H "Content-Type: application/json" -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{
    "name": "on-call-slack",
    "channel_type": "slack",
    "config": {"webhook_url": "https://hooks.slack.com/services/T/B/..."}
  }'
```

(Discord is the same with `"channel_type": "discord"` and a Discord webhook
URL.)

### Telegram (Bot API)

```bash
curl -X POST http://localhost:3000/admin/notification-channels \
  -H "Content-Type: application/json" -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{
    "name": "ops-telegram",
    "channel_type": "telegram",
    "config": {"bot_token": "123456:ABC-DEF...", "chat_id": "-1001234567890"}
  }'
```

### Email via himalaya-cli

`himalaya-cli` must be installed and configured on the cortex-server host
(see https://pimalaya.org/himalaya/). The server pipes the message to
`himalaya message send` on stdin.

```bash
curl -X POST http://localhost:3000/admin/notification-channels \
  -H "Content-Type: application/json" -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{
    "name": "oncall-email",
    "channel_type": "email",
    "config": {"to": "oncall@example.com", "account": "default"}
  }'
```

### Test

```bash
curl -X POST http://localhost:3000/admin/notification-channels/<id>/test \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

### Disable / delete

```bash
curl -X PUT http://localhost:3000/admin/notification-channels/<id> \
  -H "Content-Type: application/json" -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"enabled": false}'

curl -X DELETE http://localhost:3000/admin/notification-channels/<id> \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

---

## Shamir m-of-n Unseal Recovery (#15)

### Generate shares (one-shot, server keeps no copy)

From the dashboard's `Shamir Recovery` tab, or directly:

```bash
curl -X POST http://localhost:3000/admin/shamir/generate \
  -H "Content-Type: application/json" -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"threshold": 3, "shares": 5}'
# {
#   "threshold": 3, "shares_count": 5,
#   "shares": ["BASE64...", "BASE64...", ...],
#   "warning": "Distribute these shares to operators NOW and DO NOT store them."
# }
```

Distribute each share to a different operator. The server retains nothing.

### Recovery boot

When the operator password is unrecoverable:

```bash
CORTEX_RECOVERY_MODE=1 \
CORTEX_RECOVERY_THRESHOLD=3 \
ADMIN_TOKEN=$ADMIN_TOKEN \
cortex-server
# [cortex-server SEALED (RECOVERY MODE)] — awaiting Shamir shares on stdin
#   share 1 of 3: ********
#   share 2 of 3: ********
#   share 3 of 3: ********
# [cortex-server UNSEALED (kek_version=N, recovery_mode=true)]
```

Recovery boot writes an `alarm`-status row to `audit_logs`
(`action="recovery_boot"`) and dispatches notifications to every enabled
channel.

---

## cortex-daemon + Device Authorization (#16)

```bash
# 1. Trigger the OAuth 2.0 device-authorization grant on the agent host.
cortex-cli daemon login --url http://localhost:3000
# [cortex-cli] visit http://localhost:3000/device and approve user_code: ABCD-1234
# [cortex-cli] polling…

# 2. Approve from the dashboard's Devices tab (or directly):
curl -X POST http://localhost:3000/admin/web/device/approve \
  -H "Content-Type: application/json" -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"user_code":"ABCD-1234","agent_id":"my-agent"}'

# 3. Start the daemon (Unix socket at ~/.cortex/agent.sock, mode 0600).
#    The daemon registers an ephemeral attestation key with the server,
#    enforces SO_PEERCRED on every connection, and prevents ptrace via
#    PR_SET_DUMPABLE=0 + mlockall.
cortex-daemon &

# 4. Inspect the daemon (cached session + active attestation session_id).
cortex-cli daemon status
# daemon session @ http://localhost:3000 (expires_in=2592000s)

# 5. Forget the cached login session.
cortex-cli daemon logout
```

Direct socket protocol (one-line JSON request, one-line JSON response):

```bash
echo '{"cmd":"status"}' | nc -U ~/.cortex/agent.sock

# `run` no longer takes a token — the daemon discovers and rotates it.
echo '{"cmd":"run","program":"python","args":["main.py"],
       "project":"my-app","url":"http://localhost:3000"}' \
  | nc -U ~/.cortex/agent.sock
```

The daemon spawns the child with the secrets injected as env vars and
returns `{"ok":true,"exit_code":N}` once it exits — the raw secret values
never travel back over the socket. When the project requires admin
approval, the daemon returns
`{"ok":false,"error_code":"pending_approval","grant_id":"...","requested_keys":[...]}`
instead, so the CLI can print an actionable message.

### systemd unit (recommended)

```ini
[Unit]
Description=CortexAuth agent daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=cortex-agent
ExecStart=/usr/local/bin/cortex-daemon
Restart=on-failure
RestartSec=5

# Hardening
NoNewPrivileges=yes
MemoryDenyWriteExecute=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LockPersonality=yes
PrivateTmp=yes
CapabilityBoundingSet=CAP_IPC_LOCK
AmbientCapabilities=CAP_IPC_LOCK

[Install]
WantedBy=default.target
```

`CAP_IPC_LOCK` is needed for `mlockall(2)` to lock secret-bearing pages.

---

## First-Access Approval (`pending_grants`, #16)

A new `(agent_id, project_name)` pair triggers an admin gate before any
secret leaves the server. The first `/agent/discover` returns
HTTP 403 with body:

```json
{
  "error_code": "pending_approval",
  "details": {
    "grant_id": "<uuid>",
    "requested_keys": ["OPENAI_API_KEY", "DASHSCOPE_API_KEY"],
    "agent_id": "my-agent",
    "project_name": "my-app"
  }
}
```

A row is inserted into `pending_grants` and a notification is dispatched
to every enabled channel. The dashboard's "🔔 Pending Grants" tab lists
all open requests; admins approve/deny with:

```bash
# List
curl -H "X-Admin-Token: $ADMIN_TOKEN" \
  http://localhost:3000/admin/pending-grants

# Approve all requested keys
curl -X POST -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" -d '{}' \
  http://localhost:3000/admin/pending-grants/<grant_id>/approve

# Approve a subset
curl -X POST -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"approved_keys":["OPENAI_API_KEY"]}' \
  http://localhost:3000/admin/pending-grants/<grant_id>/approve

# Deny
curl -X POST -H "X-Admin-Token: $ADMIN_TOKEN" \
  http://localhost:3000/admin/pending-grants/<grant_id>/deny
```

After approval, subsequent `/agent/discover` calls within a 30-day
auto-approval window pass through transparently as long as the
requested env-key set is a subset of the approved keys. A wider scope
re-opens the approval workflow.

---

## Daemon Attestation Allowlist (#17)

Every running daemon registers itself at startup with `POST
/daemon/attest`, sending its binary SHA-256, ephemeral attestation
public key, version, PID, UID, and hostname. The server stores this in
`daemon_sessions` and pins all subsequent sensitive requests to the
ephemeral private key via the `X-Daemon-Attestation` header.

To enforce a release allowlist:

```bash
# Compute the daemon SHA-256 you want to allow.
sha256sum /usr/local/bin/cortex-daemon
# 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  cortex-daemon

# Add it to the allowlist (admin-only).
curl -X POST -H "X-Admin-Token: $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"binary_sha256":"9f86d081...","version":"0.1.0","description":"prod build"}' \
  http://localhost:3000/admin/allowed-daemon-versions

# List active daemon sessions and the allowlist via the dashboard's
# "🛡️ Daemon Allowlist" page or:
curl -H "X-Admin-Token: $ADMIN_TOKEN" \
  http://localhost:3000/admin/daemon-sessions
curl -H "X-Admin-Token: $ADMIN_TOKEN" \
  http://localhost:3000/admin/allowed-daemon-versions
```

When `allowed_daemon_versions` is **empty** the allowlist is **not
enforced** (existing deployments do not break on upgrade). Add the
first row to opt into enforcement; from then on, any daemon whose
binary hash is missing — or marked `enabled=0` — fails attestation
with HTTP 403 and `error_code: binary_not_allowed`.

---

## Production Deployment

### Environment Variables Summary

| Variable | Required | Description |
|----------|----------|-------------|
| `CORTEX_KEK_PASSWORD` | No (interactive) | KEK operator password. If unset, the server prompts on stdin. |
| `CORTEX_RECOVERY_MODE` | No | Set to `1` to boot via Shamir share recovery instead of the password. |
| `CORTEX_RECOVERY_THRESHOLD` | Required when `CORTEX_RECOVERY_MODE=1` | Number of shares to prompt for on stdin. |
| `ADMIN_TOKEN` | Yes | Static token for admin API access |
| `DATABASE_URL` | No | SQLite path (default: `sqlite://cortex-auth.db`) |
| `PORT` | No | HTTP listen port (default: 3000) |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | No | Enable in-process rustls TLS. |
| `CORTEX_DAEMON_SOCK` | No (cortex-daemon) | Override the default `~/.cortex/agent.sock` path. |

### Security Checklist

- [ ] Rotate the KEK periodically via `POST /admin/rotate-key` and restart with the new password
- [ ] Generate Shamir shares once and distribute to operators (`POST /admin/shamir/generate`) so a lost password is recoverable
- [ ] Configure at least one notification channel so honey-token alarms and recovery boots actually page someone
- [ ] Register every agent with an Ed25519 `agent_pub` (#13) — HMAC `jwt_secret` has been removed
- [ ] Use a strong random `ADMIN_TOKEN` (at least 32 bytes)
- [ ] Run behind a reverse proxy with TLS — or set `TLS_CERT_FILE` + `TLS_KEY_FILE` for in-process termination
- [ ] Restrict network access to the admin port
- [ ] Back up the SQLite database regularly
- [ ] Pull `CORTEX_KEK_PASSWORD` and `ADMIN_TOKEN` from a secrets manager (not from `.env` on disk)
- [ ] Set `chmod 600` on `~/.cortex/agent.sock` and `~/.cortex/agent-*.key` files (cortex-cli already does this)
