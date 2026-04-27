---
name: cortex-secrets
description: |
  How to autonomously obtain secrets and API keys from a Cortex Auth server and launch
  projects with those secrets injected as environment variables — without any human
  intervention to configure keys.

  Use this skill whenever you need to:
  - Run a project that requires API keys (OpenAI, Anthropic, SMTP, database passwords, etc.)
  - Start a process that reads secrets from environment variables
  - Authenticate with Cortex to fetch project credentials
  - Use cortex-cli to launch any command with secrets pre-loaded
  - Work on a project that has a .env file listing required keys (even if empty)
  - Deploy or execute code that depends on external services requiring credentials

  Trigger this skill at the start of any task where secrets or API keys are needed,
  before attempting to run any project code.
---

# Cortex Secrets — Autonomous Secret Injection

Cortex Auth is a secrets vault that lets you fetch API keys and credentials at runtime,
so you never need a human to manually configure environment variables. All secrets are
stored encrypted on the server; you authenticate once and receive a **short-lived project
token**, then use that token to launch your process with secrets automatically injected.

## Token lifecycle (important!)

Project tokens are **short-lived** to limit blast radius if a token is leaked
(e.g. captured from a process listing or shell history):

- **TTL: 120 minutes** from issuance (server-enforced).
- **Revocable**: an admin can revoke a token at any time via the dashboard or
  `POST /admin/projects/{name}/revoke`.
- **Daemon-held**: project tokens never appear on the CLI, in shell
  history, in environment variables, or on disk in plaintext. The
  running `cortex-daemon` keeps them in mlock'd memory + a
  mode-0600 cache at `~/.cortex/daemon-projects.json`.
- **Auto-rotated**: when a token has expired or been revoked, the
  daemon calls `/agent/discover` again automatically — no
  `regenerate_token=true` needed.
- **Pending-grant gated**: the *first* discover for a new
  `(agent_id, project_name)` pair waits on admin approval. After
  approval, calls within a 30-day window auto-pass as long as the
  requested env-key set is a subset of the approved keys.

## What you need from the human (one-time setup)

Before you can operate autonomously, a human admin must have:
1. Started the Cortex server and given you its URL (`CORTEX_URL`)
2. Generated an Ed25519 keypair on this machine via
   `cortex-cli gen-key --agent-id <id>` and uploaded the public key with
   `POST /admin/agents`. The private key stays locally at
   `~/.cortex/agent-<id>.key` (mode 0600) and is never sent over the wire.
3. Run `cortex-cli daemon login --url $CORTEX_URL` once and approved the
   user_code on the dashboard. This persists an OAuth 2.0 access token at
   `~/.cortex/daemon-session.json` (mode 0600).
4. Started `cortex-daemon` (background or systemd). The daemon registers
   its binary SHA-256 + ephemeral attestation key with `/daemon/attest`
   and listens on `~/.cortex/agent.sock`.
5. Stored the required secrets in Cortex (e.g., `OPENAI_API_KEY`, `SMTP_PASSWORD`)
6. Approved the **first** `(agent_id, project_name)` pending grant in
   the dashboard's "🔔 Pending Grants" tab — subsequent runs pass through
   for 30 days.

These values — `CORTEX_URL` and `CORTEX_PROJECT` — plus a running daemon
are the only things you need. The CLI never sees the project token.

Store them so future sessions don't need to ask again:
```
~/.cortex-credentials
CORTEX_URL=http://your-server:3000
```

Load them at the start of each session:
```bash
source ~/.cortex-credentials
export CORTEX_PROJECT=my-project
```

## Recommended path: let cortex-cli + cortex-daemon handle the lifecycle

The simplest and safest workflow — the daemon discovers the token on
first use, persists it, and auto-rotates it whenever it expires or is
revoked. The CLI just sends a one-line JSON request to the daemon
socket:

```bash
export CORTEX_URL=http://your-server:3000
export CORTEX_PROJECT=my-project

cortex-cli run -- python app.py
```

If the daemon isn't running, `cortex-cli run` exits with a clear error
pointing to `cortex-daemon`. If first-access approval is pending, the
CLI exits 1 with `pending_approval` and the `grant_id` so the human
admin knows exactly which row to approve.

## Step-by-step: manual flow (for scripts and curl)

### Step 1 — Sign your auth proof (no network call)

The auth proof is an Ed25519 signature you create locally with your private
key. It proves your identity to the Cortex server without storing any session
state.

```bash
PROOF=$(cortex-cli sign-proof \
  --agent-id "$CORTEX_AGENT_ID" \
  --priv-key-file "$CORTEX_PRIV_KEY_FILE")
TS=$(echo "$PROOF" | python3 -c "import sys,json; print(json.load(sys.stdin)['ts'])")
NONCE=$(echo "$PROOF" | python3 -c "import sys,json; print(json.load(sys.stdin)['nonce'])")
AUTH_PROOF=$(echo "$PROOF" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_proof'])")
```

This command runs entirely offline — no server needed.

### Step 2 — Discover the project and get a project token

Call `/agent/discover` with your auth proof and a description of which secrets
you need. The `file_content` field should list the environment variable names
the project requires (values can be empty — only the names matter for matching).

```bash
ENV_CONTENT=$(cat /path/to/project/.env 2>/dev/null || echo "OPENAI_API_KEY=
ANTHROPIC_API_KEY=
SMTP_PASSWORD=
DATABASE_URL=")

RESPONSE=$(curl -s -X POST "$CORTEX_URL/agent/discover" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"$CORTEX_AGENT_ID\",
    \"auth_proof\": \"$AUTH_PROOF\",
    \"ts\": $TS,
    \"nonce\": \"$NONCE\",
    \"context\": {
      \"project_name\": \"my-project\",
      \"file_content\": \"$ENV_CONTENT\"
    }
  }")

PROJECT_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['project_token'])")
EXPIRES_AT=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['token_expires_at'])")
echo "Token valid until $EXPIRES_AT (UTC)"
```

The response now includes:
- `project_token` — save this; it won't be shown again.
- `token_expires_at` — UTC timestamp when this token stops working.
- `token_ttl_seconds` — TTL in seconds (typically 7200 for 120min).

**Save the project token** — it won't be shown again:
```bash
echo "$PROJECT_TOKEN" > ~/.cortex-token-my-project
chmod 600 ~/.cortex-token-my-project
```

**Check if all secrets were found:**
```bash
FULL_MATCHED=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['full_matched'])")
UNMATCHED=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['unmatched_keys'])")

if [ "$FULL_MATCHED" != "True" ]; then
  echo "Warning: some secrets not found in Cortex: $UNMATCHED"
fi
```

### Step 3 — Run your project with secrets injected (via the daemon)

Use `cortex-cli run` to launch any command. It sends one line of JSON to
the running `cortex-daemon`, which performs the discover + secrets fetch
internally and spawns the child with the env vars injected. The CLI
process exits with the child's exit code; secrets never traverse the
socket back to it.

```bash
cortex-cli run \
  --project my-project \
  --url "$CORTEX_URL" \
  -- python app.py
```

Or use environment variables:
```bash
export CORTEX_PROJECT=my-project
export CORTEX_URL=http://your-server:3000

cortex-cli run -- python app.py
```

If `cortex-daemon` is not running you'll get:
```
Cannot connect to daemon socket /home/you/.cortex/agent.sock.
Is cortex-daemon running? Start it with: cortex-daemon
```

If the project requires admin approval you'll get:
```
[cortex-cli] project access pending admin approval
[cortex-cli] grant_id: 2f0b...
[cortex-cli] requested_keys: ["OPENAI_API_KEY"]
```
…and the CLI exits 1.  Ask the admin to approve the grant from the
dashboard's "🔔 Pending Grants" page.

## Token expiry & revocation: how it shows up

When a token has expired or been revoked, the server returns **HTTP 401** with
a JSON body that includes a structured `error_code`:

```json
{ "error": "Project token has expired. ...", "error_code": "token_expired" }
{ "error": "Project token has been revoked ...", "error_code": "token_revoked" }
```

`cortex-cli run` recognizes both codes and:
1. Calls `/agent/discover` (with `regenerate_token=true`) using your agent
   credentials.
2. Writes the new token to `~/.cortex-token-<project>` (mode 0600).
3. Retries the secrets fetch and proceeds with the launch.

If you call the API by hand, just re-run discover — the server auto-rotates
when the existing token is expired or revoked, so you don't need
`regenerate_token=true`:

```bash
PROOF=$(cortex-cli sign-proof --agent-id "$CORTEX_AGENT_ID" --priv-key-file "$CORTEX_PRIV_KEY_FILE")
TS=$(echo "$PROOF" | python3 -c "import sys,json; print(json.load(sys.stdin)['ts'])")
NONCE=$(echo "$PROOF" | python3 -c "import sys,json; print(json.load(sys.stdin)['nonce'])")
AUTH_PROOF=$(echo "$PROOF" | python3 -c "import sys,json; print(json.load(sys.stdin)['auth_proof'])")

RESPONSE=$(curl -s -X POST "$CORTEX_URL/agent/discover" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"$CORTEX_AGENT_ID\",
    \"auth_proof\": \"$AUTH_PROOF\",
    \"ts\": $TS,
    \"nonce\": \"$NONCE\",
    \"context\": {
      \"project_name\": \"my-project\",
      \"file_content\": \"$(cat .env 2>/dev/null)\"
    }
  }")

PROJECT_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['project_token'])")
echo "$PROJECT_TOKEN" > ~/.cortex-token-my-project
```

**Note:** if the existing token is still active and you don't pass
`regenerate_token=true`, the server returns `409 Conflict` to prevent
accidental rotation while another agent might still be using the old token.

## Forcing rotation (e.g. on suspected leak)

Pass `regenerate_token=true` to the discover call, or use the CLI:

```bash
cortex-cli discover --project my-project --regenerate
```

## Admin: revoking a project token

A human admin can immediately invalidate a project token without waiting for
expiration:

```bash
curl -X POST "$CORTEX_URL/admin/projects/my-project/revoke" \
  -H "X-Admin-Token: $ADMIN_TOKEN"
```

Or click "Revoke token" in the dashboard's Projects table.

The next agent call that uses the revoked token will get
`401 {"error_code":"token_revoked"}`. The agent's CLI will then auto-rotate (if
configured) and continue.

## Fetching secrets directly (without running a command)

If you need to read secret values programmatically (e.g., to pass them to a library):

```bash
SECRETS=$(curl -s "$CORTEX_URL/project/secrets/my-project" \
  -H "Authorization: Bearer $PROJECT_TOKEN")

OPENAI_KEY=$(echo "$SECRETS" | python3 -c "import sys,json; print(json.load(sys.stdin)['env_vars']['OPENAI_API_KEY'])")
```

## Getting a rendered config file

If the project uses a config template (e.g., database.yml with `{{db_password}}`):

```bash
CONFIG=$(curl -s "$CORTEX_URL/project/config/my-project/database" \
  -H "Authorization: Bearer $PROJECT_TOKEN")
echo "$CONFIG" > config/database.yml
```

## Full autonomous bootstrap script

For projects you run repeatedly:

```bash
#!/usr/bin/env bash
# cortex-bootstrap.sh — source this before running any project command
set -e

CORTEX_CREDS="${HOME}/.cortex-credentials"
PROJECT_NAME="${1:-my-project}"

[ -f "$CORTEX_CREDS" ] && source "$CORTEX_CREDS"

export CORTEX_PROJECT="$PROJECT_NAME"
# CORTEX_AGENT_ID, CORTEX_PRIV_KEY_FILE, CORTEX_URL come from ~/.cortex-credentials

# Ensure a token exists; cortex-cli run will auto-rotate if it has expired.
if [ ! -f "${HOME}/.cortex-token-${PROJECT_NAME}" ]; then
  cortex-cli discover --project "$PROJECT_NAME" >/dev/null
fi

cortex-cli run -- "${@:2}"
```

Usage: `bash cortex-bootstrap.sh my-project python app.py`

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `cortex-cli: command not found` | CLI not installed or not in PATH | Build with `cargo build --release`; add `target/release` to PATH |
| 401 on discover | Invalid `AGENT_ID` or wrong/missing private key file | Verify the agent is registered and the private key matches the uploaded `agent_pub` |
| 409 on discover | Project token still active | Wait for expiry, or pass `regenerate_token: true` |
| 401 with `error_code: token_expired` | Token older than 120min | Re-run discover (auto-rotates) or use `cortex-cli run` with agent creds |
| 401 with `error_code: token_revoked` | Admin revoked the token | Re-run discover; if it keeps happening, ask admin why |
| `full_matched: false` | Some secrets not in Cortex | Check `unmatched_keys`; ask admin to add missing secrets |
| Server unreachable | Wrong `CORTEX_URL` or server down | Verify URL, check server status |

## Security notes

- `cortex-cli run` uses `exec()` — secrets are never visible in the shell or process list.
- Project tokens expire after 120 minutes; never extend this in production code.
- Never print or log `PROJECT_TOKEN`. Keep the agent private key file
  (`~/.cortex/agent-<id>.key`) at `chmod 600`.
- Token files should be `chmod 600` (the CLI sets this automatically).
- On suspected token leak: revoke via the admin API and re-discover.

For full API reference, see `references/api.md`.
