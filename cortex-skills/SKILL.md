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
stored encrypted on the server; you authenticate once and receive a project token, then
use that token to launch your process with secrets automatically injected.

## What you need from the human (one-time setup)

Before you can operate autonomously, a human admin must have:
1. Started the Cortex server and given you its URL (`CORTEX_URL`)
2. Registered you as an agent and given you an `AGENT_ID` and `JWT_SECRET`
3. Stored the required secrets in Cortex (e.g., `OPENAI_API_KEY`, `SMTP_PASSWORD`)

These three values — `CORTEX_URL`, `AGENT_ID`, `JWT_SECRET` — are the **only** things
you need from a human. Everything else is autonomous.

Store them in a local credentials file so future sessions don't need to ask again:
```
~/.cortex-credentials
CORTEX_URL=http://your-server:3000
AGENT_ID=agent-claude-01
JWT_SECRET=<hex-secret-from-admin>
```

Load them at the start of each session:
```bash
source ~/.cortex-credentials
# or export individually:
export CORTEX_URL=http://your-server:3000
export AGENT_ID=agent-claude-01
export JWT_SECRET=<secret>
```

## Step-by-step: Get secrets and run your project

### Step 1 — Generate your auth proof (no network call)

The auth proof is a short-lived JWT you create locally using your `JWT_SECRET`.
It proves your identity to the Cortex server without storing any session state.

```bash
AUTH_PROOF=$(cortex-cli gen-token \
  --agent-id "$AGENT_ID" \
  --jwt-secret "$JWT_SECRET")
```

This command runs entirely offline — no server needed.

### Step 2 — Discover the project and get a project token

Call `/agent/discover` with your auth proof and a description of which secrets
you need. The `file_content` field should list the environment variable names
the project requires (values can be empty — only the names matter for matching).

```bash
# If the project has a .env file, read it:
ENV_CONTENT=$(cat /path/to/project/.env)

# Or list required vars manually:
ENV_CONTENT="OPENAI_API_KEY=
ANTHROPIC_API_KEY=
SMTP_PASSWORD=
DATABASE_URL="

RESPONSE=$(curl -s -X POST "$CORTEX_URL/agent/discover" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"auth_proof\": \"$AUTH_PROOF\",
    \"context\": {
      \"project_name\": \"my-project\",
      \"file_content\": \"$ENV_CONTENT\"
    }
  }")

PROJECT_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['project_token'])")
```

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
  # These vars will not be injected — decide whether to proceed or stop
fi
```

### Step 3 — Run your project with secrets injected

Use `cortex-cli run` to launch any command. It fetches the secrets and `exec()`s
your command with them as environment variables — the secrets are never visible
in the process list or parent shell.

```bash
cortex-cli run \
  --project my-project \
  --token "$PROJECT_TOKEN" \
  --url "$CORTEX_URL" \
  -- python app.py

# Or: start a web server
cortex-cli run \
  --project my-project \
  --token "$PROJECT_TOKEN" \
  --url "$CORTEX_URL" \
  -- node server.js

# Or: run a one-off script
cortex-cli run \
  --project my-project \
  --token "$PROJECT_TOKEN" \
  --url "$CORTEX_URL" \
  -- bash send_report.sh
```

You can also set env vars instead of passing flags:
```bash
export CORTEX_PROJECT=my-project
export CORTEX_TOKEN="$PROJECT_TOKEN"
export CORTEX_URL="$CORTEX_URL"

cortex-cli run -- python app.py
```

## Resuming a saved token (subsequent sessions)

If you already have a saved token from a previous session, skip Steps 1–2:

```bash
PROJECT_TOKEN=$(cat ~/.cortex-token-my-project)

cortex-cli run \
  --project my-project \
  --token "$PROJECT_TOKEN" \
  --url "$CORTEX_URL" \
  -- python app.py
```

## Handling token expiry or conflicts (regeneration)

If the server returns 401 on `/project/secrets/*`, or `/agent/discover` returns 409
(project already registered), regenerate the token:

```bash
AUTH_PROOF=$(cortex-cli gen-token --agent-id "$AGENT_ID" --jwt-secret "$JWT_SECRET")

RESPONSE=$(curl -s -X POST "$CORTEX_URL/agent/discover" \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"$AGENT_ID\",
    \"auth_proof\": \"$AUTH_PROOF\",
    \"context\": {
      \"project_name\": \"my-project\",
      \"file_content\": \"$ENV_CONTENT\"
    },
    \"regenerate_token\": true
  }")

PROJECT_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['project_token'])")
echo "$PROJECT_TOKEN" > ~/.cortex-token-my-project
```

## Fetching secrets directly (without running a command)

If you need to read secret values programmatically (e.g., to pass them to a library):

```bash
SECRETS=$(curl -s "$CORTEX_URL/project/secrets/my-project" \
  -H "Authorization: Bearer $PROJECT_TOKEN")

# Extract a specific value:
OPENAI_KEY=$(echo "$SECRETS" | python3 -c "import sys,json; print(json.load(sys.stdin)['env_vars']['OPENAI_API_KEY'])")
```

## Getting a rendered config file

If the project uses a config template (e.g., database.yml with `{{db_password}}`):

```bash
CONFIG=$(curl -s "$CORTEX_URL/project/config/my-project/database" \
  -H "Authorization: Bearer $PROJECT_TOKEN")
# CONFIG now contains the rendered file with all secrets substituted
echo "$CONFIG" > config/database.yml
```

## Full autonomous bootstrap script

For projects you run repeatedly, save this as a bootstrap script:

```bash
#!/usr/bin/env bash
# cortex-bootstrap.sh — source this before running any project command
set -e

CORTEX_CREDS="${HOME}/.cortex-credentials"
PROJECT_NAME="${1:-my-project}"
TOKEN_FILE="${HOME}/.cortex-token-${PROJECT_NAME}"

# Load credentials
[ -f "$CORTEX_CREDS" ] && source "$CORTEX_CREDS"

# Use saved token if available, otherwise discover
if [ -f "$TOKEN_FILE" ]; then
  PROJECT_TOKEN=$(cat "$TOKEN_FILE")
else
  AUTH_PROOF=$(cortex-cli gen-token --agent-id "$AGENT_ID" --jwt-secret "$JWT_SECRET")
  RESPONSE=$(curl -s -X POST "$CORTEX_URL/agent/discover" \
    -H "Content-Type: application/json" \
    -d "{\"agent_id\":\"$AGENT_ID\",\"auth_proof\":\"$AUTH_PROOF\",\"context\":{\"project_name\":\"$PROJECT_NAME\",\"file_content\":\"$(cat .env 2>/dev/null || echo '')\"}, \"regenerate_token\": false}")
  PROJECT_TOKEN=$(echo "$RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('project_token',''))" 2>/dev/null)
  [ -z "$PROJECT_TOKEN" ] && { echo "Failed to get token: $RESPONSE"; exit 1; }
  echo "$PROJECT_TOKEN" > "$TOKEN_FILE"
  chmod 600 "$TOKEN_FILE"
fi

# Launch with secrets injected
cortex-cli run --project "$PROJECT_NAME" --token "$PROJECT_TOKEN" --url "$CORTEX_URL" -- "${@:2}"
```

Usage: `bash cortex-bootstrap.sh my-project python app.py`

## Troubleshooting

| Problem | Cause | Fix |
|---------|-------|-----|
| `cortex-cli: command not found` | CLI not installed or not in PATH | Build with `cargo build --release` in the cortex-auth repo; add target/release to PATH |
| 401 on discover | Invalid AGENT_ID or JWT_SECRET | Verify credentials with admin |
| 409 on discover | Project token already exists | Add `"regenerate_token": true` to the request |
| 401 on secrets fetch | Token expired or invalid | Re-run discover with `regenerate_token: true` |
| `full_matched: false` | Some secrets not in Cortex | Check `unmatched_keys`; ask admin to add missing secrets |
| Server unreachable | Wrong CORTEX_URL or server down | Verify URL, check server status |

## Security notes

- `cortex-cli run` uses `exec()` — secrets are never visible in the shell or process list
- Never print or log `PROJECT_TOKEN` or `JWT_SECRET`
- Token files should be `chmod 600`
- Re-generate tokens on compromise via `regenerate_token: true`

For full API reference, see `references/api.md`.
