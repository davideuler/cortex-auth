# CortexAuth — Usage Guide

## Quick Start

### 1. Generate Required Keys

```bash
# Generate a 32-byte encryption key (hex)
openssl rand -hex 32
# Example output: a3f1c2d4e5b6a7f8...

# Generate an admin token
openssl rand -hex 16
```

### 2. Configure Environment

Create a `.env` file (never commit this):

```env
DATABASE_URL=sqlite://cortex-auth.db
ENCRYPTION_KEY=<64-hex-chars-from-step-1>
ADMIN_TOKEN=<your-admin-token>
PORT=3000
```

### 3. Start the Server

```bash
# Build
cargo build --release

# Run (reads .env automatically via dotenvy)
./target/release/cortex-server
```

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
```bash
curl -X POST http://localhost:3000/admin/agents \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: my-admin-token" \
  -d '{
    "agent_id": "agent-claude-code-01",
    "jwt_secret": "use-openssl-rand-hex-32-for-this",
    "description": "Claude Code agent on dev machine"
  }'
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

Agents call `/agent/discover` directly, authenticating with `agent_id` and a signed JWT (`auth_proof`).
Generate the `auth_proof` with `cortex-cli gen-token`:

```bash
AUTH_PROOF=$(cortex-cli gen-token \
  --agent-id agent-claude-code-01 \
  --jwt-secret use-openssl-rand-hex-32-for-this)

curl -X POST http://localhost:3000/agent/discover \
  -H "Content-Type: application/json" \
  -d "{
    \"agent_id\": \"agent-claude-code-01\",
    \"auth_proof\": \"$AUTH_PROOF\",
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

### Generate an auth_proof JWT

Before calling `/agent/discover`, generate a signed JWT with your agent credentials:

```bash
AUTH_PROOF=$(cortex-cli gen-token --agent-id my-agent --jwt-secret <jwt_secret>)
```

Then use `$AUTH_PROOF` in your discover request body.

### Launch a process with secrets

```bash
cortex-cli run \
  --project my-app \
  --token <project_token> \
  --url http://localhost:3000 \
  -- python3 main.py
```

### Using Environment Variables (recommended for CI/CD)

```bash
export CORTEX_PROJECT=my-app
export CORTEX_TOKEN=<project_token>
export CORTEX_URL=http://cortex-server:3000

cortex-cli run -- ./start.sh
```

### Help

```bash
cortex-cli --help
cortex-cli run --help
cortex-cli gen-token --help
```

### How It Works

1. `cortex-cli run` fetches secrets from `/project/secrets/<project>`
2. Injects the returned env vars into the process environment
3. `exec()`s the specified command — the CLI process is **replaced** by the child
4. The child process inherits all injected secrets as env vars
5. Secrets are **never printed** to stdout/stderr

### Example: Launch a Python agent with secrets

```bash
# .env.example in your project:
# OPENAI_API_KEY=
# ANTHROPIC_API_KEY=

# After setting up secrets in CortexAuth and running discover:
cortex-cli run \
  --project my-ai-agent \
  --token $PROJECT_TOKEN \
  --url http://cortex:3000 \
  -- python3 -m my_agent.main
```

The child process sees `OPENAI_API_KEY` and `ANTHROPIC_API_KEY` in its environment without them ever appearing in any configuration file or shell history.

---

## Production Deployment

### Environment Variables Summary

| Variable | Required | Description |
|----------|----------|-------------|
| `ENCRYPTION_KEY` | Yes | 64 hex chars (32 bytes) for AES-256-GCM |
| `ADMIN_TOKEN` | Yes | Static token for admin API access |
| `DATABASE_URL` | No | SQLite path (default: `sqlite://cortex-auth.db`) |
| `PORT` | No | HTTP listen port (default: 3000) |

### Security Checklist

- [ ] Rotate `ENCRYPTION_KEY` periodically (requires re-encrypting all secrets)
- [ ] Use a strong random `ADMIN_TOKEN` (at least 32 bytes)
- [ ] Run behind a reverse proxy with TLS (nginx, caddy)
- [ ] Restrict network access to the admin port
- [ ] Back up the SQLite database regularly
- [ ] Store `ENCRYPTION_KEY` and `ADMIN_TOKEN` in a secrets manager (not in .env files on disk)
