# Cortex Auth API Reference

## Authentication schemes

| Endpoint group | Auth method |
|----------------|-------------|
| `/admin/*` | `X-Admin-Token: <ADMIN_TOKEN>` header |
| `/agent/discover` | `auth_proof` JWT in request body |
| `/project/*` | `Authorization: Bearer <project_token>` header |

---

## Agent endpoints

### POST /agent/discover

Authenticate as an agent and register (or refresh) a project, returning a project token.

**Request:**
```json
{
  "agent_id": "agent-claude-01",
  "auth_proof": "<JWT signed with agent's jwt_secret>",
  "context": {
    "project_name": "my-project",
    "file_content": "OPENAI_API_KEY=\nSMTP_PASSWORD=\nDATABASE_URL="
  },
  "regenerate_token": false
}
```

- `file_content`: newline-separated `KEY=value` lines. Values are ignored; only keys are matched against stored secrets.
- `regenerate_token`: set `true` to force a new token (use on 409 or after token loss).

**Response 200:**
```json
{
  "project_token": "abc123...",
  "mapped_keys": {
    "OPENAI_API_KEY": "openai_api_key",
    "SMTP_PASSWORD": "smtp_password"
  },
  "full_matched": true,
  "unmatched_keys": [],
  "namespace": "default"
}
```

- `project_token`: save this — it won't be shown again without regeneration.
- `full_matched`: `false` means some env vars had no matching secret; see `unmatched_keys`.

**Errors:**
- `401` — unknown `agent_id` or invalid `auth_proof`
- `409` — project already registered; add `"regenerate_token": true`

---

## Project endpoints

### GET /project/secrets/{project_name}

Fetch all decrypted secrets for a project as environment variables.

**Headers:** `Authorization: Bearer <project_token>`

**Response 200:**
```json
{
  "env_vars": {
    "OPENAI_API_KEY": "sk-...",
    "SMTP_PASSWORD": "hunter2",
    "DATABASE_URL": "postgres://..."
  }
}
```

**Errors:** `401` invalid token, `404` project not found

---

### GET /project/config/{project_name}/{app_name}

Render a Handlebars config template with secrets substituted in.

**Headers:** `Authorization: Bearer <project_token>`

**Response 200:** Plain-text rendered config file.

Example: template `password = {{smtp_password}}` → `password = hunter2`

**Errors:** `401` invalid token, `404` project or template not found

---

## cortex-cli commands

### gen-token

Generate a JWT auth_proof locally (no server call).

```bash
cortex-cli gen-token \
  --agent-id <AGENT_ID> \
  --jwt-secret <JWT_SECRET>
```

Prints the signed JWT to stdout.

### run

Fetch secrets from Cortex and exec a command with them injected as env vars.

```bash
cortex-cli run \
  --project <project_name> \
  --token <project_token> \
  --url <server_url> \
  -- <command> [args...]
```

Alternatively via environment variables:
```bash
export CORTEX_PROJECT=my-project
export CORTEX_TOKEN=<project_token>
export CORTEX_URL=http://localhost:3000
cortex-cli run -- <command> [args...]
```

The command is `exec()`'d — secrets are never exposed to the parent shell.

---

## Admin endpoints (for reference)

These require `X-Admin-Token: <ADMIN_TOKEN>` and are typically run by a human admin,
not by autonomous agents.

### POST /admin/secrets
Create a secret:
```json
{
  "key_path": "openai_api_key",
  "secret_type": "KEY_VALUE",
  "value": "sk-...",
  "description": "OpenAI API key",
  "namespace": "default"
}
```

### POST /admin/agents
Register an agent:
```json
{
  "agent_id": "agent-claude-01",
  "jwt_secret": "<32-byte hex>",
  "description": "Claude autonomous agent",
  "namespace": "default"
}
```

### POST /admin/policies
Control which secrets an agent can access:
```json
{
  "policy_name": "claude-policy",
  "agent_pattern": "agent-claude-*",
  "allowed_paths": ["openai_api_key", "anthropic_api_key"],
  "denied_paths": []
}
```
