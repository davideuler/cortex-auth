# Cortex Auth API Reference

## Authentication schemes

| Endpoint group | Auth method |
|----------------|-------------|
| `/admin/*` | `X-Admin-Token: <ADMIN_TOKEN>` header |
| `/agent/discover` | `auth_proof` JWT in request body |
| `/project/*` | `Authorization: Bearer <project_token>` header |

## Project token lifecycle

- **TTL**: 120 minutes from issuance.
- **Revocable**: admins can revoke at any time via `POST /admin/projects/{name}/revoke`.
- **Auto-rotated**: re-calling `/agent/discover` for a project whose token is
  expired or revoked returns a fresh token without `regenerate_token=true`.
- **Status reporting**: `GET /admin/projects` returns `token_status`,
  `token_expires_at`, and `token_revoked_at` per project.

When a project token fails authentication, the server returns **401** with a
JSON body that includes `error_code`:

| `error_code` | Meaning |
|--------------|---------|
| `token_expired` | Token TTL elapsed; re-discover to rotate. |
| `token_revoked` | Admin revoked the token; re-discover to rotate. |
| (absent) | Token is invalid (typo / forged / wrong project). |

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
- `regenerate_token`: set `true` to force a new token even if the existing token
  is still active. Note: when the existing token has already **expired** or been
  **revoked**, the server auto-rotates regardless of this flag.

**Response 200:**
```json
{
  "project_token": "abc123...",
  "token_expires_at": "2026-04-25 12:34:56",
  "token_ttl_seconds": 7200,
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
- `token_expires_at`: UTC timestamp when this token stops working.
- `token_ttl_seconds`: TTL in seconds (currently 7200).
- `full_matched`: `false` means some env vars had no matching secret; see `unmatched_keys`.

**Errors:**
- `401` — unknown `agent_id` or invalid `auth_proof`
- `409` — project already registered with an *active* token; pass `"regenerate_token": true` to rotate

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

**Errors:**
- `401 {"error_code":"token_expired"}` — TTL elapsed, re-discover
- `401 {"error_code":"token_revoked"}` — admin revoked, re-discover
- `401` (no `error_code`) — bad/forged token
- `404` — project not found

---

### GET /project/config/{project_name}/{app_name}

Render a Handlebars config template with secrets substituted in.

**Headers:** `Authorization: Bearer <project_token>`

**Response 200:** Plain-text rendered config file.

Example: template `password = {{smtp_password}}` → `password = hunter2`

**Errors:** Same 401 semantics as `/project/secrets/*`; `404` for missing project or template.

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

### discover

Discover a project and obtain (or rotate) a project token. Saves the token to
`~/.cortex-token-<project>` (mode 0600) and prints it to stdout.

```bash
cortex-cli discover \
  --project <project_name> \
  --url <server_url> \
  --agent-id <AGENT_ID> \
  --jwt-secret <JWT_SECRET> \
  [--env-file ./.env] \
  [--regenerate]
```

`--regenerate` forces rotation even if the existing token is still active.

### run

Fetch secrets from Cortex and exec a command with them injected as env vars.

```bash
cortex-cli run \
  --project <project_name> \
  --url <server_url> \
  [--token <project_token>] \
  [--agent-id <AGENT_ID> --jwt-secret <JWT_SECRET>] \
  [--env-file ./.env] \
  [--token-file ~/.cortex-token-<project>] \
  -- <command> [args...]
```

If `--token` is omitted, the CLI reads it from `--token-file` (default
`~/.cortex-token-<project>`). When the server returns
`token_expired`/`token_revoked`, the CLI auto-rotates using `--agent-id` /
`--jwt-secret` (or `CORTEX_AGENT_ID`/`CORTEX_JWT_SECRET`) and retries.

Environment variable equivalents:
```bash
export CORTEX_PROJECT=my-project
export CORTEX_URL=http://localhost:3000
export CORTEX_TOKEN=<project_token>           # optional, falls back to token file
export CORTEX_AGENT_ID=agent-claude-01        # enables auto-rotation
export CORTEX_JWT_SECRET=<secret>             # enables auto-rotation
cortex-cli run -- <command> [args...]
```

The command is `exec()`'d — secrets are never exposed to the parent shell.

---

## Admin endpoints

These require `X-Admin-Token: <ADMIN_TOKEN>` and are typically run by a human admin.

### GET /admin/projects

Returns each project with its current token lifecycle state:
```json
[
  {
    "id": "uuid",
    "project_name": "my-project",
    "namespace": "default",
    "env_mappings": { "OPENAI_API_KEY": "openai_api_key" },
    "created_at": "2026-04-25 10:00:00",
    "token_expires_at": "2026-04-25 12:00:00",
    "token_revoked_at": null,
    "token_status": "active"
  }
]
```

`token_status` is one of `active`, `expired`, or `revoked`.

### POST /admin/projects/{project_name}/revoke

Immediately revoke the project's current token. The next request that uses the
token will receive `401 {"error_code":"token_revoked"}`. To restore service,
the agent must call `/agent/discover` (which auto-rotates a new token).

```json
{ "revoked": true, "project_name": "my-project" }
```

If the project is already revoked, returns `{"revoked": true, "already_revoked": true}`.
Returns `404` if the project doesn't exist.

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
