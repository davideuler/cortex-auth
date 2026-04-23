# CortexAuth — System Design

## Overview

CortexAuth is a lightweight, Rust-based secrets and configuration management service designed for AI agents and automated pipelines. It enables projects to securely store API keys and configuration, discover which secrets are available for their dependencies, and inject those secrets into running processes without exposing them in source code or logs.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    CortexAuth Server                     │
│                                                         │
│  ┌─────────────────┐    ┌──────────────────────────┐   │
│  │   Admin API     │    │      Agent/Project API   │   │
│  │ /admin/*        │    │  /agent/discover         │   │
│  │                 │    │  /project/secrets/:proj  │   │
│  │ - Secrets CRUD  │    │  /project/config/:p/:app │   │
│  │ - Agent mgmt    │    └──────────────────────────┘   │
│  │ - Policy mgmt   │                                    │
│  │ - Project list  │                                    │
│  └─────────────────┘                                    │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Storage Layer (SQLite)              │   │
│  │  secrets | agents | policies | projects | logs  │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
         ▲                           ▲
         │ Admin ops                 │ Runtime ops
    ┌────┴────┐                 ┌────┴──────────┐
    │ Admin   │                 │  cortex_cli   │
    │ User    │                 │  (launcher)   │
    └─────────┘                 └───────────────┘
```

## Components

### 1. cortex-server

The core HTTP service built with axum + SQLite.

**Secret Storage**
- AES-256-GCM encryption for all secret values at rest
- Nonces are randomly generated per encryption operation
- Three secret types:
  - `KEY_VALUE`: Simple key-value pairs (API keys, tokens)
  - `JSON_CONFIG`: Structured JSON configuration
  - `TEMPLATE_CONFIG`: Handlebars templates that reference other secrets

**Authentication Model**
- **Admin operations**: Protected by `X-Admin-Token` header (static token from env)
- **Agent discover**: JWT-based — agent sends `agent_id` + `auth_proof` (JWT signed with `jwt_secret`) directly in the request body; no separate session token issued
- **Project access**: Token-based — a `project_token` (SHA-256 hashed at rest) is issued during discovery

**Secret Key Architecture**
- Agent `jwt_secret` is stored AES-256-GCM encrypted (must be recovered to verify agent JWTs)
- Project tokens are 32 random bytes stored as SHA-256 hash (fast verification, sufficient entropy)
- Argon2 is used for password-style inputs (e.g., future user passwords)

### 2. Admin API (`/admin/*`)

All endpoints require `X-Admin-Token` header.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/admin/secrets` | List all secrets (no values) |
| POST | `/admin/secrets` | Create a secret |
| GET | `/admin/secrets/:id` | Get secret with decrypted value |
| PUT | `/admin/secrets/:id` | Update secret value/description |
| DELETE | `/admin/secrets/:id` | Delete secret |
| GET | `/admin/agents` | List agents |
| POST | `/admin/agents` | Register an agent |
| DELETE | `/admin/agents/:agent_id` | Remove agent |
| GET | `/admin/policies` | List policies |
| POST | `/admin/policies` | Create access policy |
| DELETE | `/admin/policies/:id` | Remove policy |
| GET | `/admin/projects` | List registered projects |

### 3. Agent API (`/agent/*`) and Project API (`/project/*`)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/agent/discover` | `agent_id` + `auth_proof` in body | Analyze .env file, register project |
| GET | `/project/secrets/:project` | Bearer project_token | Fetch mapped env vars |
| GET | `/project/config/:project/:app` | Bearer project_token | Render config template |

`/agent/discover` is called by agents at project start time. `/project/*` routes are called by `cortex-cli` at runtime.

### 4. cortex-cli

A thin CLI launcher that:
1. Calls `/project/secrets/:project_name` with the project token
2. Merges returned env vars into the current process environment
3. `exec()`s the target command (replaces itself with the child process)
4. Returns the child's exit code

Secrets are never printed; `exec()` ensures the CLI process is replaced by the child.

## Data Flow

### Project Setup Flow
```
Admin → POST /admin/secrets {openai_api_key, ...}
Agent → POST /agent/discover {agent_id, auth_proof, context: {project_name, file_content: "OPENAI_API_KEY=\n..."}}
Server → verifies agent JWT → matches env vars to secrets → stores project + mappings → returns project_token
Admin stores project_token in CI/CD secrets
```

### Runtime Flow (cortex-cli)
```
cortex-cli --project my-app --token <project_token> --url http://cortex:3000 -- ./start.sh
→ GET /project/secrets/my-app (Bearer project_token)
→ Injects {OPENAI_API_KEY: "sk-...", ...} into env
→ exec("./start.sh") with injected environment
```

## Database Schema

```sql
secrets      (id, key_path, secret_type, encrypted_value, description, created_at, updated_at)
agents       (id, agent_id, jwt_secret_encrypted, description, created_at)
policies     (id, policy_name, agent_pattern, allowed_paths, denied_paths, created_at)
projects     (id, project_name, project_token_hash, env_mappings, created_at, updated_at)
audit_logs   (id, agent_id, project_name, action, resource_path, status, timestamp)
```

## Security Properties

- All secrets encrypted at rest with AES-256-GCM (unique nonce per write)
- Admin token kept out of logs/responses
- Project tokens are one-way hashed (SHA-256); original cannot be recovered — must regenerate if lost
- Agent jwt_secrets stored encrypted (needed for JWT verification)
- Audit log written for every secret retrieval and config render
- `cortex-cli` uses `exec()` — no subprocess where parent can read env
- Server returns only the env vars mapped for the specific project
