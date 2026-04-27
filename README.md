# CortexAuth — Agent-Centric Secrets & Configuration Service

[中文文档](README.zh-CN.md)

A lightweight, Rust-based secrets vault designed for AI agents and automated pipelines. Store API keys and configuration securely, discover which secrets your project needs, and inject them at runtime — without ever hardcoding secrets in source code.

## Architecture

```
                      ┌──────────────────────────────────────┐
                      │           cortex-server              │
         admin API    │  · KEK in mlock'd memory (operator)  │
  Admin ─────────────►│  · per-row DEKs wrapped by KEK       │
  (curl / API)        │  · authenticates agents  (JWT)       │
                      │  · issues project tokens             │
                      └───────────────┬──────────────────────┘
                                      │  ② project_token
                                      │  ③ env vars
                                      │
  ┌───────────────────────────────────┼────────────────────────┐
  │                Agent              │                        │
  │         (autonomous pipeline)     │                        │
  │                                   ▼                        │
  │  ① cortex-cli gen-token  ┌─────────────────┐              │
  │  ──────────────────────► │   cortex-cli    │              │
  │                          │                 │              │
  │  ④ cortex-cli run        │  gen-token      │              │
  │  ──────────────────────► │  run → exec()   │              │
  └──────────────────────────┴────────┬────────┘──────────────┘
                                      │
                                 exec() with env vars injected
                                      │
                                      ▼
                            ┌─────────────────────┐
                            │   Project Process   │
                            │  python main.py     │
                            │  node app.js  …     │
                            │                     │
                            │  OPENAI_API_KEY=...  │
                            │  DB_PASSWORD=...    │
                            │  AUTH_TOKEN=...     │
                            └─────────────────────┘
```

**Flow:**
1. **Admin** pre-loads project secrets into `cortex-server` via the admin API
2. **Agent** calls `cortex-cli gen-token` to sign a JWT (`auth_proof`) proving its identity
3. **Agent** posts `auth_proof` to `/agent/discover` → receives a `project_token`
4. **Agent** calls `cortex-cli run --project <name> --token <project_token>` which fetches secrets from the server and `exec()`s the target process with them injected as environment variables

## Agent Key Management Principles

- **Agents never touch secret values** — secrets flow directly from `cortex-server` into the process environment via `exec()`; agent code never reads or stores them
- **No human intervention per task** — agents autonomously obtain and inject secrets across any number of projects and tasks without requiring manual input for each run
- **Fully autonomous secret injection** — unattended agent pipelines retrieve all required credentials on demand at runtime; no operator in the loop
- **Secrets never written to disk** — API keys, database credentials, tokens, and passwords exist only in process memory as environment variables; nothing is persisted to files

## Installation

### Homebrew (macOS Apple Silicon)

```bash
brew tap davideuler/cortex-auth
brew install cortex-auth
```

> **Note:** The Homebrew tap provides pre-built binaries for **Apple Silicon (M1/M2/M3) only**.
> macOS Intel users should [build from source](#build-from-source).

### Pre-built binaries (Linux / macOS Apple Silicon)

Download from the [GitHub Releases](https://github.com/davideuler/cortex-auth/releases) page.

```bash
VERSION=v0.1.2

# Detect platform
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  TARGET=aarch64-apple-darwin ;;
  Linux-x86_64)  TARGET=x86_64-unknown-linux-musl ;;
  Linux-aarch64) TARGET=aarch64-unknown-linux-musl ;;
  *) echo "No pre-built binary for this platform — see Build from source below"; exit 1 ;;
esac

ARCHIVE="cortex-auth-${VERSION}-${TARGET}"
curl -fLO "https://github.com/davideuler/cortex-auth/releases/download/${VERSION}/${ARCHIVE}.tar.gz"
tar xzf "${ARCHIVE}.tar.gz"
sudo mv "${ARCHIVE}/cortex-server" "${ARCHIVE}/cortex-cli" /usr/local/bin/
rm -rf "${ARCHIVE}" "${ARCHIVE}.tar.gz"
```

| Platform | Pre-built binary |
|----------|-----------------|
| macOS Apple Silicon (M1/M2/M3) | `cortex-auth-v0.1.2-aarch64-apple-darwin.tar.gz` |
| macOS Intel | — build from source |
| Linux x86_64 | `cortex-auth-v0.1.2-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 | `cortex-auth-v0.1.2-aarch64-unknown-linux-musl.tar.gz` |

### Build from source

Requires [Rust](https://rustup.rs) (stable).

```bash
git clone https://github.com/davideuler/cortex-auth.git
cd cortex-auth
cargo build --release
# Binaries at: target/release/cortex-server  target/release/cortex-cli
```

## Quick Start

```bash
# Generate the admin token (the KEK is derived from an operator passphrase you type at startup)
ADMIN_TOKEN=$(openssl rand -hex 16)

# Start the server. It boots SEALED and prompts for the KEK operator password
# on stdin. After the password unwraps the on-disk sentinel the server
# transitions to UNSEALED and starts listening on :3000.
DATABASE_URL=sqlite://cortex-auth.db \
ADMIN_TOKEN=$ADMIN_TOKEN \
cortex-server
# [cortex-server SEALED] Enter KEK operator password: ********

# (Headless deployments — supply the password via env var instead of stdin.)
# CORTEX_KEK_PASSWORD='strong-passphrase' cortex-server

# In another terminal — add a secret
curl -X POST http://localhost:3000/admin/secrets \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"key_path":"openai_api_key","secret_type":"KEY_VALUE","value":"sk-your-key"}'

# Discover project secrets (authenticate with agent_id + signed JWT)
AUTH_PROOF=$(cortex-cli gen-token --agent-id my-agent --jwt-secret <agent_jwt_secret>)
curl -X POST http://localhost:3000/agent/discover \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"my-agent\",\"auth_proof\":\"$AUTH_PROOF\",\"context\":{\"project_name\":\"my-app\",\"file_content\":\"OPENAI_API_KEY=\"}}"
# Save the returned project_token!

# Launch your app with secrets injected
cortex-cli run \
  --project my-app --token <project_token> --url http://localhost:3000 \
  -- python3 main.py
```

## Components

| Component | Description |
|-----------|-------------|
| `cortex-server` | HTTP API server (axum + SQLite). Stores secrets encrypted with AES-256-GCM. |
| `cortex-cli` | CLI launcher that fetches secrets and `exec()`s your process with them injected as env vars. |

## Agent Skills Integration

The `cortex-skills/` directory contains a ready-to-use skill following the
[Agent Skills open standard](https://developers.openai.com/codex/skills) — the same
`SKILL.md` format works across all major agent frameworks. Once installed, your agent
autonomously authenticates with Cortex and injects secrets without any human prompting.

| Agent | Skills directory | Docs |
|-------|-----------------|------|
| [Claude Code](https://code.claude.com/docs/en/skills) | `~/.claude/skills/` (global) · `.claude/skills/` (project) | [Extend Claude with skills](https://code.claude.com/docs/en/skills) |
| [Codex CLI](https://developers.openai.com/codex/skills) | `~/.codex/skills/` (global) · `.agents/skills/` (project) | [Agent Skills – Codex](https://developers.openai.com/codex/skills) |
| [OpenCode](https://opencode.ai/docs/skills/) | `~/.opencode/skills/` (global) · `.opencode/skills/` (project) | [Agent Skills · OpenCode](https://opencode.ai/docs/skills/) |
| [OpenClaw](https://docs.openclaw.ai/tools/skills) | `~/.openclaw/skills/` (global) · `skills/` (workspace) | [Skills – OpenClaw](https://docs.openclaw.ai/tools/skills) |
| [Hermes Agent](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills) | `~/.hermes/skills/` (local) · `~/.agents/skills/` (shared) | [Skills System · Hermes](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills) |

```bash
# 1. Clone (or use your existing copy of) cortex-auth
git clone https://github.com/davideuler/cortex-auth.git /tmp/cortex-auth

# 2. Install the skill for your agent — pick one:

# Claude Code (global)
cp -r /tmp/cortex-auth/cortex-skills ~/.claude/skills/cortex-secrets

# Codex CLI (global)
cp -r /tmp/cortex-auth/cortex-skills ~/.codex/skills/cortex-secrets

# OpenCode (global)
cp -r /tmp/cortex-auth/cortex-skills ~/.opencode/skills/cortex-secrets

# OpenClaw (global)
cp -r /tmp/cortex-auth/cortex-skills ~/.openclaw/skills/cortex-secrets

# Hermes Agent (local)
cp -r /tmp/cortex-auth/cortex-skills ~/.hermes/skills/cortex-secrets
```

To keep the skill in sync with future cortex-auth updates, use symlinks instead of copying:
```bash
ln -sf /tmp/cortex-auth/cortex-skills ~/.claude/skills/cortex-secrets
```

For project-scoped installation (committed alongside your code), copy into the
agent-specific project directory (e.g. `.claude/skills/cortex-secrets/`).

## Documentation

- [Design & Architecture](docs/DESIGN.md) — System design, security model, data flow
- [Usage Guide](docs/USAGE.md) — Admin API examples, cortex-cli usage, production setup
- [Open Questions](docs/UNCERTAINTIES.md) — Items needing stakeholder decisions
- [Roadmap](docs/NEXT_STEPS.md) — Security hardening, features, optimizations

## Development

```bash
# Run all tests
cargo test --workspace

# Check for lint issues
cargo clippy --workspace -- -D warnings

# Build release binaries
cargo build --release
```

## Security Model

### Envelope Encryption with Operator-Held KEK

CortexAuth uses a two-tier key hierarchy. The **KEK** (Key Encryption Key) lives only in the
operator's head and in process memory; the DB never stores it. Every secret is encrypted with
its own random **DEK** (Data Encryption Key); the DEK is then wrapped with the KEK and stored
beside the ciphertext. The plaintext DEK is zeroized as soon as the row is written.

#### Server boot — SEALED → UNSEALED

```
1. cortex-server starts in SEALED state — no listener yet
2. Operator types the KEK password (stdin) or supplies CORTEX_KEK_PASSWORD
3. Server derives KEK = Argon2id(password, salt_from_DB) and mlocks it
4. Server reads the sentinel ciphertext, decrypts it with KEK, compares to
   the known plaintext → proves the password matches the prior KEK
5. Server transitions to UNSEALED and binds :3000
```

A wrong password fails the sentinel check and the process exits without ever opening the listener.
On first boot the sentinel is generated and stored automatically.

#### Write path (admin adds a secret)

```
plaintext = "sk-abc123..."

step 1  DEK         = random_bytes(32)
step 2  ciphertext  = AES-256-GCM(DEK, nonce_d, plaintext)
step 3  wrapped_DEK = AES-256-GCM(KEK, nonce_k, DEK)
step 4  INSERT INTO secrets(ciphertext, wrapped_DEK, kek_version, ...)
step 5  zeroize(DEK, plaintext)
```

#### Read path (agent fetches a secret)

```
step 1  SELECT ciphertext, wrapped_DEK
step 2  DEK       = AES-256-GCM-Decrypt(KEK, nonce_k, wrapped_DEK)
step 3  plaintext = AES-256-GCM-Decrypt(DEK, nonce_d, ciphertext)
step 4  return plaintext; zeroize intermediate DEK copies
```

Compromise of the DB alone does not leak any secret — the wrapped DEKs are useless without the KEK,
which is only ever in the running server's memory.

### Namespaces

Namespaces partition secrets, agents, projects, and configs. An agent registered in namespace
`prod` only sees secrets in `prod`; the same agent ID in `staging` sees a different set. Manage
namespaces from the dashboard (`Namespaces` tab) or the admin API:

```bash
curl -X POST http://localhost:3000/admin/namespaces \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"staging","description":"Pre-prod environment"}'

# Tag a secret/agent at create-time:
curl -X POST http://localhost:3000/admin/secrets \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"key_path":"openai_api_key","secret_type":"KEY_VALUE","value":"sk-...","namespace":"staging"}'
```

The `default` namespace is created automatically and cannot be deleted. A namespace that still
owns secrets/agents/projects refuses deletion.

### Other guarantees

- AES-256-GCM with a unique nonce per write for both DEK→body and KEK→DEK steps
- Project tokens hashed with SHA-256 (the raw token is never stored)
- Admin operations protected by static `ADMIN_TOKEN`
- `/agent/discover` authenticates agents directly via signed JWT (no separate session token)
- Project access via one-time-issued `project_token` (must be saved — cannot be recovered)
- Full audit log of all secret accesses
- `cortex-cli` uses `exec()` — secrets never visible to a parent process
- KEK rotation: `POST /admin/rotate-key {"new_kek_password": "..."}` re-wraps every DEK with the new KEK and bumps `kek_version`. Body ciphertexts are untouched.
