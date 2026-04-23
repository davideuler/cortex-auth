# CortexAuth — Agent-Centric Secrets & Configuration Service

A lightweight, Rust-based secrets vault designed for AI agents and automated pipelines. Store API keys and configuration securely, discover which secrets your project needs, and inject them at runtime — without ever hardcoding secrets in source code.

## Quick Start

```bash
# Generate keys
ENCRYPTION_KEY=$(openssl rand -hex 32)
ADMIN_TOKEN=$(openssl rand -hex 16)
SESSION_SECRET=$(openssl rand -hex 32)

# Start the server
DATABASE_URL=sqlite://cortex-auth.db \
ENCRYPTION_KEY=$ENCRYPTION_KEY \
ADMIN_TOKEN=$ADMIN_TOKEN \
SESSION_SECRET=$SESSION_SECRET \
cargo run --bin cortex-server

# In another terminal — add a secret
curl -X POST http://localhost:3000/admin/secrets \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"key_path":"openai_api_key","secret_type":"KEY_VALUE","value":"sk-your-key"}'

# Discover project secrets
curl -X POST http://localhost:3000/agent/discover \
  -H "Content-Type: application/json" \
  -d '{"context":{"project_name":"my-app","file_content":"OPENAI_API_KEY="}}'
# Save the returned project_token!

# Launch your app with secrets injected
cargo run --bin cortex-cli -- \
  --project my-app --token <project_token> --url http://localhost:3000 \
  -- python3 main.py
```

## Components

| Component | Description |
|-----------|-------------|
| `cortex-server` | HTTP API server (axum + SQLite). Stores secrets encrypted with AES-256-GCM. |
| `cortex-cli` | CLI launcher that fetches secrets and `exec()`s your process with them injected as env vars. |

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

- Secrets encrypted at rest with AES-256-GCM (unique nonce per write)
- Agent credentials stored encrypted; project tokens stored as SHA-256 hashes
- Admin operations protected by static `ADMIN_TOKEN`
- Project access via one-time-issued `project_token` (must be saved — cannot be recovered)
- Full audit log of all secret accesses
- `cortex-cli` uses `exec()` — secrets never visible to a parent process
