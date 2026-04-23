# CortexAuth — Agent-Centric Secrets & Configuration Service

[中文文档](README.zh-CN.md)

A lightweight, Rust-based secrets vault designed for AI agents and automated pipelines. Store API keys and configuration securely, discover which secrets your project needs, and inject them at runtime — without ever hardcoding secrets in source code.

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
VERSION=v0.1.1

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
| macOS Apple Silicon (M1/M2/M3) | `cortex-auth-v0.1.1-aarch64-apple-darwin.tar.gz` |
| macOS Intel | — build from source |
| Linux x86_64 | `cortex-auth-v0.1.1-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 | `cortex-auth-v0.1.1-aarch64-unknown-linux-musl.tar.gz` |

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
# Generate keys
ENCRYPTION_KEY=$(openssl rand -hex 32)
ADMIN_TOKEN=$(openssl rand -hex 16)

# Start the server
DATABASE_URL=sqlite://cortex-auth.db \
ENCRYPTION_KEY=$ENCRYPTION_KEY \
ADMIN_TOKEN=$ADMIN_TOKEN \
cortex-server

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
- Agent JWT secrets stored encrypted; project tokens stored as SHA-256 hashes
- Admin operations protected by static `ADMIN_TOKEN`
- `/agent/discover` authenticates agents directly via signed JWT (no separate session token)
- Project access via one-time-issued `project_token` (must be saved — cannot be recovered)
- Full audit log of all secret accesses
- `cortex-cli` uses `exec()` — secrets never visible to a parent process
