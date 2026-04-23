# CortexAuth — 面向 AI Agent 的密钥与配置服务

[English](README.md)

一个轻量级的 Rust 密钥保险库，专为 AI Agent 和自动化流水线设计。安全地存储 API Key 和配置，在运行时自动发现并注入项目所需的密钥——无需在源代码中硬编码任何敏感信息。

## 架构

```
                      ┌──────────────────────────────────────┐
                      │           cortex-server              │
         管理员 API    │  · 存储密钥（AES-256-GCM 加密）      │
  管理员 ────────────►│  · 验证 Agent 身份（JWT）             │
  (curl / API)        │  · 签发项目令牌                       │
                      └───────────────┬──────────────────────┘
                                      │  ② project_token
                                      │  ③ env vars 环境变量
                                      │
  ┌───────────────────────────────────┼────────────────────────┐
  │               Agent               │                        │
  │         （自主运行的 AI 流水线）    │                        │
  │                                   ▼                        │
  │  ① cortex-cli gen-token  ┌─────────────────┐              │
  │  ──────────────────────► │   cortex-cli    │              │
  │                          │                 │              │
  │  ④ cortex-cli run        │  gen-token      │              │
  │  ──────────────────────► │  run → exec()   │              │
  └──────────────────────────┴────────┬────────┘──────────────┘
                                      │
                                 exec() 注入环境变量
                                      │
                                      ▼
                            ┌─────────────────────┐
                            │    项目进程           │
                            │  python main.py     │
                            │  node app.js  …     │
                            │                     │
                            │  OPENAI_API_KEY=...  │
                            │  DB_PASSWORD=...    │
                            │  AUTH_TOKEN=...     │
                            └─────────────────────┘
```

**执行流程：**
1. **管理员** 通过 admin API 将项目密钥预存至 `cortex-server`
2. **Agent** 调用 `cortex-cli gen-token` 签名 JWT（`auth_proof`）以证明身份
3. **Agent** 将 `auth_proof` POST 到 `/agent/discover` → 获取 `project_token`
4. **Agent** 调用 `cortex-cli run --project <name> --token <project_token>`，从服务器拉取密钥并通过 `exec()` 将其注入为环境变量后启动目标进程

## Agent 密钥管理原则

- **Agent 不接触密钥明文** — 密钥由 `cortex-server` 直接通过 `exec()` 注入进程环境，Agent 代码本身从不读取或存储密钥值
- **无需人工介入** — Agent 自主完成跨项目、跨任务的密钥获取与注入，每次运行无需人工手动输入凭证
- **全自动密钥注入** — 无人值守的 Agent 流水线在运行时按需获取所需密钥，无需操作人员介入
- **密钥不落盘** — API Key、数据库密码、Auth Token、密码等凭证仅以环境变量形式存在于进程内存中，不写入任何文件

## 安装

### Homebrew（macOS Apple Silicon）

```bash
brew tap davideuler/cortex-auth
brew install cortex-auth
```

> **注意：** Homebrew tap 仅提供 **Apple Silicon（M1/M2/M3）** 的预编译二进制文件。
> macOS Intel 用户请参考[从源码编译](#从源码编译)。

### 预编译二进制（Linux / macOS Apple Silicon）

从 [GitHub Releases](https://github.com/davideuler/cortex-auth/releases) 页面下载。

```bash
VERSION=v0.1.2

# 自动识别平台
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  TARGET=aarch64-apple-darwin ;;
  Linux-x86_64)  TARGET=x86_64-unknown-linux-musl ;;
  Linux-aarch64) TARGET=aarch64-unknown-linux-musl ;;
  *) echo "该平台暂无预编译包，请参考下方从源码编译"; exit 1 ;;
esac

ARCHIVE="cortex-auth-${VERSION}-${TARGET}"
curl -fLO "https://github.com/davideuler/cortex-auth/releases/download/${VERSION}/${ARCHIVE}.tar.gz"
tar xzf "${ARCHIVE}.tar.gz"
sudo mv "${ARCHIVE}/cortex-server" "${ARCHIVE}/cortex-cli" /usr/local/bin/
rm -rf "${ARCHIVE}" "${ARCHIVE}.tar.gz"
```

| 平台 | 预编译包 |
|------|--------|
| macOS Apple Silicon（M1/M2/M3） | `cortex-auth-v0.1.2-aarch64-apple-darwin.tar.gz` |
| macOS Intel | — 请从源码编译 |
| Linux x86_64 | `cortex-auth-v0.1.2-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 | `cortex-auth-v0.1.2-aarch64-unknown-linux-musl.tar.gz` |

### 从源码编译

需要安装 [Rust](https://rustup.rs)（stable 版本）。

```bash
git clone https://github.com/davideuler/cortex-auth.git
cd cortex-auth
cargo build --release
# 产物路径：target/release/cortex-server  target/release/cortex-cli
```

## 快速开始

```bash
# 生成密钥
ENCRYPTION_KEY=$(openssl rand -hex 32)
ADMIN_TOKEN=$(openssl rand -hex 16)

# 启动服务器
DATABASE_URL=sqlite://cortex-auth.db \
ENCRYPTION_KEY=$ENCRYPTION_KEY \
ADMIN_TOKEN=$ADMIN_TOKEN \
cortex-server

# 在另一个终端——添加一个密钥
curl -X POST http://localhost:3000/admin/secrets \
  -H "Content-Type: application/json" \
  -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"key_path":"openai_api_key","secret_type":"KEY_VALUE","value":"sk-your-key"}'

# 发现项目密钥（使用 agent_id + 签名 JWT 进行认证）
AUTH_PROOF=$(cortex-cli gen-token --agent-id my-agent --jwt-secret <agent_jwt_secret>)
curl -X POST http://localhost:3000/agent/discover \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"my-agent\",\"auth_proof\":\"$AUTH_PROOF\",\"context\":{\"project_name\":\"my-app\",\"file_content\":\"OPENAI_API_KEY=\"}}"
# 保存返回的 project_token！

# 注入密钥并启动应用
cortex-cli run \
  --project my-app --token <project_token> --url http://localhost:3000 \
  -- python3 main.py
```

## 组件说明

| 组件 | 描述 |
|------|------|
| `cortex-server` | HTTP API 服务器（axum + SQLite），使用 AES-256-GCM 加密存储密钥。 |
| `cortex-cli` | CLI 启动器，获取密钥后通过 `exec()` 将其注入为环境变量并启动子进程。 |

## 文档

- [设计与架构](docs/DESIGN.md) — 系统设计、安全模型、数据流
- [使用指南](docs/USAGE.md) — 管理员 API 示例、cortex-cli 用法、生产部署
- [待决问题](docs/UNCERTAINTIES.md) — 需要确认的事项
- [路线图](docs/NEXT_STEPS.md) — 安全加固、功能规划、性能优化

## 开发

```bash
# 运行所有测试
cargo test --workspace

# 检查代码规范
cargo clippy --workspace -- -D warnings

# 编译发布版本
cargo build --release
```

## 安全模型

- 密钥静态加密：AES-256-GCM，每次写入使用唯一随机数（nonce）
- Agent JWT 密钥加密存储；项目令牌以 SHA-256 哈希形式保存
- 管理员操作通过静态 `ADMIN_TOKEN` 保护
- `/agent/discover` 直接通过签名 JWT 验证 Agent 身份，无独立 Session 令牌
- 项目访问使用一次性签发的 `project_token`（必须保存，无法找回，仅可重新生成）
- 全量审计日志，记录所有密钥访问行为
- `cortex-cli` 使用 `exec()` 启动子进程——父进程无法访问密钥
