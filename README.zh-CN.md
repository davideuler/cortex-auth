# CortexAuth — 面向 AI Agent 的密钥与配置服务

[English](README.md)

一个轻量级的 Rust 密钥保险库，专为 AI Agent 和自动化流水线设计。安全地存储 API Key 和配置，在运行时自动发现并注入项目所需的密钥——无需在源代码中硬编码任何敏感信息。

## 安装

### Homebrew（macOS）

```bash
brew tap davideuler/cortex-auth
brew install cortex-auth
```

### 直接下载

从 [GitHub Releases](https://github.com/davideuler/CortexAuth/releases) 页面下载预编译的二进制文件。

### 一键安装（Linux / macOS）

```bash
VERSION=v0.1.1

# 自动识别平台
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  TARGET=aarch64-apple-darwin ;;
  Darwin-x86_64) TARGET=x86_64-apple-darwin ;;
  Linux-x86_64)  TARGET=x86_64-unknown-linux-musl ;;
  Linux-aarch64) TARGET=aarch64-unknown-linux-musl ;;
  *) echo "不支持的平台"; exit 1 ;;
esac

ARCHIVE="cortex-auth-${VERSION}-${TARGET}"
curl -fLO "https://github.com/davideuler/CortexAuth/releases/download/${VERSION}/${ARCHIVE}.tar.gz"
tar xzf "${ARCHIVE}.tar.gz"
sudo mv "${ARCHIVE}/cortex-server" "${ARCHIVE}/cortex-cli" /usr/local/bin/
rm -rf "${ARCHIVE}" "${ARCHIVE}.tar.gz"
```

### 手动下载

| 平台 | 安装包 |
|------|--------|
| macOS Apple Silicon | `cortex-auth-v0.1.1-aarch64-apple-darwin.tar.gz` |
| macOS Intel | `cortex-auth-v0.1.1-x86_64-apple-darwin.tar.gz` |
| Linux x86_64 | `cortex-auth-v0.1.1-x86_64-unknown-linux-musl.tar.gz` |
| Linux ARM64 | `cortex-auth-v0.1.1-aarch64-unknown-linux-musl.tar.gz` |

每个安装包包含两个二进制文件：`cortex-server` 和 `cortex-cli`。解压后将它们放到 `PATH` 中的任意目录即可。

### 从源码编译

```bash
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
