# CortexAuth — 面向 AI Agent 的密钥与配置服务

[English](README.md)

一个轻量级的 Rust 密钥保险库，专为 AI Agent 和自动化流水线设计。安全地存储 API Key 和配置，在运行时自动发现并注入项目所需的密钥——无需在源代码中硬编码任何敏感信息。

## 架构

```
                      ┌──────────────────────────────────────┐
                      │           cortex-server              │
         管理员 API    │  · KEK 常驻 mlock 内存（运维持有口令） │
  管理员 ────────────►│  · 每行数据各自的 DEK 由 KEK 包裹      │
  (curl / API)        │  · 验证 Agent 身份（JWT）              │
                      │  · 签发项目令牌                        │
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
- **无需人工介入** — Agent 自主完成跨项目、跨任务的密钥获取与注入，每次运行无需人工手动输入凭证（首次项目密钥访问审批除外）
- **全自动密钥注入** — 无人值守的 Agent 流水线在运行时按需获取所需密钥，无需操作人员介入
- **密钥不落盘** — API Key、数据库密码、Auth Token、密码等凭证仅以环境变量形式存在于进程内存中，不写入任何文件
- **同 UID AI Agent 隔离** — `cortex-daemon`（#16）在独立进程中持有 Agent 的 Ed25519 私钥并通过 Unix socket（`~/.cortex/agent.sock`）暴露 `run`/`inject_template` 操作，同机进程可请求执行已知二进制但无法导出密钥原文

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
# 生成 admin token；KEK 由启动时输入的运维口令派生（不再使用 ENCRYPTION_KEY 环境变量）
ADMIN_TOKEN=$(openssl rand -hex 16)

# 启动服务器：进程先进入 SEALED 状态，等待运维通过 stdin 输入 KEK 口令；
# 口令解开 DB 中的哨兵后切换到 UNSEALED 并开始监听 :3000。
DATABASE_URL=sqlite://cortex-auth.db \
ADMIN_TOKEN=$ADMIN_TOKEN \
cortex-server
# [cortex-server SEALED] Enter KEK operator password: ********

# 无人值守部署可改用环境变量传入：
# CORTEX_KEK_PASSWORD='strong-passphrase' cortex-server

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

## Agent Skills 集成

`cortex-skills/` 目录包含一个开箱即用的 Skill，遵循
[Agent Skills 开放标准](https://developers.openai.com/codex/skills)——
同一份 `SKILL.md` 可在所有主流 Agent 框架中使用。安装后，Agent 将自主完成
Cortex 认证和密钥注入，无需任何人工提示。

| Agent | Skills 目录 | 文档 |
|-------|------------|------|
| [Claude Code](https://code.claude.com/docs/en/skills) | `~/.claude/skills/`（全局）· `.claude/skills/`（项目） | [Extend Claude with skills](https://code.claude.com/docs/en/skills) |
| [Codex CLI](https://developers.openai.com/codex/skills) | `~/.codex/skills/`（全局）· `.agents/skills/`（项目） | [Agent Skills – Codex](https://developers.openai.com/codex/skills) |
| [OpenCode](https://opencode.ai/docs/skills/) | `~/.opencode/skills/`（全局）· `.opencode/skills/`（项目） | [Agent Skills · OpenCode](https://opencode.ai/docs/skills/) |
| [OpenClaw](https://docs.openclaw.ai/tools/skills) | `~/.openclaw/skills/`（全局）· `skills/`（工作区） | [Skills – OpenClaw](https://docs.openclaw.ai/tools/skills) |
| [Hermes Agent](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills) | `~/.hermes/skills/`（本地）· `~/.agents/skills/`（共享） | [Skills System · Hermes](https://hermes-agent.nousresearch.com/docs/user-guide/features/skills) |

```bash
# 1. 克隆（或使用已有的）cortex-auth 仓库
git clone https://github.com/davideuler/cortex-auth.git /tmp/cortex-auth

# 2. 将 skill 安装到对应 Agent——按需选择：

# Claude Code（全局）
cp -r /tmp/cortex-auth/cortex-skills ~/.claude/skills/cortex-secrets

# Codex CLI（全局）
cp -r /tmp/cortex-auth/cortex-skills ~/.codex/skills/cortex-secrets

# OpenCode（全局）
cp -r /tmp/cortex-auth/cortex-skills ~/.opencode/skills/cortex-secrets

# OpenClaw（全局）
cp -r /tmp/cortex-auth/cortex-skills ~/.openclaw/skills/cortex-secrets

# Hermes Agent（本地）
cp -r /tmp/cortex-auth/cortex-skills ~/.hermes/skills/cortex-secrets
```

如需在 cortex-auth 更新时自动同步，可使用符号链接替代复制：
```bash
ln -sf /tmp/cortex-auth/cortex-skills ~/.claude/skills/cortex-secrets
```

如需项目级安装（与代码一起提交），将 skill 复制到对应 Agent 的项目目录下
（例如 `.claude/skills/cortex-secrets/`）。

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

### 信封加密 + 运维持有 KEK

CortexAuth 采用两级密钥体系。**KEK**（密钥加密密钥）只存在运维大脑里和服务器进程内存中，
DB 永不存储。每条数据使用一把独立的随机 **DEK**（数据加密密钥）加密，DEK 再被 KEK
"包"住后与密文一起入库；DEK 明文写入完成立即在内存中清零。

#### 启动流程：SEALED → UNSEALED

```
1. cortex-server 启动后处于 SEALED 状态，尚未监听端口
2. 运维通过 stdin 输入 KEK 口令（或通过 CORTEX_KEK_PASSWORD 提供）
3. 服务器：KEK = Argon2id(口令, DB 中的 salt)，并对该内存页执行 mlock
4. 取库里的"哨兵密文"，用 KEK 解密 → 与已知明文比对 → 验证 KEK 正确
5. 服务器切到 UNSEALED 并开 :3000 监听
```

口令错误时哨兵解密失败，进程退出且永不打开监听端口。首次启动时哨兵自动生成入库。

#### 写入流程（admin 添加 API_KEY）

```
plaintext = "sk-abc123..."

step 1   DEK         = random_bytes(32)
step 2   ciphertext  = AES-256-GCM(DEK, nonce_d, plaintext)
step 3   wrapped_DEK = AES-256-GCM(KEK, nonce_k, DEK)
step 4   INSERT INTO secrets(ciphertext, wrapped_DEK, kek_version, ...)
step 5   立即 zeroize 内存中的 DEK 和 plaintext
```

#### 读取流程（agent 拉取密钥）

```
step 1   SELECT ciphertext, wrapped_DEK
step 2   DEK       = AES-256-GCM-Decrypt(KEK, nonce_k, wrapped_DEK)
step 3   plaintext = AES-256-GCM-Decrypt(DEK, nonce_d, ciphertext)
step 4   返回 plaintext，并 zeroize 中间产生的 DEK 副本
```

仅泄露 DB 文件不会泄露任何密钥——wrapped_DEK 离开 KEK 毫无用处，而 KEK 只存在运行中的服务器内存里。

### Namespace（命名空间）

Namespace 用于隔离密钥、Agent、项目、配置。一个注册在 `prod` 的 Agent 仅能看到 `prod` 下的密钥；
同名 Agent 注册在 `staging` 则看到不同的集合。可通过 Dashboard 的 "Namespaces" 标签页或 admin API 管理：

```bash
curl -X POST http://localhost:3000/admin/namespaces \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"name":"staging","description":"预发布环境"}'

# 创建密钥/Agent 时显式指定 namespace：
curl -X POST http://localhost:3000/admin/secrets \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"key_path":"openai_api_key","secret_type":"KEY_VALUE","value":"sk-...","namespace":"staging"}'
```

`default` namespace 自动创建且不可删除；仍有密钥/Agent/项目引用的 namespace 拒绝删除。

### 蜜罐告警与外发通知（#12 / #15）

蜜罐密钥被读取时立即吊销调用方令牌、写入 `alarm` 审计行，并向所有启用的通知渠道
派发外发告警。同样地，使用 Shamir 分片恢复模式启动服务时也会派发告警。
通道在管理后台 `Notifications` 页签中管理；支持类型：

| 通道 | 传输方式 | 配置 |
|------|----------|------|
| Slack    | 入站 webhook | `{"webhook_url":"https://hooks.slack.com/..."}` |
| Discord  | 入站 webhook | `{"webhook_url":"https://discord.com/api/webhooks/..."}` |
| Telegram | Bot API | `{"bot_token":"...","chat_id":"..."}` |
| Email    | `himalaya-cli`（在 PATH 中可用时） | `{"to":"oncall@example.com","account":"..."}` |

通道配置本身使用 KEK 信封加密；只盗取数据库不会泄露 webhook URL 或 bot token。

### Ed25519 Agent 身份（#13）

Agent 现在可以注册 **Ed25519 公钥** 替代（或并行于）传统的 HMAC `jwt_secret`。
Agent 在本地用 `cortex-cli gen-key` 生成密钥对，仅上传公钥，并在 `/agent/discover`
时对 `ts | nonce | agent_id | /agent/discover` 进行 Ed25519 签名作为 `auth_proof`。
请求 `ts` 必须在服务器时钟 ±5 分钟内（防重放）。

```bash
# 1. 本地生成密钥对（私钥落盘 ~/.cortex/agent-<id>.key，权限 0600）
cortex-cli gen-key --agent-id my-agent

# 2. 上传公钥注册 Agent
curl -X POST http://localhost:3000/admin/agents \
  -H "Content-Type: application/json" -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"agent_id":"my-agent","agent_pub":"<base64url-pubkey>"}'

# 3. 运行时签名
cortex-cli sign-proof --agent-id my-agent --priv-key-file ~/.cortex/agent-my-agent.key
```

### Ed25519 签名项目令牌（#14）

`POST /agent/discover` 接受 `signed_token: true`，响应中除了传统随机 `project_token`
还会返回 EdDSA 签名的 JWT 形式 `signed_project_token`。验证方从
`GET /.well-known/jwks.json` 获取服务器公钥（按 `kid` 索引，便于密钥轮转后老 token
继续可验证）；吊销由 `revoked_token_jti` 表承担。

### Shamir m-of-n 解封恢复（#15）

操作员密码丢失时，可用 Shamir 分片重建 KEK：

```bash
# 一次性生成分片（服务器不保留副本，请立刻分发给操作员）
curl -X POST http://localhost:3000/admin/shamir/generate \
  -H "Content-Type: application/json" -H "X-Admin-Token: $ADMIN_TOKEN" \
  -d '{"threshold": 3, "shares": 5}'

# 恢复模式启动：交互式从 stdin 读取 m 份分片
CORTEX_RECOVERY_MODE=1 CORTEX_RECOVERY_THRESHOLD=3 \
ADMIN_TOKEN=$ADMIN_TOKEN \
cortex-server
```

恢复成功后会写入 `alarm` 状态的 `recovery_boot` 审计行并触发外发通知。

### 设备授权与 cortex-daemon（#16）

长期运行的 `cortex-daemon` 可在 Unix Socket（`~/.cortex/agent.sock`，权限 0600）
代为持有 Ed25519 会话密钥，调用方通过 socket 请求 `run` 即可注入密钥并执行进程，
原始密钥永远不会回传。登录使用 OAuth 2.0 设备授权（RFC 8628）：

```bash
cortex-daemon &
cortex-cli daemon login --url http://localhost:3000   # 打印 user_code
# 管理员在 /device 页面或 Devices 页签批准 user_code，绑定到注册过的 agent_id
cortex-cli daemon status
```

### 其他保障

- AES-256-GCM 全程使用唯一随机 nonce，DEK→密文 与 KEK→DEK 两层均独立 nonce
- 项目令牌：legacy 路径用 SHA-256 哈希存储；signed_token 路径使用 EdDSA JWT，公钥经 JWKS 暴露
- 管理员操作通过静态 `ADMIN_TOKEN` 保护（多用户 RBAC 列入 #18）
- `/agent/discover` 支持 Ed25519（优先）或 HMAC-SHA256 JWT 验证 Agent 身份
- 全量审计日志且 HMAC-SHA256 链式防篡改
- `cortex-cli` 使用 `exec()` 启动子进程——父进程无法访问密钥
- `cortex-daemon` 通过 Unix socket 屏蔽密钥导出
- KEK 轮转：`POST /admin/rotate-key`；KEK 恢复：Shamir 分片
- 外发告警支持 Slack / Discord / Telegram / 邮件（himalaya-cli）
