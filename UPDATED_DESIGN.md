## 一、原则：
- **Agents never touch secret values** — secrets flow directly from `cortex-server` into the process environment via `exec()`; agent code never reads or stores them

- **No human intervention per task** — agents autonomously obtain and inject secrets across any number of projects and tasks without requiring manual input for each run (except first time project secrets access approval)

- **Fully autonomous secret injection** — unattended agent pipelines retrieve all required credentials on demand at runtime; no operator in the loop

- **Secrets never written to disk** — API keys, database credentials, tokens, and passwords exist only in process memory as environment variables; nothing is persisted to files


## 二、存储数据的信封加密 / Vault 式 unseal 详解

###  KEK 与 DEK 的定义

|名称|全称|角色|数量|存放位置|
|---|---|---|---|---|
|**DEK**|Data Encryption Key|**直接加密一条数据**|**每条 secret 各一个**（短命，可频繁生成）|加密后随密文存在数据库里|
|**KEK**|Key Encryption Key|**加密 DEK**|全库**一把**（长命，少量、贵重）|永不落盘；运行期内存中；启动时从外部信任根 unwrap 拿到|

类比："数据"是信件，DEK 是写满收件人地址的信封，KEK 是公司保险柜的钥匙。看的人要先用保险柜钥匙（KEK）打开保险柜，从里面拿出对应的信封钥匙（DEK），才能拆开信封看信。**保险柜钥匙永远不交给员工，每次员工要查信件时由保险柜本身解锁返回单封信封钥匙。**

### 写入流程（admin 加一条 API_KEY secret）

```
plaintext = "sk-abc123..."

step 1：生成一把全新 DEK（32 字节随机数）
    DEK = random_bytes(32)

step 2：用 DEK 加密 plaintext
    ciphertext = AES-256-GCM(DEK, nonce_d, plaintext, secret_id, kek_version)

step 3：用内存里的 KEK "包"住这个 DEK
    wrapped_DEK = AES-256-GCM(KEK, nonce_k, DEK, secret_id, kek_version)

step 4：写库
    INSERT INTO secrets(ciphertext, secret_id, nonce_d, wrapped_DEK, nonce_k, kek_version, ...)

step 5：立刻 zeroize 内存里的 DEK 与 plaintext
```

### 读取流程（agent 拿这条 secret）

```
step 1：SELECT ciphertext, wrapped_DEK ...

step 2：用内存里的 KEK 解开 wrapped_DEK
    DEK = AES-256-GCM-Decrypt(KEK, nonce_k, wrapped_DEK)

step 3：用 DEK 解密 ciphertext
    plaintext = AES-256-GCM-Decrypt(DEK, nonce_d, ciphertext)

step 4：返回 plaintext 给调用方；zeroize DEK 与 plaintext 的中间副本
```

### 三大好处具体兑现

**好处 ① 拖库无用**

- 库里只有 `ciphertext + wrapped_DEK + nonce`
- 没有 KEK，连 wrapped_DEK 都解不开 → 一条都看不到
- 即使 KEK 派生用了运维密码，攻击者也得离线暴力破解强密码（Argon2id 让"暴力"在十年尺度上不可行）

**好处 ② KEK 轮转 O(N) 且不动密文**

- 想换 KEK_old → KEK_new
- 只需对每行：用 KEK_old 解 wrapped_DEK，再用 KEK_new 重 wrap
- 32 字节读出 → 32 字节写回，**真实密文（可能 KB～MB）从未被读写**
- 千万条记录的库轮转可能也就秒级

**好处 ③ KEK 可以放进"贵宾级保险柜"**

- 因为 KEK 只在**启动时**被使用一次，之后留在内存里
- 你可以让 KEK 来自 AWS KMS / HSM / TPM —— 这些"慢但安全"的设施只需被调用一次
- 之后所有 secret 读写在内存里完成，不会拖性能

**好处 ④ 单条 DEK 泄漏只伤一条记录**

- 如果某次内存窗口里某一条 DEK 被截走，攻击者**只能解这一条**对应的 ciphertext
- 不会像"共享一把 master key"那样一损全损

---

## 四、整套 sealed / unsealed 流程串起来

把 Vault 的状态机移植到 cortex-server：

```
┌────────────────────────────────────────────────────┐
│  状态 0：BOOT                                       │
│  - 进程刚起，DB 已连接，但所有业务路由 disabled    │
│  - 仅 /sys/seal-status, /sys/unseal 开放           │
└──────────────────────────┬─────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────┐
│  状态 1：SEALED  （KEK = None）                     │
│  - 数据库里全是 ciphertext + wrapped_DEK           │
│  - 没有 KEK，谁来都解不开任何一条                  │
│  - 等外部信任根送 KEK 进来                         │
└──────────────────────────┬─────────────────────────┘
                           │ 外部信任根 → KEK
                           ▼
              ┌───────────┴───────────┐
              │                       │
   ┌──────────┴────────┐    ┌─────────┴──────────┐
   │ 自动模式          │    │ 人工模式           │
   │  - KMS:Decrypt    │    │  - 操作员密码      │
   │  - TPM unseal     │    │  - Shamir 收 K 份  │
   └──────────┬────────┘    └─────────┬──────────┘
              │                       │
              └───────────┬───────────┘
                          ▼
                 KEK 进入内存（mlock）
                          │
                          ▼
               用 KEK 试解一条"哨兵 DEK"
                          │
                          ▼
                          OK?
                          │
                          ▼
┌────────────────────────────────────────────────────┐
│  状态 2：UNSEALED                                   │
│  - 业务路由全开                                    │
│  - 任何 secret 读写都走 KEK→DEK→明文流程           │
│  - KEK 永远在内存                                  │
└──────────────────────────┬─────────────────────────┘
                           │ POST /sys/seal 或进程退出
                           ▼
                内存 KEK 被 zeroize → 回到 SEALED
```

#### 一次"启动到 ready"的全图（以 KMS auto-unseal 为例）

```
1. 命令行 拉起 cortex-server
2. server 读 DB metadata 表得知 kek_version=7、source=kms、kms_ciphertext=0xAB...
3. server 用机器自己的 IAM Role 调 KMS:Decrypt(0xAB...)
4. KMS 校验 IAM 主体，记录调用，返回 KEK 明文
5. server 把 KEK mlock 进受保护内存
6. server 取库里"哨兵 DEK"，用 KEK 解开，对比哨兵明文 → 验证 KEK 正确
7. server 切到 UNSEALED，开 :3000 监听
```

用 KMS，或者命令行启动 cortex-server，手工输入启动密钥（操作密钥），由启动密钥生成 KEK（使用Argon2ID Hash算法）。
#### 一次"普通 secret 读取"的全图

```
1. agent 调 GET /project/secrets/foo (Bearer project_token)
2. server 校验 token、policy、namespace
3. server 查映射的每条 secret 行：
     for row in mapped_secrets:
        DEK = AES-GCM-Decrypt(KEK,         row.wrapped_DEK_nonce, row.wrapped_DEK)
        val = AES-GCM-Decrypt(DEK,         row.value_nonce,       row.ciphertext)
        env_vars[row.env_name] = val
        zeroize(DEK)  // ← 仅在这次请求生命周期里短暂存在
4. JSON 返回
5. zeroize env_vars
```

---

## 五、回到你前一句的图，逐层解释

```
┌─────────────────────────────────────────────────────┐
│  外部信任根 (KMS / HSM / TPM / 操作员密码 / Shamir) │  ←【根】KEK 的存放方式
└────────────────┬────────────────────────────────────┘
                 │ 启动时 unwrap / unseal              ←【过程】只在启动时进行一次
                 ▼
┌─────────────────────────────────────────────────────┐
│  Master KEK (内存中，永不落盘)                       │  ←【主钥】mlock+zeroize 全程不进磁盘
└────────────────┬────────────────────────────────────┘
                 │ 解密 wrapped_DEK                    ←【过程】每次请求时使用
                 ▼
┌─────────────────────────────────────────────────────┐
│  每条 secret 独立 DEK (随密文一起存库, KEK-wrapped)  │  ←【数据钥】被 KEK 包好后存库
└─────────────────────────────────────────────────────┘
                 │ 解密 ciphertext
                 ▼
       业务可用的明文 secret（短命，用完 zeroize）
```

逐行：

- **第 1 框（外部信任根）**：`KEK` 不是凭空出现的，它要么从云 KMS 解密出来、要么从 TPM 的封印里出来、要么从运维输入的密码 + Argon2 派生出来、要么从 Shamir 的 K 块凑出来。这些**都不在数据库里、也不在 server 自己的磁盘上**——这就是"拖库无用"的根源。
- **第 2 框（KEK）**：进了内存，从此不再出现在磁盘任何地方；进程被 kill 即消失。
- **第 3 框（DEK）**：每条 secret 独立一把；DEK 自己被 KEK 加密后存进数据库；攻击者拿着库 + wrapped_DEK，没有 KEK 一筹莫展。
- **第 4 框（明文）**：只在响应一次请求那几毫秒里出现，立刻清零。

---

## 六、几个常见问题答疑

**Q1：为什么不在每次写库时直接用 KMS 加密？** A：因为 KMS 调用慢（10–50ms 量级）、有限速、按次收费。每条 secret 读写都打 KMS 不可行。信封加密让 KMS 只参与"启动 KEK unwrap"和"轮转 KEK"两次大事件，平时业务全在内存高速路径。

**Q2：DEK 一直在内存吗？** A：**不**。DEK 是"按需解开、用完即弃"。库里存的是 wrapped_DEK；处理一次请求才临时把对应那条的 DEK 解出来，用完 zeroize。所以即使内存被瞬间 dump，也只能拿到当时正在处理的那几条对应的 DEK，而不是全库。

**Q3：每条 secret 一个 DEK，是不是 32 字节 × 千万条 = 320MB？** A：是。但这是**密文存储**，不影响内存。实际现代部署（Vault、AWS Secrets Manager、GCP Secret Manager）都是这个量级，DB 完全 OK。如果实在想省，可以"一个 namespace 一个 DEK"折中，但损失了"单条 DEK 泄漏只伤一条"的精度。

**Q4：Shamir 比直接给 5 个人各发一份完整 KEK 强在哪？** A：发完整 KEK = `(1, 5)` 阈值，**任何一个人单独叛变就能解全库**。Shamir `(3, 5)` 要求 3 个人合谋才行，**且 1 或 2 个人手里的 share 真的、数学上、什么都说明不了**——不是"难破解"，是"破不了"。

**Q5：操作员密码 + Argon2id 也算外部信任根？** A：算。密码本身不是信任根，**"装在某位运维脑子里的那个密码"**是信任根。它没出现在你的磁盘、你的库、你的备份里——所以拖库 + 拷服务器配置文件**都没用**。代价是每次重启需要这位运维到场。

**Q6：如果攻击者拿到 root，KEK 还有意义吗？** A：在线 root：意义有限（KEK 在内存，root 能 ptrace 抓出来）。但**拖库类攻击占现实泄露的绝大多数**——备份桶配错权限、误把 dump 推到 GitHub、磁盘报废没擦——这些场景里 KEK 不在 dump 里就完全救回来了。这正是"按攻击概率分配防御预算"的合理做法。

---

## 七、一句话记法

> **DEK 锁数据，KEK 锁 DEK，外部信任根锁 KEK；Shamir 把"锁 KEK 的钥匙"再切成 K-of-N，使任何单点都开不了门。**


m=64 MiB, t=3, p=4

## 八、 cortex-auth 的数据加密

| 场景                        | 用什么                             | 为什么                                     |
| ------------------------- | ------------------------------- | --------------------------------------- |
| **运维 unseal 密码 → 派生 KEK** | **Argon2id（高档参数）**              | 启动只跑一次，可以重；密码低熵必须慢哈希                    |
| 多用户 RBAC 管理员密码            | Argon2id（中档：64 MiB / t=3 / p=4） | 登录 ~200 ms，用户无感                         |
| admin_token 哈希            | HMAC-SHA256 + pepper            | 同上                                      |
| 审计日志完整性                   | HMAC-SHA256（链式）                 | 高频写入，不需慢哈希                              |
**Argon2id = "慢 + 占内存"的密码哈希**。它通过强制每次验证都消耗大量 RAM，让攻击者无法用 GPU/ASIC 集群批量暴力破解低熵密码。在 cortex-auth 中，它最重要的用武之地是**把运维 unseal 密码转化为 256 位的 KEK**——一个低熵秘密被它"锻造"成一个高熵密钥，从而支撑起整个信封加密体系的信任根。
### Cortext server 启动流程：

```
1. server 读 kek_metadata: source='argon2id', salt=0x..., params=(1GiB, t=6, p=4)
2. 提示：cortex-server> Enter unseal password:
3. 运维输入密码（不回显）
4. derive_kek_from_password(pw, salt) ← 这一步耗时 ~5 s，CPU 跑满 4 核 + 占 1 GB RAM
5. 用派生出的 KEK 试解一条"哨兵 DEK" → 验证密码正确
6. 进入 UNSEALED 状态
```

攻击者拖走库后想暴力破解：

- 必须对每个候选密码花 ~5 秒 + 1 GB RAM
- 一台 GPU 装 24 GB 显存只能并发跑 24 路（vs 用 SHA-256 时几万路）
- 强密码（哪怕"diceware 5 词"）几个世纪都跑不完

## 九、Agent 的鉴权

**Agent 的身份验证改造为 Ed25519**：

```
注册时：
  agent 本地生成 keypair (priv_a, pub_a)；只把 pub_a 上传给 server
  server 库里只存 pub_a（32 字节，公开信息，不必加密）
每次 discover：
  agent → Ed25519-Sign(priv_a, payload) = sig
  server → Ed25519-Verify(pub_a, payload, sig)
```

 **给 project_token 加签名, 换成 Ed25519 签名 token：**
 
```
token = base64( {project_id, exp, scope} ) + base64( Ed25519-Sign(server_priv, claims) )
```

服务端验证时**只需公钥**，不需要查库——天然支持无状态横向扩展。
server_priv（服务端的签名私钥）： cortex-server 自己持有的 Ed25519 私钥，专门用来给签发出去的 token 签字。

claims: "这个 token 所声明的所有事实，包含**身份、有效期、权限范围、约束条件**等所有结构化信息"。
JWT 标准（RFC 7519）规定了 7 个"保留 claim"，业务可以**自由扩展**自定义 claim：

| Claim | 全称         | cortex-auth 中的含义                  |
| ----- | ---------- | --------------------------------- |
| `iss` | issuer     | 谁签发的 → `"cortex-server"`          |
| `sub` | subject    | 这个 token 代表谁 → `"project:my-app"` |
| `aud` | audience   | 给谁用的 → `"cortex-cli"`             |
| `iat` | issued at  | 何时签发（Unix 秒）                      |
| `exp` | expiration | 何时过期（**最重要**）                     |
| `nbf` | not before | 何时起开始生效（用于"未来生效" token）           |
| `jti` | JWT ID     | 唯一 ID，用于防重放/单次使用                  |

cortex-auth 业务自定义可加：

- `scope`、`namespace`、`agent_id`、`project_id` 等

> **claims = 这张"通行证"上印的所有字段**。签名只是确认这些字段没人改过，**字段本身全部明文**——任何持有 token 的人都能读出 `exp`、`scope`，但**不能修改**（一改签名就废）。

## `exp`（expiration）—— 过期时间

**值**：Unix 时间戳（秒），表示"过了这个点这张 token 就作废"。

```
"iat": 1714200000,    // 2024-04-27 12:00:00 UTC 签发"exp": 1714207200     // 2024-04-27 14:00:00 UTC 过期 (2 小时后)
```

服务端验签时：

```
if now() >= claims.exp {    return Err("token expired");}
```

**为什么必要**：

- 即使 token 被偷，**爆炸半径自动收敛**——攻击者只能在剩余时间窗口内作恶
- 对应 cortex-auth 当前 SKILL.md 文档里"120 分钟 TTL"的设计，就是 `exp = iat + 7200`

**配套 claim**：

- `nbf` (not before)：让 token "5 分钟后才生效"，常用于预签发
- `iat` (issued at)：写明签发时间，便于日志和"超过 N 天的 token 必须刷新"这类策略

#### `scope`（授权范围）—— 这张 token 能干什么

**字面意思**："这张 token 被授权访问哪些资源、做哪些操作"。

cortex-auth 当前问题（前面分析过）：**一个 project_token 能拿到该项目的全部 env_vars**。改成签名 token 后，可以把"能拿哪些"写进 token 本身：

#### 几种常见 scope 表达模式

#### 模式 A：动词:对象 字符串数组（最常见）

```
"scope": [  "secrets:read:openai_api_key",  "secrets:read:smtp_password",  "config:render:database"]
```
#### 模式 B：OAuth 风格的空格分隔字符串

```
"scope": "secrets.read config.render"
```

#### 模式 C：结构化 + 通配符

```
"scope": {  "secrets": ["openai_api_key", "smtp_password"],  "configs": ["*"]}
```
#### 模式 D：Macaroon 风格的"caveats（约束条件）"

```
"caveats": [  "project = my-app",  "secret IN (openai_api_key, smtp_password)",  "client_ip = 10.0.0.0/8",  "time < 2024-04-27T14:00:00Z"]
```

最强大、最复杂——Google 的 Macaroon 论文专门讲这个。

#### cortex-auth 推荐用法

```
{
  "sub": "project:my-app",
  "scope": [
    "secrets:read:openai_api_key",
    "secrets:read:smtp_password"
  ],
  "namespace": "team-a",
  "exp": 1714207200
}
```

**收益**：

- 现在拿到一个 token 就能读所有 mapped secrets → 改成"取 token 时声明你要哪些，server 把允许的写进 scope"
- 审计粒度从"取过 secret"变成"取过哪条 secret"
- 即使 token 泄漏，攻击者**也只能用到 scope 之内的资源**

##  0427 改进点：
### 1.cortex server 启动时，输入运维操作密码，根据操作密码生成内存中的 KEK.

```
1. 命令行启动 cortex-server，服务器初始状态为 SEALED
2. 运维输入操作密码，由操作密码生活才 KEK
3. server 把 KEK mlock 进受保护内存
4. server 取库里"哨兵 DEK"，用 KEK 解开，对比哨兵明文 → 验证 KEK 正确
5. server 切到 UNSEALED，开 :3000 监听
```

### 2.数据写入 DB 流程（例如 admin 在后台添加一条 API_KEY secret）

每一条数据都是用各自的 DEK (Data Encryption Key) 来加密，并且不保存明文的 DEK。

```
plaintext = "sk-abc123..."

step 1：生成一把全新 DEK（32 字节随机数）
    DEK = random_bytes(32)

step 2：用 DEK 加密 plaintext
    ciphertext = AES-256-GCM(DEK, nonce_d, plaintext)

step 3：用内存里的 KEK "包"住这个 DEK
    wrapped_DEK = AES-256-GCM(KEK, nonce_k, DEK)

step 4：写库
    INSERT INTO secrets(ciphertext, nonce_d, wrapped_DEK, nonce_k, kek_version)

step 5：立刻 zeroize 内存里的 DEK 与 plaintext
```

### 3.数据读取流程（agent 拿这条 secret）

```
step 1：SELECT ciphertext, wrapped_DEK ...

step 2：用内存里的 KEK 解开 wrapped_DEK
    DEK = AES-256-GCM-Decrypt(KEK, nonce_k, wrapped_DEK)

step 3：用 DEK 解密 ciphertext
    plaintext = AES-256-GCM-Decrypt(DEK, nonce_d, ciphertext)

step 4：返回 plaintext 给调用方；zeroize DEK 与 plaintext 的中间副本
```

### 4.可以维护 namespace, 所有存储的密钥，配置都可以选择一个或者多个 namespace

 namespace 下面的 agent/project 可以使用归属到 namespace 下面的密钥/配置。
 同一 key_path 在不同 namespace 可以重名。namespace 删除时，删除 secret/agent 关联的 namespace 的关系。
 "管理员"的 namespace 维度:多用户 RBAC 引入后, 每个管理员可以创建/读/写自己的 namespace 下面的数据。
 超级管理员可以管理所有数据。

### 5. cortex-auth 的数据加密

| 场景                        | 用什么                             | 为什么                                     |
| ------------------------- | ------------------------------- | --------------------------------------- |
| **运维 unseal 密码 → 派生 KEK** | **Argon2id（高档参数）**              | 启动只跑一次，可以重；密码低熵必须慢哈希                    |
| 多用户 RBAC 管理员密码            | Argon2id（中档：64 MiB / t=3 / p=4） | 登录 ~200 ms，用户无感                         |
| admin_token 哈希            | HMAC-SHA256 + pepper            | 同上                                      |
| 审计日志完整性                   | HMAC-SHA256（链式）                 | 高频写入，不需慢哈希                              |
**Argon2id = "慢 + 占内存"的密码哈希**。它通过强制每次验证都消耗大量 RAM，让攻击者无法用 GPU/ASIC 集群批量暴力破解低熵密码。在 cortex-auth 中，它最重要的用武之地是**把运维 unseal 密码转化为 256 位的 KEK**——一个低熵秘密被它"锻造"成一个高熵密钥，从而支撑起整个信封加密体系的信任根。

### 6.Agent 的身份验证改造为 Ed25519**：

```
注册时：
  agent 本地生成 keypair (priv_a, pub_a)；只把 pub_a 上传给 server
  server 库里只存 pub_a（32 字节，公开信息，不必加密）
每次 discover：
  agent → Ed25519-Sign(priv_a, payload) = sig
  server → Ed25519-Verify(pub_a, payload, sig)
```

Payload 含 ts + nonce + agent_id + path.

### 7.给 project_token 加签名, 换成 Ed25519 签名 token
 
```
token = base64( {project_id, exp, scope} ) + base64( Ed25519-Sign(server_priv, claims) )
```

project_token 引入 scope claim， project 能够使用的 token，以及自动检测到的，token 映射关系，需要在管理后台管理员确认后，才可以生效。同时 project token 可以 revoke，并且有默认的有效期。 默认有效期 14 天。
payload 必含 ts + nonce + path + method。

### 8. 运维密码 recovery / 备份机制

Shamir m-of-n unseal 的密钥来做 Revovery 和数据恢复。避免运维忘记密码 / 离职，正库不可解密。

### 9、cortex-cli daemon 的 device authorization 启动 daemon

借鉴 OAuth 2.0 **Device Authorization Grant** (RFC 8628)，配合本地 Ed25519 keypair，实现"运行命令 → 浏览器 SSO → 自动落地"的现代体验。类似 **gh / gcloud / aws sso** 的 cli 验证流程。

cortex-cli daemon login 时， 用户输入 agent-id，然后发起 device authorization 流程，产生 user_code，输出链接，提示用户登陆 cortex server 后台，打开页面，输入 code 来授权，授权时可以看到 hostname, agent-id, key fingerprint, 允许访问的 namespace 等信息，确认审核通过，还是拒绝。

payload 必含 ts + nonce + path + method。

- ✅ 新增 `cortex daemon login`、`cortex daemon logout`、`cortex daemon status`
- ✅ Server 新增：`/device/authorize`、`/device/token`、`/device`、`/web/device/approve`、`/devices`、`/auth/oidc/*`
- ✅ Server 新增：`pending_devices` 表

 **9.1 `POST /device/authorize`（机器对机器）**

**请求**：

```
{  "agent_pub": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",  "hostname": "alice-mbp",  "os": "darwin-arm64",  "cli_version": "0.2.0",  "init_proof": "<base64 Ed25519 sig over `device-init|<nonce>|<unix_ts>`>",  "init_nonce": "<base64 32B random>",  "init_ts": 1714200000}
```

**Server 端校验**：

- `init_proof` 是用 `agent_pub` 对应的 priv 签的（**自证持私钥**，防止有人盗用别人公钥来注册）
- `init_ts` 在 ±60 秒
- `agent_pub` 不在已登记表里（同一公钥只能登记一次）

**响应**：

```
{  "device_code": "GhT3pX...8a",                       // 不可见，daemon 持  "user_code": "WXYZ-1234",                            // 用户念给浏览器  "verification_uri": "https://cortex.example.com/device",  "verification_uri_complete": "https://cortex.example.com/device?user_code=WXYZ-1234",  "expires_in": 600,  "interval": 5,  "server_pub_fingerprint": "SHA256:11qY...AaPcHURo"   // 关键：CLI 当场 pin}
```

 **9.2 `POST /device/token`（机器对机器，daemon 轮询）**
`poll_proof` 让"持私钥的人"才能换 token，防止有人偷了 device_code 截胡。

**请求**：

```
{  "device_code": "GhT3pX...8a",  "poll_proof": "<Ed25519 sig over `poll|<device_code>|<unix_ts>`>",  "poll_ts": 1714200030}
```

`poll_proof` 让"持私钥的人"才能换 token，防止有人偷了 device_code 截胡。

**响应（pending）**：

```
{ "error": "authorization_pending" }
```

**响应（速率过快）**：
```
{ "error": "slow_down" }    // daemon 把 interval 加倍
```

**响应（已批准）**：

```
{
  "agent_id": "agent-alice-mbp-3f4a",
  "namespace": "team-a",
  "allowed_projects": ["my-app", "translator"],
  "server_pub": "<base64 32B Ed25519 公钥>",
  "server_pub_fingerprint": "SHA256:11qY...AaPcHURo",
  "issued_at": 1714200120,
  "user": { "sub": "alice@example.com", "name": "Alice" }
}
```

**响应（拒绝/过期）**：

```
{ "error": "access_denied" }       // 用户在 web 点了 Deny
{ "error": "expired_token" }       // 10 分钟没批
```

 **9.3 GET /device（Web 页，给人用）**
让用户输入 user_code（如果没带 query 参数）
重定向到 SSO（如果未登录）
显示设备信息卡：hostname、key fingerprint、namespace 选择、project 选择
大字号显示 fingerprint，让用户回终端核对

**9.4 POST /web/device/approve（Web 表单提交）**
请求（已在 SSO 会话内）：

{
  "user_code": "WXYZ-1234",
  "namespace": "team-a",
  "allowed_projects": ["my-app", "translator"]
}
Server 行为：

校验 SSO session 仍有效
校验 user_code 处于 pending、未过期
把 pending_devices 那行更新为 approved
写入"用户 X 批准了设备 Y、key fingerprint Z" 的审计 log（链式 MAC）
返回成功页"✓ Authorized. You can return to the terminal."


 **9.5. `GET /devices`（用户管理 Web 页）**

让用户看到自己名下所有已批准的设备：

- hostname、key fingerprint、enrolled_at、last_used_at、namespace
- 每行一个 **Revoke** 按钮 → `DELETE /devices/{agent_id}`

**9.6、Device Authorization 的安全细节（每个都很关键）**

##### ① "自证持私钥"的 init_proof

```
init_proof = Ed25519-Sign(agent_priv, "device-init"||nonce||ts)
```

**为什么**：防止恶意 daemon 用别人泄漏的公钥来注册——签名挑战让"持公钥"必须等于"持私钥"。

##### ② Fingerprint 双向 pin

- CLI **打印** fingerprint 让用户在 web 页核对（防被 MITM 替换公钥）
- Web 页**显示** fingerprint 让用户对照（防被 MITM 替换设备）
- daemon **再次校验** server_pub fingerprint 与第 ⑤ 步一致（防 server_pub 被中间人替换）

这是 SSH `ssh-add` 与 GitHub SSH key fingerprint 的同一思路。

##### ③ user_code 的字符集

```
user_code 字符集：BCDFGHJKLMNPQRSTVWXZ + 0123456789（去掉 0/O、1/I/l 等易混字符）长度：8 字符（4-4 分组 "WXYZ-1234"）熵：~36 bit
```

绝不能用 base64——用户念出来要不歧义。

##### ④ device_code 的属性

- 256 bit 随机
- TTL 10 分钟
- 用一次即销毁
- 只通过 HTTPS 传输

##### ⑤ poll_proof 防截胡

即使有人通过 `tcpdump` 偷到了 device_code，没有 agent_priv 也无法凭它换 token。

##### ⑥ Approval 显示的关键信息

Web 页授权时**必须**显示：

- 设备 hostname、IP（最后一跳）、地理位置（GeoIP 可选）
- agent_pub fingerprint（让用户对终端核对）
- 当前登录的 SSO 用户身份
- ⚠️ 如果终端不是你启动的，**不要 approve**（钓鱼防御提示）

##### ⑦ 频率限速

- 同 IP `/device/authorize` 1 次/分钟
- 同 device_code `/device/token` 至少 5 秒间隔，slow_down 加倍
- 每用户 24 小时内最多新增 5 台设备, per-user_code 连续6次错误锁定
— 同一个 user_code 被并发 POST /web/device/approve 时是否互斥, 需要 SELECT … FOR UPDATE。

##### ⑧ 设备生命周期

- 默认 90 天未使用自动 disable
- Disable 后必须 Web 端重新 approve（不删 keypair，只 toggle 状态）
- DELETE 才真删，对应 agent_pub 被列入 revocation

##### ⑨ Server 公钥轮转

- JWKS 端点 `GET /.well-known/jwks.json` 暴露多版本：
    
    ```
    { "keys": [    { "kid": "2024-q2", "alg": "EdDSA", "x": "..." },    { "kid": "2024-q3", "alg": "EdDSA", "x": "..." }]}
    ```
    
- daemon 每 24 小时同步一次 JWKS
- 新 token header 用新 kid，旧 token 验签兜底用旧 kid，平滑过渡
---
 
 **9.7、命令行 UX 细节**

### 主路径
```
$ cortex daemon login --agent-id <agent-id> --url https://cortex.example.com

▸ Generating Ed25519 keypair...
✓ Public key fingerprint:
    SHA256:8e1f4a3c7b2d9f8e0a5c1d3e6b8f9a2c

▸ Requesting authorization from server...
✓ Server fingerprint pinned:
    SHA256:11qY...AaPcHURo

▸ Open this URL in your browser to authorize this device:

    https://cortex.example.com/device?user_code=WXYZ-1234

  Or enter code manually at https://cortex.example.com/device:

    ┌──────────────┐
    │  WXYZ-1234   │
    └──────────────┘

  (Browser opens automatically. Press Ctrl+C to cancel.)

  ⚠ Make sure the fingerprint shown in your browser matches:
      SHA256:8e1f4a3c7b2d9f8e0a5c1d3e6b8f9a2c

▸ Waiting for authorization...      [10:00 ⠧]
✓ Authorized by alice@example.com
✓ Agent ID:   agent-alice-mbp-3f4a
✓ Namespace:  team-a
✓ Projects:   my-app, translator

▸ Starting daemon at ~/.cortex/agent.sock ... done.
```

 **Headless / SSH session**

检测到无 GUI（无 `DISPLAY` / `WAYLAND_DISPLAY`、stdin 不是 tty 的 SSH 等）时：
```
$ cortex daemon login --no-browser

✓ Public key fingerprint:
    SHA256:8e1f4a3c7b2d9f8e0a5c1d3e6b8f9a2c

▸ This terminal cannot open a browser. Authorize on another device:

    https://cortex.example.com/device?user_code=WXYZ-1234

  ▒▒▒▒▒▒▒  ▒▒  ▒▒▒▒▒▒▒
  ▒     ▒  ▒▒▒  ▒     ▒    ← 终端 QR code (qrcode crate)
  ▒ ▒▒▒ ▒  ▒  ▒ ▒ ▒▒▒ ▒
  ▒ ▒▒▒ ▒  ▒  ▒ ▒ ▒▒▒ ▒
  …

  WXYZ-1234

▸ Waiting...
```

### 标志位

```
cortex daemon login
    --url <https://...>              # cortex-server 地址
    --no-browser                     # 不自动开浏览器，仅打印 URL
    --device-name <hostname>         # 重命名（默认从 OS）
    --agent-id <agent-id>
    --namespace <name>               # 预选 namespace（仍需 web 端确认）
    --json                           # 输出 JSON 给脚本用
```


###  详细审计日志

每次 secret 使用都记录：

时间、agent_id、project、resource_path

调用方 PID、binary sha256、argv hash、cwd、git commit

网络源 IP / hostname / OS

用 audit_mac_key（HKDF 派生）做链式 MAC，防内鬼篡改

日志中记录把链尾 hash ； 或者定期推到外部锚点（Git 仓库 commit）

### Honey-token

在 secret 库里故意放几条永远不会被合法使用的 secret：

legacy_aws_root_key = "AKIA-FAKE-..."

internal_kafka_password = "FAKE..."

任何取这些 secret 的请求 = 100% 攻击信号，立即告警 + 立即冻结调用方 agent。

### cortex-cli run xxxxx 运行一个项目的时候，自动注入各种需要的 API_Key， API_KEY 需要通过 HTTPS 接口从 cortex server 来拿到。 避免 AI Agent 也能通过类似的方法拿到各种 API_KEY

**根本困境**：在同一台机器上，Agent 进程和 `cortex-cli` 进程是**同一个 UID**。它们对 OS 而言是无差别的：

- 都能读 `~/.cortex/config.toml`
- 都能 connect 到 `~/.cortex/agent.sock`
- 都能发 HTTPS 请求到 cortex-server
- 都能 `ptrace` 同 UID 的进程
- 都能读 `/proc/<pid>/environ`

**不要试图"挡住 agent"——而是要让 cortex-cli 拥有一个"agent 拿不到的能力"，并且让 secret 永远只走那个能力。**

**Daemon 提供"动作 API"，不提供"读取 API"**

把 daemon 的对外接口（Unix socket）设计成**只能"用"，不能"拿"**：

```
~/.cortex/agent.sock 暴露的方法：

✅ run(project, scope, argv) → daemon fork() + 注入 env + execve(argv)
                              → 返回子进程 PID/exit code/stdout/stderr handle
                              → 全程 secret 不离开 daemon 与 child 的内存

✅ inject_template(project, scope, template_path, output_path)
                              → daemon 渲染模板写文件（再 chmod 600）
                              → 返回 ok/fail，永不返回内容

✅ ssh_proxy(host)            → daemon 充当 SSH agent，私钥不出 daemon

❌ NO get_secrets(project)    ← 完全不存在这个 API
❌ NO get_secret(name)        ← 完全不存在
```

关键变化：
```
之前：
  HTTP 服务端 ─[plaintext]→ cortex-cli ─[env via exec]→ child
                              ↑
                          agent 可以做同样请求

之后：
  HTTP 服务端 ─[plaintext]→ daemon ─[env via exec]→ child
                              ↑
                          agent 即使骗 daemon 也只能让它去 exec
                          agent 自己向 server 发 HTTPS：
                          → 但服务端验签时拒绝
```

cortex-cli run 项目的时候，调用 cortext-cli deamon run {project} 来注入变量启动项目。

**服务端配套限制**
* cortex-server 也要变：**不再发"返回 env 字典"的 plaintext 端点**
* 真正读 secret 的请求需要带**额外的 daemon attestation header**

#### 在 Unix socket 上做 Peer Credential 检查

Linux 有 `SO_PEERCRED`、macOS/BSD 有 `getpeereid()`，可以在 daemon 端拿到**对面那个进程的真实 PID**，然后：

``` rust
// daemon 端（pseudocode）
fn handle_connection(sock: UnixStream) {
    let cred = sock.peer_cred()?;          // SO_PEERCRED
    let pid  = cred.pid;
    let uid  = cred.uid;
    
    if uid != current_uid() { return reject(); }
    
    // 关键：解析对面进程的可执行文件
    let exe_path = std::fs::read_link(format!("/proc/{}/exe", pid))?;
    let exe_hash = sha256_file(&exe_path)?;
    
    // 验证 cortex-cli 自身的二进制 hash
    if !ALLOWED_CALLER_HASHES.contains(&exe_hash) {
        audit("rejected non-cortex-cli caller", pid, exe_path);
        return reject();
    }
    
    // 还可以检查父进程链：
    // 是否在某个 sandbox 内、是否被 strace 附着等
    
    handle_request(sock);
}
```

`ALLOWED_CALLER_HASHES` 是 cortex-cli 自身二进制的哈希——daemon 启动时计算 `cortex-cli` 的 sha256，注册为白名单（或在 daemon 二进制里编译进去）。

#### 把"不该有的口子"关掉

1. ❌ **从服务端删除 `GET /project/secrets/<name>` 这个返回 plaintext 的端点的"裸 token 即可访问"模式**
2. ✅ 改成"只接受带 `daemon_attestation` header 的请求"——daemon 在请求中签一段挑战，证明自己是合法 daemon
3. ✅ daemon Unix socket 加 `SO_PEERCRED` 校验调用方 UID + 二进制 hash
4. ✅ cortex-cli 启动检查 `LD_PRELOAD` 等并 abort
5. ✅ daemon 进程 `prctl(PR_SET_DUMPABLE, 0)`、Linux 上推荐设 `kernel.yama.ptrace_scope=2`

> **把"agent 用 curl 直接拿 secret"这个最大的漏洞补上**。

### cortex server "只接受带 `daemon_attestation` header 的请求"——daemon 在请求中签一段挑战，证明自己是合法 daemon

daemon 和 agent 同 UID，凡是 daemon 能从某处读出来的东西，agent 也能从同一处读出来。所以 attestation 必须建立在**只有 daemon 这个进程实例当时才拥有的某个东西**之上。

 **一、目标定义**

让 cortex-server 拒绝**所有不是来自合法 cortex-agent daemon 的请求**，包括：

| 攻击者                                         | 做什么                          |
| ------------------------------------------- | ---------------------------- |
| AI agent 用 curl 直接打服务端                      | 没有合法 attestation header      |
| AI agent 偷 keyring （或文件）里的 agent_priv       | 即使签了 Ed25519 也不行             |
| AI agent 杀 daemon 后启动假 daemon               | 假 daemon 不能复现真 daemon 注册时的状态 |
| AI agent 重放真 daemon 的合法请求                   | 时间戳 + nonce 防重放              |
| AI agent ptrace daemon 内存抠出 attestation key | 通过 OS 配置阻断                   |

仅靠 `agent_priv` 不够——它躺在 keyring （或者文件里面） 里同 UID 都能拿。我们需要一把 **绝不出现在 keyring、绝不写盘、只活在 daemon 进程当前生命周期内** 的密钥，由它签每一次请求。

agent_priv 放哪? macOS Keychain / Linux Secret Service / 文件 + 0600， fallback 到文件上（设置600权限），Linux 上 Secret Service 通常依赖 GNOME-keyring 解锁,headless 服务器没有 GUI, 自动 fallback 避免卡住。

 **二、核心设计：双层密钥 + 短命会话**

```
┌────────────────────────────────────────────────────────────┐
│  长期身份层（已有）                                         │
│   agent_priv (Ed25519)                                      │
│   - 在系统 keyring                                          │
│   - 仅 daemon 启动时取一次                                  │
│   - 用途：登录、注册新会话、证明"我是 alice 这台机器"        │
└────────────────────────┬───────────────────────────────────┘
                         │ 启动时一次性"派生授权"
                         ▼
┌────────────────────────────────────────────────────────────┐
│  会话 attestation 层（新增）                                │
│   attestation_priv (Ed25519, 32 字节)                       │
│   - daemon 启动时随机生成                                   │
│   - 永不写盘 / 永不进 keyring                                │
│   - mlock 内存 + 进程死亡即消失                             │
│   - daemon 重启 = 新一把 attestation_priv = 新会话           │
│   用途：签每一个 outbound 请求                              │
└────────────────────────────────────────────────────────────┘
```

**为什么要分两层**：

- `agent_priv` 长期凭据，泄漏代价高、难以频繁轮转
- `attestation_priv` 短命凭据，**与 daemon 的"这次启动"绑定**，daemon 重启或被杀立刻失效；偷它没意义

 **三、Bootstrap：daemon 启动时一次性注册**

```
┌──────────────┐                                ┌─────────────┐
│ cortex-agent │                                │ cortex-srv  │
│   daemon     │                                │             │
└──────┬───────┘                                └──────┬──────┘
       │                                                │
       │ ① 命令行 拉起                                │
       │                                                │
       │ ② 进程硬化（必须先做！）                       │
       │   - prctl(PR_SET_DUMPABLE, 0)                  │
       │   - mlockall(MCL_CURRENT|MCL_FUTURE)           │
       │   - prctl(PR_SET_NO_NEW_PRIVS, 1)             │
       │   - 检查 LD_PRELOAD 等为空，否则 abort         │
       │                                                │
       │ ③ 从 keyring 取 agent_priv                    │
       │   （Touch ID / 系统密码解锁）                   │
       │                                                │
       │ ④ 当场随机生成 attestation_keypair           │
       │   attestation_priv, attestation_pub            │
       │   立刻 mlock                                   │
       │                                                │
       │ ⑤ 计算自身环境指纹：                           │
       │   - daemon_binary_sha256 (读 /proc/self/exe)   │
       │   - boot_id (/proc/sys/kernel/random/boot_id)  │
       │   - hostname / uid / pid / started_at_unix     │
       │                                                │
       │ ⑥ 构造 init payload，agent_priv 签            │
       │   payload = {                                  │
       │     agent_id: "agent-alice-mbp-3f4a",          │
       │     attestation_pub: <32B base64>,             │
       │     daemon_binary_sha256: <hex>,               │
       │     boot_id: <uuid>,                           │
       │     daemon_pid: <int>,                         │
       │     started_at: <unix_ts>,                     │
       │     hostname: "alice-mbp",                     │
       │     nonce_init: <random 32B>                   │
       │   }                                            │
       │   sig_init = Ed25519-Sign(agent_priv,           │
       │              canonical_json(payload))           │
       │                                                │
       │ ⑦ POST /daemon/attest                          │
       │   {payload, sig_init}                          │
       ├───────────────────────────────────────────────►│
       │                                                │
       │                                                │ ⑧ 服务端：
       │                                                │  a. 查 agent_pub by agent_id
       │                                                │  b. Ed25519 验签 sig_init
       │                                                │  c. 校验 nonce_init 未见过
       │                                                │  d. 校验 daemon_binary_sha256
       │                                                │     ∈ allowed_daemon_versions
       │                                                │     （服务端维护一张白名单，
       │                                                │      由 cortex 项目签名发布）
       │                                                │  e. 校验同 agent_id 没有
       │                                                │     太频繁的重新注册
       │                                                │     （比如 30 秒内 3 次→ 拒绝）
       │                                                │  f. 写库：daemon_sessions(
       │                                                │       session_id (UUID),
       │                                                │       agent_id,
       │                                                │       attestation_pub,
       │                                                │       boot_id,
       │                                                │       daemon_pid,
       │                                                │       started_at,
       │                                                │       expires_at: now+8h,
       │                                                │       status='active')
       │                                                │  g. 写 audit log
       │                                                │
       │ ⑨ 200 OK                                       │
       │   { session_id: <uuid>,                        │
       │     server_nonce: <random 32B>,                │
       │     expires_at: <ts> }                         │
       │◄───────────────────────────────────────────────┤
       │                                                │
       │ ⑩ daemon 持久化到内存：                        │
       │   DaemonSession {                              │
       │     attestation_priv,                          │
       │     attestation_pub,                           │
       │     session_id,                                │
       │     server_nonce,                              │
       │     expires_at                                 │
       │   }                                            │
       │   ↑ 全在 mlock 内存                            │
       │                                                │
       │ ⑪ 进入主事件循环，开始接受 IPC                  │
```

 **几个关键校验点**

**daemon_binary_sha256 白名单**：cortex 项目维护一份"已知合法 daemon 二进制"清单，由项目 release 私钥签名。服务端把这份列表加载到内存。**任何 agent 想自己编译"假 daemon"上来注册都会因为 hash 不匹配而被拒**。这把"信任 daemon 二进制"提升到密码学层面。

**boot_id 校验**：`/proc/sys/kernel/random/boot_id` 是 Linux 内核维护的 UUID，**每次系统启动都会变**。如果攻击者想把同一台机器在不重启的情况下"看起来"是新启动，骗不过这个值。同 boot_id 内同 agent_id 注册多次 → 服务端按"daemon 重启"处理（旧会话失效）。

同 daemon 多次 attest，旧 session 立刻 invalidate,新 attest 唯一 active,避免幽灵会话。

**频率限速**：30 秒内同 agent_id 重注册 3 次以上 → 拒绝 + 告警。这挡住"agent 反复 kill daemon 重启抢注册时机"的攻击。

## 四、每请求的 attestation header

之后 daemon 调任何敏感端点，都附带一个签名 header：
```
POST /project/token HTTP/1.1
Host: cortex.example.com
Authorization: Bearer <session_token>
X-Daemon-Attestation: eyJwYXlsb2FkIjp7Imp0aSI6Ii4uLiIsInRzIj...
Content-Type: application/json
Content-Length: 187

{"project":"my-app","scope":["secrets:read:OPENAI_API_KEY"]}
```

`X-Daemon-Attestation` header 内容是 base64 编码的 JSON：
```
{
  "payload": {
    "session_id":   "78be1c5e-...-9f4a",
    "ts":           1714200120,
    "jti":          "rand-128-bit-base64",
    "method":       "POST",
    "path":         "/project/token",
    "body_sha256":  "8e1f4a3c7b2d9f8e0a5c1d3e6b8f9a2c...",
    "auth_token_id": "<jti of Authorization Bearer token>"
  },
  "sig": "<Ed25519-Sign(attestation_priv, canonical_json(payload))>"
}
```
### 服务端验证清单（每条都不能省）
```
1. 解 header → payload + sig
2. 查 daemon_sessions WHERE session_id = payload.session_id AND status='active'
   → 拿到 attestation_pub 和 expires_at
3. Ed25519-Verify(attestation_pub, canonical_json(payload), sig)  ← 必须常时
4. 检查 payload.expires_at > now
5. 检查 |payload.ts - now| ≤ 60 秒（防重放，防时钟漂移攻击）
6. 检查 (session_id, jti) 不在最近 5 分钟的 nonce 缓存里 → 否则拒绝
7. 检查 payload.method == 当前请求的 method
8. 检查 payload.path == 当前请求的 path（含 query string）
9. 计算实际 body 的 SHA-256，与 payload.body_sha256 一致
10. 检查 payload.auth_token_id 与 Authorization 头里的 JWT.jti 一致
    （绑定 attestation 和 session_token，不能拼接两个不同请求）
11. 把 (session_id, jti) 写入 nonce 缓存，ttl=5min
12. 写 audit_log：哪个 session、哪个动作、哪个 binary
```

**为什么要绑 method、path、body_sha256**：防止有人偷了一段合法 attestation header 拿到别处用。每条 attestation 只能配它对应的那个具体请求。

**为什么要绑 auth_token_id**：防止 attestation 与 Authorization 头被分别截获再交叉拼接。

 **系统配置（部署时一次性）**

```
# /etc/sysctl.d/99-cortex.conf
kernel.yama.ptrace_scope = 2     # 仅同 namespace 内 root 可 ptrace；同 UID 不行kernel.dmesg_restrict = 1fs.protected_hardlinks = 1
fs.protected_symlinks = 1
```

`ptrace_scope=2` 是关键——这一行让 agent 即使同 UID 也**不能** ptrace daemon。

 **systemd unit 加固**

```
[Service]ExecStart=/usr/bin/
```

### macOS

```
// PT_DENY_ATTACH 拒绝 ptraceextern "C" {    fn ptrace(request: i32, pid: i32, addr: *mut u8, data: i32) -> i32;}const PT_DENY_ATTACH: i32 = 31;unsafe { ptrace(PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0); }
```

> **Daemon attestation 的本质**是给"daemon 这次启动"造一把**生于内存、死于内存**的临时密钥，让服务端可以验证：每个进来的请求**确实**是从这个具体进程发出来的、**确实**没被改过、**确实**不是 5 分钟前的重放。

> **它的安全性建立在两件事**：
> 
> 1. **OS 级进程隔离**（`mlock` + `PR_SET_DUMPABLE=0` + `ptrace_scope=2`）—— 让 attestation_priv 不被同 UID 的 agent 抠出
> 2. **服务端二进制 hash 白名单** —— 让 agent 不能自己编译"假 daemon"上来注册
> 
> 两者任何一项失守，整套体系就退化成"普通 Ed25519 签名 + 重放保护"，agent 偷到密钥仍能伪造。所以**部署时 systemd 配置和 sysctl 设置和密码学算法一样重要**。