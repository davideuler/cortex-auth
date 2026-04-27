# CortexAuth — Items Needing Confirmation

This document records design decisions and open questions that require stakeholder input.

---

## 1. Token Recovery Strategy

**Issue**: When a project is re-discovered (POST /agent/discover for an existing project), the original `project_token` cannot be returned because only its SHA-256 hash is stored. The current behavior returns `__existing__:<project_id>` as the token value, which is not a usable token.

**Question**: What should happen on re-discovery of an existing project?
- Option A: Always regenerate the token (current behavior when `regenerate_token: true`)
- Option B: Return a sentinel indicating "project already registered — use your saved token or pass `regenerate_token: true`"
- Option C: Store the token encrypted rather than hashed (allows recovery but is a security trade-off)

**Current behavior**: Returns `__existing__:<id>` sentinel when project exists and `regenerate_token` is not set.
Option A is OK.

---

## 2. Agent Policy Enforcement

**Issue**: The policy system stores `agent_pattern`, `allowed_paths`, and `denied_paths`, but the current Agent API endpoints **do not enforce policies** when fetching secrets. Policies are stored but not consulted at access time.

**Question**: Should policy enforcement be implemented?
- The data model is in place, but the enforcement logic (glob pattern matching on agent_id, path checking) is not wired into `/agent/secrets` and `/agent/config` handlers.
- If yes: agent session tokens from `/agent/authenticate` would need to carry the agent_id and be validated against matching policies on each request.
Yes.

---

## 3. Session Token vs Project Token

**Issue**: There are currently two separate auth flows:
1. Agent auth flow: `jwt_secret` → session_token (1-hour expiry)
2. Project flow: `project_token` (no expiry, permanent until regenerated)

The session_token from agent authentication is not currently used to gate `/agent/secrets` or `/agent/config`. Only the `project_token` is used there.

**Question**: Should agent authentication be required before accessing project secrets?
- Combined flow: agent authenticates first, then uses session_token + project_token together?
- Separate flows: agents and projects are independent auth concerns?
Agent and projects are independant auth concerns.
The /discover api should be called by agent with session token.

---

## 4. Secret Namespace / Access Control

**Issue**: Currently, any project with a valid `project_token` can be mapped to ANY secret in the vault via the discover flow. There is no per-secret access control.

**Question**: Should secrets be namespaced or tagged with which projects/agents can access them?
- This would prevent one project from being mapped to secrets it shouldn't see.
Yes, put a namespace for secret. and also a namespace for project/agent too.

---

## 5. Encryption Key Rotation

**Resolved**. The data model is now envelope-encrypted (per-row DEKs wrapped by an in-memory KEK).
`POST /admin/rotate-key {"new_kek_password": "..."}` re-derives the KEK from a new operator
passphrase, re-wraps every DEK, and bumps `kek_version`. Body ciphertexts are untouched, so
rotation is O(rows wrapped) rather than O(rows re-encrypted). The server must be restarted with
the new passphrase afterward to pick up the new KEK in memory.

---

## 6. Scalability / Multi-Instance

**Issue**: SQLite with a single file does not support multiple concurrent writer instances. If the server needs to run as multiple replicas, a different database backend is needed.

**Question**: Is single-instance sufficient, or is horizontal scaling required?
- If scaling is needed: consider PostgreSQL backend (sqlx supports it with a feature flag change)
No, SQLite is OK currently.

---

## 7. cortex-cli Windows Support

**Issue**: `cortex-cli` uses `std::os::unix::process::CommandExt::exec()` which is Unix-only. The Windows equivalent is different.

**Question**: Is Windows support required?
- If yes: need to implement a Windows-compatible launcher (spawn child, wait, forward exit code)
No. Only Unix-only is supported.

---

## 8. TLS / HTTPS

**Resolved**. TLS is terminated in-process when both `TLS_CERT_FILE` and `TLS_KEY_FILE`
environment variables are set; otherwise the server falls back to plain HTTP for local dev.
Implementation uses `tokio-rustls` with PKCS8 private keys.

---

## 9. Audit Log Retention

**Resolved**. Audit logs are deleted after a rolling 60-day window. The cleanup task runs
once a day from `cortex-server/src/main.rs`. Every state-changing API call is logged,
including KEK rotation, namespace lifecycle, and honey-token alarms.

---

## 10. Project Token Scope (April 2026)

**Resolved**. Each `project_token` now carries an explicit `scope` — the set of secret
`key_path`s frozen on the project row at discover time. `/project/secrets` filters its
response to the scope; a leaked token cannot read anything outside its mint-time scope.
The token is still a SHA-256-hashed opaque random string (not yet a signed Ed25519 JWT
— see open question #14).

**Default TTL** raised from 120 minutes to **14 days** now that scope contains the blast
radius.

---

## 11. Tamper-Evident Audit Log (April 2026)

**Resolved**. Audit rows are HMAC-SHA256 chained: each row's `entry_mac` covers
`prev_hash || canonical_payload`, with the running tail MAC stored in `audit_mac_state`.
The MAC key is derived from the KEK using HMAC with a fixed domain separator
(`cortex-auth/audit-mac-v1`).

Audit rows also carry optional caller metadata (`caller_pid`, `caller_binary_sha256`,
`caller_argv_hash`, `caller_cwd`, `caller_git_commit`, `source_ip`, `hostname`, `os`)
populated from `X-Cortex-Caller-*` request headers.

**Open**:
- Verification CLI: a `cortex-cli verify-audit` subcommand that walks the audit log and
  recomputes each entry MAC to detect tampering would be high-value but is not yet built.
- External anchoring: the design suggests periodically pinning the chain tail to an
  external commit (e.g. a Git repo) so an internal admin who holds the audit MAC key
  cannot rewrite history. Not implemented.
- The CLI does not yet populate the `X-Cortex-Caller-*` headers, so audit rows from
  `cortex-cli run` only carry `source_ip` (when behind a proxy that sets `X-Forwarded-For`).

---

## 12. Honey Tokens (April 2026)

**Resolved**. Secrets carry an `is_honey_token` boolean. A read attempt against a
honey-token immediately:

1. Revokes the calling project's token (sets `token_revoked_at`).
2. Writes an `alarm`-status row to the audit log (`action="honey_token_access"`).
3. Returns a generic 401 to the caller.
4. Dispatches an outbound notification to every enabled channel.

**Outbound notifications (resolved April 2026)**: `notification_channels` table holds
envelope-encrypted channel configs managed via the dashboard's `Notifications` tab and
`POST /admin/notification-channels`. Channel types:

- `slack`   — incoming webhook
- `discord` — incoming webhook
- `telegram`— Bot API (`bot_token` + `chat_id`)
- `email`   — pipes the message to `himalaya-cli` on stdin (when on PATH)

Dispatch is fire-and-forget per channel in a tokio task; a slow webhook never blocks
the calling request handler. See `cortex-server/src/notifications.rs`.

**Still open**: severity filters / per-channel templating / retry-with-backoff. Today
every channel receives the same plain-text payload for both honey-token alarms and
recovery-boot events. Tracked under #20.

---


## 13. Ed25519 Agent Identity (April 2026)

**Resolved (basic)**. The migration `007_ed25519_and_devices.sql` adds an `agent_pub`
column to `agents`. Registration (`POST /admin/agents`) accepts either:

- `jwt_secret` (legacy HMAC-SHA256 path — preserved for backwards compatibility), and/or
- `agent_pub` (base64url-encoded Ed25519 public key — preferred).

When an agent has `agent_pub`, `/agent/discover` requires the request body to include
`ts` and `nonce` and verifies `auth_proof` as an Ed25519 signature over
`ts | nonce | agent_id | /agent/discover`. The ts must be within ±5 minutes of the
server clock (drop-replay window).

CLI:
- `cortex-cli gen-key --agent-id <id>` writes a private key to
  `~/.cortex/agent-<id>.key` (mode 0600) and prints the base64url public key on stdout.
- `cortex-cli sign-proof --agent-id <id> --priv-key-file <path>` prints a JSON
  `{ts, nonce, auth_proof}` ready to splice into the discover body.

**Still open**:
- Forward migration: a campaign that asks every existing HMAC agent to upload a public
  key, then purges the encrypted HMAC secret. Today both credentials can coexist on the
  same row.
- Replay nonce caching (an LRU of `(agent_id, nonce)` for the 5-minute window) — the
  current path only enforces the timestamp bound. Tracked in NEXT_STEPS #4.

---

## 14. Signed Ed25519 Project Tokens (April 2026)

**Resolved (basic)**. The migration adds `server_keys` (envelope-encrypted server signing
key) and `revoked_token_jti`. On first boot the server generates an Ed25519 keypair,
stores it sealed under the KEK, and exposes the public key at
`GET /.well-known/jwks.json` (kid-versioned).

`POST /agent/discover` accepts `signed_token: true`. When set, the response carries an
EdDSA-signed JWT in `signed_project_token` alongside the legacy random `project_token`.
Claims: `{iss, sub, aud, iat, exp, jti, scope, namespace, project_id}`. Both formats are
accepted on `/project/*` — the verification path branches on whether the bearer token has
3 dot-separated segments (JWT) or not (legacy hex hash compare).

Revocation is via `revoked_token_jti` (checked on every signed-token request). The
`/admin/projects/<name>/revoke` endpoint also continues to set `token_revoked_at` for the
legacy path.

**Still open**:
- Insert a `revoked_token_jti` row when an admin revokes a project — today only legacy
  tokens are revoked; signed JWTs are revoked only by setting `exp` past or by waiting
  for natural expiry. The migration column exists; wiring the admin handler is small but
  not yet done.
- Body-replay protection (`ts + nonce + path + method` covered by an HMAC over the
  bearer) — the design calls for this on every request; today only the discover path
  uses ts/nonce.

---

## 15. Shamir m-of-n Unseal Recovery (April 2026)

**Resolved**. The `sharks` crate provides a `(m, n)` Shamir split/recover primitive.

- `POST /admin/shamir/generate {threshold, shares}` splits the *running* KEK into n
  shares with threshold m and returns them once. The server retains nothing; the
  response carries a `warning` field telling the operator to distribute immediately.
- `CORTEX_RECOVERY_MODE=1 CORTEX_RECOVERY_THRESHOLD=<m>` boots in recovery mode. The
  server prompts for m shares interactively on stdin (echo disabled via `rpassword`),
  reconstructs the KEK, verifies the on-disk sentinel, and either succeeds or refuses to
  bind the listener.
- A successful recovery boot writes an `alarm`-status `recovery_boot` row to the audit
  log and dispatches notifications to every enabled channel (#12).

See `cortex-server/src/shamir.rs` and `cortex-server/src/kek.rs::unseal_via_recovery`.

**Still open**:
- Multi-file share input (today: stdin only) — operators sometimes prefer dropping share
  files into a directory. Easy to add as a fallback.
- Restoring the KEK *and* the operator password — the current recovery boot only puts
  the KEK back in memory; rotating to a fresh password requires running
  `POST /admin/rotate-key` from the recovered instance.

---

## 16. cortex-cli Daemon + Device Authorization (April 2026)

**Resolved (basic)**. Server-side endpoints + scaffolding daemon + dashboard UI:

Server endpoints (in `cortex-server/src/api/agent.rs` + `admin.rs`):
- `POST /device/authorize`            — issues `device_code` + `user_code` (10 min TTL).
- `POST /device/token`                — daemon polls; returns `authorization_pending`
  until approved, then mints an EdDSA JWT access token bound to the agent_id.
- `GET  /device`                      — minimal HTML approval form.
- `POST /admin/web/device/approve`    — admin-token-gated approval (binds user_code → agent_id).
- `GET  /admin/devices`               — list pending + enrolled devices.
- `DELETE /admin/devices/:agent_id`   — revoke a device.

CLI (`cortex-cli daemon login | status | logout`) implements the OAuth 2.0 device-grant
client flow, persisting the access token at `~/.cortex/daemon-session.json` (mode 0600).

`cortex-daemon` (separate binary in the cortex-cli crate) listens on
`~/.cortex/agent.sock` (mode 0600) with a single-line JSON protocol:

- `{"cmd":"status"}` → returns the cached daemon-session JSON.
- `{"cmd":"run","program":..,"args":..,"project":..,"token":..,"url":..}` → fetches
  secrets, spawns the program with the env vars injected, returns
  `{"ok":true,"exit_code":N}` after the child exits. The raw secret values never travel
  back over the socket.

**Still open**:
- SSO integration at `/auth/oidc/*` — today device approval is admin-token-gated, not
  user-bound.
- Frequency limits (1 authorize/min/IP, 5 devices/user/day) — rate limiting is generally
  absent; tracked under NEXT_STEPS #3.
- `inject_template` and `ssh_proxy` socket commands.
- Daemon attestation (#17 below).
- OS-level hardening: `prctl(PR_SET_DUMPABLE, 0)`, `mlockall`, sysctl
  `kernel.yama.ptrace_scope=2`, `MemoryDenyWriteExecute=yes`, `PT_DENY_ATTACH` on macOS.

---

## 17. Daemon Attestation Header (deferred)

**Design intent (UPDATED_DESIGN.md §"daemon attestation header")**: After the daemon
logs in, it generates a per-process `attestation_priv` (Ed25519, never written to disk)
and registers `attestation_pub` with the server via `POST /daemon/attest`. Every
sensitive request afterwards must carry an `X-Daemon-Attestation` header signed by
`attestation_priv` covering `(session_id, ts, jti, method, path, body_sha256,
auth_token_id)`. The server checks the binary SHA-256 against an allowed-daemon-versions
whitelist on attestation, and only sessions backed by approved binaries can read secrets.

**Status**: NOT IMPLEMENTED. Depends on #16 (the daemon must exist first). Needs:
- New `daemon_sessions` table.
- New `allowed_daemon_versions` table populated from a project-signed release manifest.
- Per-request attestation verification middleware.
- Replay protection (5-minute jti cache).
- OS-level hardening guidance: `prctl(PR_SET_DUMPABLE, 0)`, `mlockall`, sysctl
  `kernel.yama.ptrace_scope=2`, systemd unit `MemoryDenyWriteExecute=yes`,
  `PT_DENY_ATTACH` on macOS.

---

## 18. Multi-User RBAC for Admins (deferred)

**Design intent (UPDATED_DESIGN.md §4)**: Replace the single static `ADMIN_TOKEN` with
multi-user accounts where each admin has a namespace scope. Super-admins can manage all
namespaces; regular admins only their own.

**Status**: NOT IMPLEMENTED. Today the `ADMIN_TOKEN` is a single shared bearer token
checked by `check_admin_token()`. Migrating requires:
- `admin_users` table (id, email, password_hash via Argon2id mid-tier, namespace_scope,
  is_super, created_at).
- `/auth/login` and session cookie / OIDC integration.
- All admin handlers gated by namespace scope check.
- Migration story for the bootstrap super-admin.

---

## 19. JWKS Endpoint for Server Public Key Rotation (deferred)

Tied to #14. Once project tokens are Ed25519-signed, the server's signing key needs to
rotate without breaking in-flight tokens. The standard answer is JWKS at
`GET /.well-known/jwks.json` with `kid` versioning. Daemons cache JWKS for 24 hours.

---

## 20. Honey-Token Outbound Alerting (April 2026)

**Resolved (basic)** — see #12. Slack / Discord / Telegram / email-via-himalaya channels
are now implemented and dispatched on every honey-token access (and on Shamir recovery
boots — #15).

**Still open**:
- Per-namespace channel mapping (today every channel receives every event).
- Severity filters so a slack channel can opt into honey-token alarms but not
  recovery-boot pages.
- Per-channel payload templating (today every channel gets the same plain-text body).
- Retry / exponential backoff (today a single attempt; failures land in `tracing::warn!`).

---

## 21. CLI Caller Metadata Headers (deferred)

The server accepts `X-Cortex-Caller-Pid`, `X-Cortex-Caller-Binary-SHA256`,
`X-Cortex-Caller-Argv-Hash`, `X-Cortex-Caller-Cwd`, `X-Cortex-Caller-Git-Commit`,
`X-Cortex-Hostname`, `X-Cortex-Os` and stores them on the audit row. The current
`cortex-cli` does not populate them yet — when added it should:

- compute its own SHA-256 from `/proc/self/exe` (Linux) or `_NSGetExecutablePath()` (macOS);
- hash `argv` so the audit row records *which* invocation;
- read the cwd and `git rev-parse HEAD` if a `.git` directory is present;
- include hostname and `uname -s -m`.

These fields are advisory — a malicious caller can lie — but combined with the source
IP and signed `project_token`/`auth_proof` they make forensic post-mortem dramatically
faster.
