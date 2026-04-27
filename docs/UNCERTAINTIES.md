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

## 11. Honey Tokens (April 2026)

**Resolved (basic)**. Secrets carry an `is_honey_token` boolean. A read attempt against a
honey-token immediately:

1. Revokes the calling project's token (sets `token_revoked_at`).
2. Writes an `alarm`-status row to the audit log (`action="honey_token_access"`).
3. Returns a generic 401 to the caller.

**Open**: Outbound notifications. The current implementation logs via `tracing::warn!` and
the audit log; it does not page on-call. Stakeholder decision needed on whether to wire a
webhook / PagerDuty / e-mail integration.

---

## 12. Tamper-Evident Audit Log (April 2026)

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

## 13. Ed25519 Agent Identity (deferred)

**Design intent (UPDATED_DESIGN.md §9)**: Replace the current HS256 JWT auth (where the
agent's `jwt_secret` lives encrypted in the DB and the agent must prove possession of it)
with Ed25519 keypairs. The agent generates `(priv_a, pub_a)` locally and only uploads
`pub_a`; auth proofs are Ed25519 signatures over `ts || nonce || agent_id || path`.

**Status**: NOT IMPLEMENTED. The current code still uses HMAC-SHA256 JWTs with shared
`jwt_secret`s encrypted in the DB (`agents.jwt_secret_encrypted`). Migrating requires:
- Adding `agent_pub` column to `agents` table.
- Switching `/agent/discover` validation from `jsonwebtoken::decode` to
  `ed25519_dalek::Verifier`.
- Updating `cortex-cli gen-token` to sign with a local private key instead of HS256.
- Coordinating a forward migration: existing agents need to upload a public key on first
  re-auth before their JWT secret is purged.

---

## 14. Signed Ed25519 Project Tokens (deferred)

**Design intent (UPDATED_DESIGN.md §7)**: Project tokens become Ed25519-signed JWTs of
the form `base64(claims) || base64(sig)` with claims `{iss, sub, aud, iat, exp, jti, scope,
namespace, project_id}`. A request body must include `ts + nonce + path + method` so an
intercepted token cannot be replayed against a different endpoint.

**Status**: NOT IMPLEMENTED. The token is still an opaque random string SHA-256 hashed
into `projects.project_token_hash`, but the `scope` claim is now stored alongside the
hash (#10). Migrating requires:
- Server keypair (`server_priv`, `server_pub`) generated/loaded at boot, sealed with the
  KEK at rest, mlocked in memory.
- A JWKS endpoint (`GET /.well-known/jwks.json`) for the server public key, with `kid`
  versioning so old tokens stay verifiable across rotations.
- Token issuance produces an EdDSA-signed JWT instead of a random hex string.
- Verification path replaces hash lookup with signature verification + revocation check
  against a `revoked_token_jti` table.

---

## 15. Shamir m-of-n Unseal Recovery (deferred)

**Design intent (UPDATED_DESIGN.md §8)**: To survive operator password loss, the KEK can
be reconstructed from a Shamir secret-sharing `(m, n)` set (e.g. 3-of-5). Each share is
distributed to a different operator at install time; on a recovery boot the server reads
m shares from stdin, reconstructs the KEK, and verifies the sentinel.

**Status**: NOT IMPLEMENTED. Decision needed on whether to depend on a Shamir crate
(`sharks`, `vsss-rs`) or vendor the implementation. Also: the recovery UX (interactive
prompt vs. multi-file) and audit/alarm story when the server boots in recovery mode.

---

## 16. cortex-cli Daemon + Device Authorization (deferred)

**Design intent (UPDATED_DESIGN.md §9)**: A long-running `cortex-daemon` process
authenticates once via the OAuth 2.0 Device Authorization Grant (RFC 8628), holds the
agent's Ed25519 private key in mlocked memory, and exposes a Unix socket
(`~/.cortex/agent.sock`) where `cortex-cli run` can ask it to "exec a command with these
secrets injected" — without ever returning the secret to the caller.

This protects against the AI-agent-on-the-same-UID problem: an agent process on the same
machine can connect to the socket and ask the daemon to run a known-good binary, but it
cannot extract raw secret material because the socket exposes only `run()` /
`inject_template()` / `ssh_proxy()`, never `get_secret()`.

**Status**: NOT IMPLEMENTED. A large body of work:
- `cortex-cli daemon login` / `logout` / `status` subcommands.
- Server endpoints: `POST /device/authorize`, `POST /device/token`, `GET /device`,
  `POST /web/device/approve`, `GET /devices`, `DELETE /devices/{agent_id}`.
- New `pending_devices` table and SSO integration at `/auth/oidc/*`.
- Web UI for the user-facing approval flow.
- Frequency limits (1 authorize/min/IP, 5 devices/user/day, etc.).
- Dashboard tab listing all enrolled devices for the current user.

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

## 20. Honey-Token Outbound Alerting (deferred)

The honey-token alarm is currently logged to the audit table and `tracing::warn!`. Real
deployments need an outbound webhook (PagerDuty, Slack, generic webhook) to ensure an
on-call human sees the alarm in seconds. Stakeholder decision needed on the integration
target and whether the webhook URL is per-namespace.

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
