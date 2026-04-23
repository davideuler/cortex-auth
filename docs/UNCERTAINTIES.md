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

**Issue**: If the `ENCRYPTION_KEY` changes, all stored encrypted values become unreadable. There is no key rotation mechanism.

**Question**: Is key rotation required? If so, a migration utility is needed that:
1. Decrypts all secrets with the old key
2. Re-encrypts with the new key
3. Updates the database atomically
Yes

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

**Issue**: The server currently listens on plain HTTP. In production, secrets in transit would be unprotected without a TLS terminating proxy.

**Question**: Should TLS be built into the server, or is a reverse proxy (nginx/caddy) assumed?
TLS should be built into the server.

---

## 9. Audit Log Retention

**Issue**: Audit logs grow indefinitely with no cleanup policy.

**Question**: What is the retention policy for audit logs?
- Rolling 30/90-day window?
- Export to external log aggregation?
Rolling a 60-day window. All operations should be logged.
