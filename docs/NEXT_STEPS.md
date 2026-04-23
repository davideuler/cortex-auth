# CortexAuth — Next Steps, Optimizations & Security Hardening

## Priority 1: Critical for Production

### Security

1. **Enforce access policies**
   The policy data model is stored but not applied. Wire glob-pattern matching on agent_id against stored policies when agents call `/agent/secrets` and `/agent/config`. This is the most important security gap.

2. **TLS support**
   Add rustls-based TLS directly in the server (using `axum-server` with `rustls`), or clearly document that a TLS-terminating reverse proxy is mandatory. Secrets in transit over plain HTTP is unacceptable in production.

3. **Rate limiting**
   Add per-IP rate limiting on authentication endpoints (`/agent/authenticate`, `/agent/discover`) to prevent brute-force attacks on agent JWT secrets and token enumeration.

4. **Encrypt project token at rest differently**
   Consider using a keyed HMAC (HMAC-SHA256 with a server-side key) instead of plain SHA-256 for project token hashing. This prevents offline attacks if the DB is exfiltrated.

5. **Constant-time token comparison**
   Replace `hash_token(token) == hash` with `subtle::ConstantTimeEq` to prevent timing attacks on token verification.

### Correctness

6. **Fix re-discover token behavior**
   The current `__existing__:<id>` sentinel for existing projects is not a valid token. Implement proper behavior: either return a clear error message or force `regenerate_token: true` to be explicit.

7. **Validate key_path format**
   Add regex/allowlist validation for `key_path` to prevent path injection or confusingly named secrets (e.g., restrict to `[a-z0-9_/.-]`).

---

## Priority 2: Feature Completeness

8. **Admin web UI**
   Build a minimal web interface (HTML + Alpine.js or plain JS) served at `/admin/ui` by the server for managing secrets and agents without needing curl/HTTP clients.

9. **Policy enforcement with session tokens**
   Link agent session tokens to their resolved policies so that per-agent secret access can be enforced at the vault level, not just project level.

10. **Secret versioning**
    Track historical versions of secrets (value history) to enable rollback if a secret is accidentally overwritten. Store N most recent versions.

11. **Bulk secret import**
    Add `POST /admin/secrets/bulk` to import multiple secrets at once (e.g., from a `.env` file export).

12. **Project token expiry**
    Add optional `expires_at` field to project tokens. Expired tokens should return 401 with a clear "token expired" message rather than "invalid token".

---

## Priority 3: Operational Improvements

13. **Metrics endpoint**
    Add `GET /metrics` returning Prometheus-compatible metrics: request count, error rate, auth failures, active projects, total secrets.

14. **Health check endpoint**
    Add `GET /health` returning `{"status": "ok", "db": "ok"}` for load balancer / uptime monitoring.

15. **Key rotation utility**
    Implement a `cortex-server rotate-key --new-key <hex>` subcommand that re-encrypts all secrets under a new ENCRYPTION_KEY atomically.

16. **Audit log query API**
    Add `GET /admin/audit-logs?project=&action=&since=` for querying audit history from the admin interface.

17. **Backup / restore commands**
    Add `cortex-server export --output secrets.enc.json` and `cortex-server import` for encrypted backup/restore of the secrets vault.

---

## Priority 4: Architecture Improvements

18. **PostgreSQL support**
    Make the database backend configurable — sqlx already supports PostgreSQL with just a feature flag change in Cargo.toml. This unlocks multi-instance deployments.

19. **Secret namespacing / tagging**
    Add `namespace` and `tags` fields to secrets to organize large secret collections and enable namespace-level access control.

20. **Config file watcher**
    Allow the server to reload its non-sensitive config (port, log level) from a config file on SIGHUP without restarting.

21. **Plugin-based auth backends**
    Support additional agent authentication backends beyond JWT (e.g., mTLS client certificates, GitHub Actions OIDC tokens).

---

## Security Hardening Checklist

- [ ] All admin endpoints behind a network firewall — not exposed to the internet
- [ ] `ENCRYPTION_KEY` and `ADMIN_TOKEN` loaded from a secrets manager (AWS SSM, Vault, etc.), not `.env` files on disk
- [ ] Server process runs as a dedicated non-root user
- [ ] SQLite database file permissions: `chmod 600 cortex-auth.db`
- [ ] Enable SQLite WAL mode for better concurrency: `PRAGMA journal_mode=WAL`
- [ ] Log rotation configured to prevent disk fill from audit logs
- [ ] Regular automated backups of the database file
- [ ] Dependency audit: `cargo audit` in CI pipeline
- [ ] Fuzz testing of the encryption/decryption layer
- [ ] Pen test the admin API for authorization bypass

---

## Performance Optimizations

- **Connection pooling**: Current `max_connections=10` is appropriate for SQLite single-writer mode; increase only when migrating to PostgreSQL
- **Response caching**: For `GET /agent/secrets` in high-traffic scenarios, add in-memory TTL cache (30-60s) keyed by `(project_name, token_hash)` to reduce DB reads
- **Lazy decryption**: For `GET /admin/secrets` list, values are not decrypted (only on detail view) — this pattern should be maintained
- **Index optimization**: Consider adding composite index `(project_name, secret_type)` if the vault grows large
