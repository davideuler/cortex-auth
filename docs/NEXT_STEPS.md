# CortexAuth — Next Steps, Optimizations & Security Hardening

## Priority 1: Critical for Production

### Security

1. **Enforce access policies on legacy HMAC agents**
   The policy data model is stored and applied at discover time (path filtering by agent pattern). Tighten this for the Ed25519 path so policy decisions are recorded on every `/project/*` call, not just at discover.

2. **TLS support** *(implemented)*
   In-process rustls TLS terminates when both `TLS_CERT_FILE` and `TLS_KEY_FILE` are set. A TLS-terminating reverse proxy remains the recommended deployment pattern.

3. **Rate limiting**
   Add per-IP rate limiting on authentication endpoints (`/agent/discover`, `/device/authorize`, `/device/token`) to prevent brute-force attacks on agent JWT secrets, Ed25519 nonces, and device-flow user_code enumeration.

4. **Replay-protection for Ed25519 auth_proof**
   The current Ed25519 path enforces a ±5-minute `ts` window but does not yet cache nonces. Add a small in-memory LRU keyed by `(agent_id, nonce)` so the same proof cannot be replayed within the window.

5. **Constant-time token comparison** *(implemented)*
   Project token verification uses `subtle::ConstantTimeEq` for the SHA-256 hash compare path; the JWT path is signature-bound and not timing-attackable.

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

15. **Key rotation utility** *(implemented)*
    `POST /admin/rotate-key {"new_kek_password": "..."}` re-derives the KEK from a new
    operator passphrase and re-wraps every per-row DEK in a single transaction. Body
    ciphertexts are untouched. Restart the server with the new passphrase afterward.

16. **Audit log query API**
    Add `GET /admin/audit-logs?project=&action=&since=` for querying audit history from the admin interface.

17. **Backup / restore commands**
    Add `cortex-server export --output secrets.enc.json` and `cortex-server import` for encrypted backup/restore of the secrets vault.

---

## Priority 4: Architecture Improvements

18. **PostgreSQL support**
    Make the database backend configurable — sqlx already supports PostgreSQL with just a feature flag change in Cargo.toml. This unlocks multi-instance deployments.

19. **Secret namespacing / tagging** *(namespacing implemented)*
    Namespaces partition secrets, agents, and projects; manage them via `/admin/namespaces`
    or the dashboard "Namespaces" tab. Free-form tagging is still TBD.

20. **Config file watcher**
    Allow the server to reload its non-sensitive config (port, log level) from a config file on SIGHUP without restarting.

21. **Plugin-based auth backends** *(Ed25519 implemented)*
    Ed25519 is now the preferred agent identity (#13). HMAC remains as a backwards-compat path. Beyond these: mTLS client certificates and GitHub Actions OIDC tokens.

22. **Daemon attestation header (#17)**
    The current `cortex-daemon` is *unattested* — it can run any binary version. Add a per-process `attestation_priv` registered at boot and require an `X-Daemon-Attestation` header on every request signed over `(session_id, ts, jti, method, path, body_sha256, auth_token_id)`. Server-side allowed-binary whitelist gated by binary SHA-256.

23. **Multi-user RBAC for admins (#18)**
    The single shared `ADMIN_TOKEN` is acceptable for a one-operator deployment, but production needs per-user accounts with namespace scopes, password (Argon2id) or OIDC login, and per-user audit attribution. Currently device-approval and Shamir share generation are admin-token-gated; under RBAC they should additionally require a privileged role.

24. **Honey-token webhook customization (#20)**
    Each notification channel today receives the same payload. Future work: per-channel payload templates, per-namespace channel mapping, retry/backoff, and a `severity` filter so a slack channel can opt into honey-token alarms without recovery-mode pages.

25. **Verify-audit CLI (#11)**
    `cortex-cli verify-audit --db cortex-auth.db` would walk `audit_logs` row-by-row, recompute each `entry_mac` from `prev_hash || canonical_payload`, and report any mismatch. The MAC key derivation is documented in `crypto::derive_audit_mac_key`.

---

## Security Hardening Checklist

- [ ] All admin endpoints behind a network firewall — not exposed to the internet
- [ ] `CORTEX_KEK_PASSWORD` and `ADMIN_TOKEN` loaded from a secrets manager (AWS SSM, Vault, etc.), not `.env` files on disk
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
