use std::collections::HashMap;
use std::sync::Arc;

use crate::{
    config::AppConfig,
    crypto::{self, Kek},
    db::DbPool,
    ed25519_keys::ServerKeypair,
    rate_limiter::RateLimiter,
};

/// In-memory nonce replay cache.
/// Key: "agent_id:nonce", Value: Unix timestamp when the nonce was first seen.
/// Entries older than NONCE_WINDOW_SECS are pruned on every insert.
pub struct NonceCache(HashMap<String, i64>);

impl Default for NonceCache {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceCache {
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    /// Returns `true` if the nonce is fresh (first use), `false` if it's a replay.
    pub fn check_and_insert(&mut self, key: String, ts: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        // Prune stale entries (older than 5-minute window).
        self.0.retain(|_, &mut seen_ts| (now - seen_ts) < 300);
        if self.0.contains_key(&key) {
            return false;
        }
        self.0.insert(key, ts);
        true
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub config: AppConfig,
    /// In-memory KEK populated after the operator unseals the server.
    pub kek: Arc<Kek>,
    /// HKDF-style derivative of the KEK used to MAC-chain audit log rows.
    pub audit_mac_key: Arc<[u8; 32]>,
    /// Serializes audit log appends so concurrent writers see a consistent chain.
    pub audit_mutex: Arc<tokio::sync::Mutex<()>>,
    /// Server's Ed25519 signing keypair.
    pub server_keypair: Arc<ServerKeypair>,
    /// SHA-256 hex digest of the bootstrap admin token.
    pub admin_token_hash: Arc<String>,
    /// Replay-nonce TTL cache. Key: "agent_id:nonce", Value: first-seen ts.
    /// Pruned automatically on every insert; bounded by max requests per 5 min.
    pub nonce_cache: Arc<std::sync::Mutex<NonceCache>>,
    /// Per-IP / per-device_code sliding-window rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
}

impl AppState {
    pub fn new(
        pool: DbPool,
        config: AppConfig,
        kek: Kek,
        server_keypair: ServerKeypair,
        admin_token_hash: String,
    ) -> Self {
        let audit_mac_key = crypto::derive_audit_mac_key(&kek);
        Self {
            pool,
            config,
            kek: Arc::new(kek),
            audit_mac_key: Arc::new(audit_mac_key),
            audit_mutex: Arc::new(tokio::sync::Mutex::new(())),
            server_keypair: Arc::new(server_keypair),
            admin_token_hash: Arc::new(admin_token_hash),
            nonce_cache: Arc::new(std::sync::Mutex::new(NonceCache::new())),
            rate_limiter: Arc::new(RateLimiter::new()),
        }
    }
}
