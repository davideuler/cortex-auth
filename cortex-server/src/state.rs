use std::sync::Arc;

use crate::{
    config::AppConfig,
    crypto::{self, Kek},
    db::DbPool,
    ed25519_keys::ServerKeypair,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub config: AppConfig,
    /// In-memory KEK populated after the operator unseals the server. Held
    /// behind Arc so the inner KEK is freed (and zeroized) when the last
    /// AppState clone is dropped at shutdown.
    pub kek: Arc<Kek>,
    /// HKDF-style derivative of the KEK used to MAC-chain audit log rows.
    /// Holding it in memory only — recomputable from the KEK at any time.
    pub audit_mac_key: Arc<[u8; 32]>,
    /// Serializes audit log appends so concurrent writers see a consistent
    /// `prev_mac` and the chain stays linear.
    pub audit_mutex: Arc<tokio::sync::Mutex<()>>,
    /// Server's Ed25519 signing keypair — used to mint signed project tokens
    /// (#14) and to advertise the public key via /.well-known/jwks.json.
    pub server_keypair: Arc<ServerKeypair>,
}

impl AppState {
    pub fn new(pool: DbPool, config: AppConfig, kek: Kek, server_keypair: ServerKeypair) -> Self {
        let audit_mac_key = crypto::derive_audit_mac_key(&kek);
        Self {
            pool,
            config,
            kek: Arc::new(kek),
            audit_mac_key: Arc::new(audit_mac_key),
            audit_mutex: Arc::new(tokio::sync::Mutex::new(())),
            server_keypair: Arc::new(server_keypair),
        }
    }
}
