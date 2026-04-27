use std::sync::Arc;

use crate::{config::AppConfig, crypto::Kek, db::DbPool};

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub config: AppConfig,
    /// In-memory KEK populated after the operator unseals the server. Held
    /// behind Arc so the inner KEK is freed (and zeroized) when the last
    /// AppState clone is dropped at shutdown.
    pub kek: Arc<Kek>,
}

impl AppState {
    pub fn new(pool: DbPool, config: AppConfig, kek: Kek) -> Self {
        Self {
            pool,
            config,
            kek: Arc::new(kek),
        }
    }
}
