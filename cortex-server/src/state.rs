use crate::{config::AppConfig, db::DbPool};

#[derive(Clone)]
pub struct AppState {
    pub pool: DbPool,
    pub config: AppConfig,
}

impl AppState {
    pub fn new(pool: DbPool, config: AppConfig) -> Self {
        Self { pool, config }
    }
}
