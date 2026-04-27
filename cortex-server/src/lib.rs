pub mod api;
pub mod audit;
pub mod config;
pub mod crypto;
pub mod dashboard;
pub mod db;
pub mod error;
pub mod kek;
pub mod models;
pub mod state;

use axum::{routing::get, Router};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard::serve))
        .nest("/admin", api::admin::router())
        .nest("/agent", api::agent::router())
        .nest("/project", api::agent::project_router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
