pub mod api;
pub mod audit;
pub mod config;
pub mod crypto;
pub mod dashboard;
pub mod db;
pub mod ed25519_keys;
pub mod error;
pub mod kek;
pub mod models;
pub mod notifications;
pub mod shamir;
pub mod state;

use axum::{routing::get, Router};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard::serve))
        .route("/.well-known/jwks.json", get(api::agent::jwks))
        .route("/device/authorize", axum::routing::post(api::agent::device_authorize))
        .route("/device/token", axum::routing::post(api::agent::device_token))
        .route("/device", get(api::agent::device_approval_page))
        .nest("/admin", api::admin::router())
        .nest("/agent", api::agent::router())
        .nest("/project", api::agent::project_router())
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
