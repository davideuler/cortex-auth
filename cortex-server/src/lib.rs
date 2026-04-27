pub mod admin_token;
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
pub mod rate_limiter;
pub mod shamir;
pub mod state;

use axum::{http::HeaderValue, routing::get, Router};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use state::AppState;

pub fn build_router(state: AppState) -> Router {
    let cors = build_cors_layer(&state.config.dashboard_origins);

    Router::new()
        .route("/", get(dashboard::serve))
        .route("/.well-known/jwks.json", get(api::agent::jwks))
        .route(
            "/device/authorize",
            axum::routing::post(api::agent::device_authorize),
        )
        .route("/device/token", axum::routing::post(api::agent::device_token))
        .route("/device", get(api::agent::device_approval_page))
        .nest("/admin", api::admin::router())
        .nest("/agent", api::agent::router())
        .nest("/daemon", api::daemon::router())
        .nest("/project", api::agent::project_router())
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

fn build_cors_layer(allowed_origins: &[String]) -> CorsLayer {
    if allowed_origins.is_empty() {
        // Default: same-origin only — no cross-origin requests permitted.
        return CorsLayer::new();
    }

    let origins: Vec<HeaderValue> = allowed_origins
        .iter()
        .filter_map(|o| o.parse::<HeaderValue>().ok())
        .collect();

    if origins.is_empty() {
        return CorsLayer::new();
    }

    CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
        ])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
            "x-admin-token".parse().unwrap(),
            "x-cortex-caller-pid".parse().unwrap(),
            "x-cortex-caller-binary-sha256".parse().unwrap(),
            "x-cortex-caller-argv-hash".parse().unwrap(),
            "x-cortex-caller-cwd".parse().unwrap(),
            "x-cortex-caller-git-commit".parse().unwrap(),
            "x-cortex-hostname".parse().unwrap(),
            "x-cortex-os".parse().unwrap(),
            "x-daemon-attestation".parse().unwrap(),
        ])
}
