use axum::{http::StatusCode, response::{IntoResponse, Response}, Json};
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// 401 with structured `error_code` so clients can distinguish expired/revoked
    /// tokens from generic auth failures and trigger auto-rotation.
    #[error("Token error ({code}): {message}")]
    TokenError { code: &'static str, message: String },

    /// 403 with a structured `error_code` and an optional details payload —
    /// used by `/agent/discover` to return `pending_approval` when a grant
    /// is awaiting human review.
    #[error("Forbidden ({code}): {message}")]
    Forbidden {
        code: &'static str,
        message: String,
        details: Option<Value>,
    },

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Conflict: {0}")]
    Conflict(String),

    #[error("Internal error: {0}")]
    Internal(#[from] anyhow::Error),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl AppError {
    pub fn token_expired() -> Self {
        AppError::TokenError {
            code: "token_expired",
            message: "Project token has expired. Re-run /agent/discover with regenerate_token=true to obtain a fresh token.".into(),
        }
    }

    pub fn token_revoked() -> Self {
        AppError::TokenError {
            code: "token_revoked",
            message: "Project token has been revoked by an administrator. Contact your admin or re-run /agent/discover with regenerate_token=true.".into(),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::TokenError { code, message } => (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": message, "error_code": code })),
            )
                .into_response(),
            AppError::Forbidden { code, message, details } => {
                let mut body = json!({ "error": message, "error_code": code });
                if let Some(d) = details {
                    body["details"] = d;
                }
                (StatusCode::FORBIDDEN, Json(body)).into_response()
            }
            other => {
                let (status, message) = match &other {
                    AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
                    AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
                    AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
                    AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
                    AppError::Internal(e) => {
                        tracing::error!("Internal error: {:?}", e);
                        (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
                    }
                    AppError::Database(e) => {
                        tracing::error!("Database error: {:?}", e);
                        (StatusCode::INTERNAL_SERVER_ERROR, "Database error".to_string())
                    }
                    AppError::TokenError { .. } | AppError::Forbidden { .. } => unreachable!(),
                };
                (status, Json(json!({ "error": message }))).into_response()
            }
        }
    }
}
