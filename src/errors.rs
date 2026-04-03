use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("Authentication required")]
    AuthenticationRequired,

    #[error("Access denied: {0}")]
    AccessDenied(String),

    #[error("Application error: {0}")]
    ApplicationError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::AuthenticationRequired => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::AccessDenied(_) => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::ApplicationError(_) => (StatusCode::BAD_REQUEST, self.to_string()),
            AppError::ConfigError(_) => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
            AppError::Internal(_) => {
                // Don't leak internal error details
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
            }
        };

        (status, message).into_response()
    }
}
