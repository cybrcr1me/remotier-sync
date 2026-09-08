//! One error type, one JSON shape on the wire.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use remotier_sync_proto::api::ApiError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not found")]
    NotFound,
    #[error("that email is already registered")]
    EmailTaken,
    #[error("wrong email or password")]
    BadCredentials,
    #[error("sign in first")]
    Unauthorised,
    #[error("registration is closed on this instance")]
    RegistrationClosed,
    #[error("too many attempts, try again shortly")]
    RateLimited,
    #[error("{0}")]
    BadRequest(String),
    #[error("database error")]
    Db(#[from] sqlx::Error),
    #[error("internal error")]
    Internal(String),
}

impl Error {
    fn parts(&self) -> (StatusCode, &'static str) {
        match self {
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::EmailTaken => (StatusCode::CONFLICT, "email_taken"),
            Self::BadCredentials => (StatusCode::UNAUTHORIZED, "bad_credentials"),
            Self::Unauthorised => (StatusCode::UNAUTHORIZED, "unauthorised"),
            Self::RegistrationClosed => (StatusCode::FORBIDDEN, "registration_closed"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::Db(_) | Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = self.parts();

        // A database or internal error is logged in full and reported as nothing. The
        // detail is for the operator; to a caller it is a way to probe the schema.
        let message = match &self {
            Self::Db(e) => {
                tracing::error!(error = %e, "database error");
                "internal error".to_string()
            }
            Self::Internal(detail) => {
                tracing::error!(detail, "internal error");
                "internal error".to_string()
            }
            other => other.to_string(),
        };

        (
            status,
            Json(ApiError {
                code: code.to_string(),
                message,
            }),
        )
            .into_response()
    }
}

pub type Result<T> = std::result::Result<T, Error>;
