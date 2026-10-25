//! API error type: stable error codes, no internal detail leaked to clients.

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    InvalidCredentials(&'static str),
    #[error("authentication required")]
    Unauthenticated { needs_setup: bool },
    #[error("{0}")]
    Forbidden(&'static str),
    #[error("not found")]
    NotFound,
    #[error("{0}")]
    Conflict(&'static str),
    #[error("vault is locked")]
    VaultLocked,
    #[error("too many requests")]
    RateLimited { retry_after_secs: u64 },
    #[error("stored data failed integrity check")]
    Integrity,
    #[error("internal error")]
    Internal(#[source] anyhow::Error),
}

impl ApiError {
    pub fn internal(e: impl Into<anyhow::Error>) -> Self {
        Self::Internal(e.into())
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.into())
    }
}

impl From<vault::VaultError> for ApiError {
    fn from(e: vault::VaultError) -> Self {
        use vault::VaultError as V;
        match e {
            V::InvalidCredentials => Self::InvalidCredentials("invalid credentials"),
            V::InvalidRecoveryKey => Self::InvalidCredentials("invalid credentials"),
            V::PasswordPolicy(why) => Self::BadRequest(format!("password {why}")),
            V::Integrity | V::Malformed(_) => Self::Integrity,
            V::Random | V::Kdf => Self::Internal(anyhow::anyhow!("vault: {e}")),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::BadRequest(_) => (StatusCode::BAD_REQUEST, "bad_request"),
            Self::InvalidCredentials(_) => (StatusCode::UNAUTHORIZED, "invalid_credentials"),
            Self::Unauthenticated { .. } => (StatusCode::UNAUTHORIZED, "unauthenticated"),
            Self::Forbidden(_) => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Self::VaultLocked => (StatusCode::LOCKED, "vault_locked"),
            Self::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "rate_limited"),
            Self::Integrity => (StatusCode::INTERNAL_SERVER_ERROR, "integrity_error"),
            Self::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        let mut body = json!({ "error": code, "message": self.to_string() });
        match &self {
            Self::Internal(source) => {
                let id = crate::util::new_id();
                tracing::error!(error_id = %id, error = ?source, "internal error");
                body["id"] = json!(id);
            }
            Self::Integrity => tracing::error!("stored ciphertext failed integrity check"),
            Self::Unauthenticated { needs_setup } => body["needs_setup"] = json!(needs_setup),
            _ => {}
        }
        let mut response = (status, Json(body)).into_response();
        if let Self::RateLimited { retry_after_secs } = self
            && let Ok(v) = HeaderValue::from_str(&retry_after_secs.max(1).to_string())
        {
            response.headers_mut().insert(header::RETRY_AFTER, v);
        }
        response
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
