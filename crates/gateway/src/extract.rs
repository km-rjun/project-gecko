//! JSON body extractors whose rejections use the API error format.

use axum::{
    body::Bytes,
    extract::{FromRequest, Request},
    http::header,
};
use serde::de::DeserializeOwned;

use crate::error::ApiError;

fn is_json(req: &Request) -> bool {
    req.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            ct.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
        })
}

fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(bytes)
        .map_err(|e| ApiError::BadRequest(format!("invalid JSON body: {e}")))
}

async fn body<S: Send + Sync>(req: Request, state: &S) -> Result<Bytes, ApiError> {
    Bytes::from_request(req, state)
        .await
        .map_err(|_| ApiError::BadRequest("request body too large or unreadable".into()))
}

/// Required JSON body (`Content-Type: application/json`).
#[derive(Debug)]
pub struct ApiJson<T>(pub T);

impl<T: DeserializeOwned, S: Send + Sync> FromRequest<S> for ApiJson<T> {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        if !is_json(&req) {
            return Err(ApiError::BadRequest(
                "Content-Type must be application/json".into(),
            ));
        }
        let bytes = body(req, state).await?;
        parse(&bytes).map(Self)
    }
}

/// Optional JSON body: an empty body yields `T::default()`.
#[derive(Debug)]
pub struct OptionalJson<T>(pub T);

impl<T: DeserializeOwned + Default, S: Send + Sync> FromRequest<S> for OptionalJson<T> {
    type Rejection = ApiError;
    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        let json = is_json(&req);
        let bytes = body(req, state).await?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(Self(T::default()));
        }
        if !json {
            return Err(ApiError::BadRequest(
                "Content-Type must be application/json".into(),
            ));
        }
        parse(&bytes).map(Self)
    }
}
