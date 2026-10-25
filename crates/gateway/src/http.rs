//! HTTP router. Checkpoint 1 exposes only the unauthenticated health endpoint.

use axum::{Json, Router, routing::get};
use serde_json::{Value, json};

/// Builds the application router.
pub fn router() -> Router {
    Router::new().route("/api/health", get(health))
}

/// Liveness probe for container healthchecks. Deliberately returns no version or build data.
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}
