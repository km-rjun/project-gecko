//! HTTP router and background housekeeping.

use std::time::Duration;

use axum::{
    Json, Router,
    extract::DefaultBodyLimit,
    middleware,
    routing::{delete, get, post},
};
use serde_json::{Value, json};

use crate::{
    api::{account, admin, audit_api, auth, invites, nodes, vault_api},
    audit,
    state::AppState,
    util::now_ms,
};

/// Request body limit for the JSON API (docs/02 §10).
pub const MAX_BODY: usize = 64 * 1024;

/// Builds the application router.
pub fn router(state: AppState) -> Router {
    let api = Router::new()
        .route("/api/health", get(health))
        .route("/api/me", get(auth::me))
        .route("/api/setup", post(auth::setup))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/recover", post(auth::recover))
        .route("/api/vault/unlock", post(vault_api::unlock))
        .route("/api/vault/lock", post(vault_api::lock))
        .route("/api/account/password", post(account::change_password))
        .route(
            "/api/account/recovery-key",
            post(account::regenerate_recovery_key),
        )
        .route("/api/invites/redeem", post(invites::redeem))
        .route("/api/nodes", get(nodes::list).post(nodes::create))
        .route(
            "/api/nodes/{id}",
            get(nodes::get).put(nodes::update).delete(nodes::delete),
        )
        .route(
            "/api/nodes/{id}/host-identity/reset",
            post(nodes::reset_host_identity),
        )
        .route("/api/audit", get(audit_api::own))
        .route("/api/ws", get(crate::ws::upgrade))
        .route(
            "/api/admin/invites",
            get(invites::list).post(invites::create),
        )
        .route("/api/admin/invites/{id}", delete(invites::revoke))
        .route("/api/admin/users", get(admin::list_users))
        .route("/api/admin/users/{id}/disable", post(admin::disable))
        .route("/api/admin/users/{id}/enable", post(admin::enable))
        .route("/api/admin/users/{id}", delete(admin::delete))
        .route("/api/admin/audit", get(audit_api::all))
        .route("/api/admin/audit/verify", get(audit_api::verify));

    api.layer(DefaultBodyLimit::max(MAX_BODY))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::security::require_origin,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            crate::security::headers,
        ))
        .with_state(state)
}

/// Liveness probe for container healthchecks. Deliberately returns no version or build data.
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

/// Periodic idle-lock sweep, expired-session cleanup and rate-limiter housekeeping.
pub fn spawn_housekeeping(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(30));
        loop {
            tick.tick().await;
            if let Err(e) = housekeeping(&state).await {
                tracing::error!(error = %e, "housekeeping failed");
            }
        }
    })
}

/// One housekeeping pass (public for tests).
pub async fn housekeeping(state: &AppState) -> anyhow::Result<()> {
    for user_id in state.keyring.sweep() {
        audit::vault_lock(state, &user_id, "idle").await;
    }
    let idle_ms = i64::try_from(state.settings.session_idle.as_millis()).unwrap_or(i64::MAX);
    let now = now_ms();
    let expired: Vec<String> = sqlx::query_scalar(
        "SELECT session_id FROM auth_sessions WHERE expires_at <= ? OR last_seen_at < ?",
    )
    .bind(now)
    .bind(now.saturating_sub(idle_ms))
    .fetch_all(&state.db)
    .await?;
    for id in expired {
        crate::session::end(state, &id).await?;
    }
    state.limits.housekeeping();
    Ok(())
}
