//! Account administration. Admins cannot read other users' vaults.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;

use crate::{
    audit::{self, Event, Outcome},
    error::{ApiError, ApiResult},
    session::{self, Admin},
    state::AppState,
};

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct AccountView {
    id: String,
    username: String,
    is_admin: bool,
    disabled: bool,
    created_at: i64,
}

/// `GET /api/admin/users`
pub async fn list_users(
    State(state): State<AppState>,
    _: Admin,
) -> ApiResult<Json<Vec<AccountView>>> {
    Ok(Json(
        sqlx::query_as(
            "SELECT id, username, is_admin, disabled, created_at FROM users ORDER BY created_at",
        )
        .fetch_all(&state.db)
        .await?,
    ))
}

async fn set_disabled(
    state: &AppState,
    admin: &Admin,
    id: &str,
    disabled: bool,
) -> ApiResult<StatusCode> {
    if id == admin.0.session.user_id {
        return Err(ApiError::Forbidden("cannot change your own account state"));
    }
    let res = sqlx::query("UPDATE users SET disabled = ?, updated_at = ? WHERE id = ?")
        .bind(disabled)
        .bind(crate::util::now_ms())
        .bind(id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    if disabled {
        session::revoke_user(state, id, None).await?;
    }
    let event = if disabled {
        "user.disabled"
    } else {
        "user.enabled"
    };
    audit::record(
        state,
        Event::new(event, Outcome::Success)
            .actor(&admin.0.session.user_id)
            .ip(admin.0.session.ip)
            .detail("target_user_id", id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /api/admin/users/{id}/disable`
pub async fn disable(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    set_disabled(&state, &admin, &id, true).await
}

/// `POST /api/admin/users/{id}/enable`
pub async fn enable(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    set_disabled(&state, &admin, &id, false).await
}

/// `DELETE /api/admin/users/{id}` — cascades the user's nodes and secrets.
pub async fn delete(
    State(state): State<AppState>,
    admin: Admin,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    if id == admin.0.session.user_id {
        return Err(ApiError::Forbidden("cannot delete your own account"));
    }
    session::revoke_user(&state, &id, None).await?;
    let res = sqlx::query("DELETE FROM users WHERE id = ?")
        .bind(&id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::record(
        &state,
        Event::new("user.deleted", Outcome::Success)
            .actor(&admin.0.session.user_id)
            .ip(admin.0.session.ip)
            .detail("target_user_id", id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
