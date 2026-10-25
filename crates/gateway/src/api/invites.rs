//! Admin-issued single-use invites (decision D-007).

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use vault::{SecretString, user};

use super::{UserView, insert_user, validate_username, with_cookie};
use crate::{
    audit::{self, Event, Outcome},
    error::{ApiError, ApiResult},
    extract::{ApiJson, OptionalJson},
    session::{self, Admin, ClientIp},
    state::AppState,
    util::{new_id, now_ms, random_token, token_hash},
};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInput {
    ttl_hours: Option<u32>,
}

/// `POST /api/admin/invites`
pub async fn create(
    State(state): State<AppState>,
    Admin(u): Admin,
    OptionalJson(input): OptionalJson<CreateInput>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let ttl = input.ttl_hours.unwrap_or(72);
    if !(1..=168).contains(&ttl) {
        return Err(ApiError::BadRequest(
            "ttl_hours must be between 1 and 168".into(),
        ));
    }
    let token = random_token()?;
    let id = new_id();
    let now = now_ms();
    let expires_at = now + i64::from(ttl) * 3_600_000;
    sqlx::query("INSERT INTO invites (id, token_hash, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?)")
        .bind(&id)
        .bind(token_hash(&token).as_slice())
        .bind(&u.session.user_id)
        .bind(now)
        .bind(expires_at)
        .execute(&state.db)
        .await?;
    audit::record(
        &state,
        Event::new("user.invite_created", Outcome::Success)
            .actor(&u.session.user_id)
            .ip(u.session.ip)
            .detail("invite_id", id.clone()),
    )
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(
            json!({ "id": id, "token": token.as_str(), "expires_at": expires_at, "path": format!("/invite#{}", token.as_str()) }),
        ),
    ))
}

#[derive(Debug, Serialize, sqlx::FromRow)]
pub struct InviteView {
    id: String,
    created_at: i64,
    expires_at: i64,
    used_at: Option<i64>,
    used_by: Option<String>,
}

/// `GET /api/admin/invites`
pub async fn list(State(state): State<AppState>, _: Admin) -> ApiResult<Json<Vec<InviteView>>> {
    let rows = sqlx::query_as(
        "SELECT id, created_at, expires_at, used_at, used_by FROM invites ORDER BY created_at DESC",
    )
    .fetch_all(&state.db)
    .await?;
    Ok(Json(rows))
}

/// `DELETE /api/admin/invites/{id}` — revokes an unused invite.
pub async fn revoke(
    State(state): State<AppState>,
    Admin(u): Admin,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let res = sqlx::query("DELETE FROM invites WHERE id = ? AND used_at IS NULL")
        .bind(&id)
        .execute(&state.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(ApiError::NotFound);
    }
    audit::record(
        &state,
        Event::new("user.invite_revoked", Outcome::Success)
            .actor(&u.session.user_id)
            .ip(u.session.ip)
            .detail("invite_id", id),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemInput {
    token: SecretString,
    username: String,
    password: SecretString,
}

/// `POST /api/invites/redeem` — creates the account and logs it in.
pub async fn redeem(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(input): ApiJson<RedeemInput>,
) -> ApiResult<Response> {
    state.limits.check_enroll(ip)?;
    validate_username(&input.username)?;
    vault::kdf::normalize_password(&input.password)?;
    let hash = token_hash(input.token.expose());
    let invite_id: Option<String> = sqlx::query_scalar(
        "SELECT id FROM invites WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?",
    )
    .bind(hash.as_slice())
    .bind(now_ms())
    .fetch_optional(&state.db)
    .await?;
    let Some(invite_id) = invite_id else {
        return Err(ApiError::InvalidCredentials("invalid or expired invite"));
    };
    let user_id = new_id();
    let (uid, kdf) = (user_id.clone(), state.settings.kdf);
    let enrolled = state
        .run_kdf(move || user::enroll(&uid, &input.password, kdf))
        .await??;

    let mut tx = state.db.begin().await?;
    insert_user(&mut tx, &user_id, &input.username, false, &enrolled.record).await?;
    let claimed = sqlx::query("UPDATE invites SET used_at = ?, used_by = ? WHERE id = ? AND used_at IS NULL AND expires_at > ?")
        .bind(now_ms())
        .bind(&user_id)
        .bind(&invite_id)
        .bind(now_ms())
        .execute(&mut *tx)
        .await?;
    if claimed.rows_affected() != 1 {
        return Err(ApiError::InvalidCredentials("invalid or expired invite"));
    }
    tx.commit().await?;

    let (token, sid) = session::create(
        &state,
        &user_id,
        &ip.to_string(),
        &session::user_agent(&headers),
    )
    .await?;
    state.keyring.insert(&sid, &user_id, enrolled.mvk);
    audit::record(
        &state,
        Event::new("user.created", Outcome::Success)
            .actor(&user_id)
            .ip(Some(ip))
            .detail("invite_id", invite_id),
    )
    .await?;
    Ok(with_cookie(
        session::set_cookie(&state, &token),
        StatusCode::CREATED,
        Some(
            json!({ "user": UserView { id: user_id, username: input.username, is_admin: false }, "recovery_key": enrolled.recovery_key.expose() }),
        ),
    ))
}
