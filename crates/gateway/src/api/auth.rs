//! Setup, login, logout, recovery and session status.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use serde_json::json;
use vault::{SecretString, user};

use super::{UserRow, UserView, insert_user, update_key_record, validate_username, with_cookie};
use crate::{
    audit::{self, Event, Outcome},
    bootstrap,
    error::{ApiError, ApiResult},
    extract::ApiJson,
    session::{self, ClientIp, Session},
    state::AppState,
    util::new_id,
};

/// `GET /api/me`
pub async fn me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let Some(s) = Session::load(&state, &headers).await? else {
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&state.db)
            .await?;
        return Err(ApiError::Unauthenticated {
            needs_setup: users == 0,
        });
    };
    let vault = match state.keyring.state(&s.token_hash) {
        crate::keyring::VaultState::Unlocked(_) => "unlocked",
        crate::keyring::VaultState::IdleLocked => {
            audit::vault_lock(&state, &s.user_id, "idle").await;
            "locked"
        }
        crate::keyring::VaultState::Locked => "locked",
    };
    let expires_in = (s.expires_at - crate::util::now_ms()).max(0) / 1000;
    Ok(Json(json!({
        "user": { "id": s.user_id, "username": s.username, "is_admin": s.is_admin },
        "vault": vault,
        "idle_lock_in_s": state.keyring.idle_lock_in(&s.token_hash),
        "session_expires_in_s": expires_in,
    })))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupInput {
    bootstrap_token: SecretString,
    username: String,
    password: SecretString,
}

/// `POST /api/setup` — creates the first (admin) account.
pub async fn setup(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(input): ApiJson<SetupInput>,
) -> ApiResult<Response> {
    state.limits.check_enroll(ip)?;
    if !bootstrap::check(&state, input.bootstrap_token.expose()) {
        return Err(ApiError::InvalidCredentials("invalid bootstrap token"));
    }
    validate_username(&input.username)?;
    let user_id = new_id();
    let (uid, kdf) = (user_id.clone(), state.settings.kdf);
    let enrolled = state
        .run_kdf(move || user::enroll(&uid, &input.password, kdf))
        .await??;

    let mut tx = state.db.begin().await?;
    let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&mut *tx)
        .await?;
    if users > 0 {
        return Err(ApiError::Conflict("setup already completed"));
    }
    insert_user(&mut tx, &user_id, &input.username, true, &enrolled.record).await?;
    tx.commit().await?;
    bootstrap::consume(&state);

    let (token, hash) = session::create(
        &state,
        &user_id,
        &ip.to_string(),
        &session::user_agent(&headers),
    )
    .await?;
    state.keyring.insert(hash, &user_id, enrolled.mvk);
    audit::record(
        &state,
        Event::new("auth.bootstrap", Outcome::Success)
            .actor(&user_id)
            .ip(Some(ip)),
    )
    .await?;
    Ok(with_cookie(
        session::set_cookie(&state, &token),
        StatusCode::CREATED,
        Some(
            json!({ "user": UserView { id: user_id, username: input.username, is_admin: true }, "recovery_key": enrolled.recovery_key.expose() }),
        ),
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginInput {
    username: String,
    password: SecretString,
}

/// `POST /api/auth/login` — authenticates and unlocks the vault.
pub async fn login(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(input): ApiJson<LoginInput>,
) -> ApiResult<Response> {
    state.limits.check_auth(ip, &input.username)?;
    let row = UserRow::by_username(&state, &input.username).await?;
    let kdf = state.settings.kdf;
    let Some(row) = row.filter(|r| !r.disabled) else {
        state
            .run_kdf(move || user::burn_dummy(&input.password, kdf))
            .await?;
        audit::record(
            &state,
            Event::new("auth.login_failed", Outcome::Failure)
                .ip(Some(ip))
                .detail("username", input.username.clone()),
        )
        .await?;
        return Err(ApiError::InvalidCredentials("invalid credentials"));
    };
    let record = row.key_record()?;
    let (uid, rec) = (row.id.clone(), record.clone());
    let result = state
        .run_kdf(move || {
            let mvk = user::unlock(&uid, &rec, &input.password)?;
            // Transparent upgrade when the configured KDF cost changed.
            let upgraded = if rec.kdf == kdf {
                None
            } else {
                Some(user::change_password(
                    &uid,
                    &rec,
                    &mvk,
                    &input.password,
                    kdf,
                )?)
            };
            Ok::<_, vault::VaultError>((mvk, upgraded))
        })
        .await?;
    let (mvk, upgraded) = match result {
        Ok(v) => v,
        Err(e) => {
            audit::record(
                &state,
                Event::new("auth.login_failed", Outcome::Failure)
                    .actor(&row.id)
                    .ip(Some(ip))
                    .detail("username", row.username.clone()),
            )
            .await?;
            return Err(e.into());
        }
    };
    if let Some(new_record) = upgraded {
        update_key_record(&state, &row.id, &new_record, false).await?;
    }
    let (token, hash) = session::create(
        &state,
        &row.id,
        &ip.to_string(),
        &session::user_agent(&headers),
    )
    .await?;
    state.keyring.insert(hash, &row.id, mvk);
    audit::record(
        &state,
        Event::new("auth.login", Outcome::Success)
            .actor(&row.id)
            .ip(Some(ip)),
    )
    .await?;
    Ok(with_cookie(
        session::set_cookie(&state, &token),
        StatusCode::OK,
        Some(json!({ "user": row.view() })),
    ))
}

/// `POST /api/auth/logout`
pub async fn logout(State(state): State<AppState>, s: Session) -> ApiResult<Response> {
    sqlx::query("DELETE FROM auth_sessions WHERE token_hash = ?")
        .bind(s.token_hash.as_slice())
        .execute(&state.db)
        .await?;
    state.keyring.remove(&s.token_hash);
    audit::record(
        &state,
        Event::new("auth.logout", Outcome::Success)
            .actor(&s.user_id)
            .ip(s.ip),
    )
    .await?;
    Ok(with_cookie(
        session::clear_cookie(&state),
        StatusCode::NO_CONTENT,
        None,
    ))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverInput {
    username: String,
    recovery_key: SecretString,
    new_password: SecretString,
}

/// `POST /api/auth/recover` — recovery key + new password; rotates the recovery key.
pub async fn recover(
    State(state): State<AppState>,
    ClientIp(ip): ClientIp,
    headers: HeaderMap,
    ApiJson(input): ApiJson<RecoverInput>,
) -> ApiResult<Response> {
    state.limits.check_auth(ip, &input.username)?;
    vault::kdf::normalize_password(&input.new_password)?;
    let kdf = state.settings.kdf;
    let Some(row) = UserRow::by_username(&state, &input.username)
        .await?
        .filter(|r| !r.disabled)
    else {
        state
            .run_kdf(move || user::burn_dummy(&input.new_password, kdf))
            .await?;
        return Err(ApiError::InvalidCredentials("invalid credentials"));
    };
    let record = row.key_record()?;
    let uid = row.id.clone();
    let result = state
        .run_kdf(move || {
            user::recover(&uid, &record, &input.recovery_key, &input.new_password, kdf)
        })
        .await?;
    let enrolled = match result {
        Ok(e) => e,
        Err(e) => {
            audit::record(
                &state,
                Event::new("vault.recovery_used", Outcome::Failure)
                    .actor(&row.id)
                    .ip(Some(ip)),
            )
            .await?;
            return Err(e.into());
        }
    };
    update_key_record(&state, &row.id, &enrolled.record, true).await?;
    session::revoke_user(&state, &row.id, None).await?;
    let (token, hash) = session::create(
        &state,
        &row.id,
        &ip.to_string(),
        &session::user_agent(&headers),
    )
    .await?;
    state.keyring.insert(hash, &row.id, enrolled.mvk);
    audit::record(
        &state,
        Event::new("vault.recovery_used", Outcome::Success)
            .actor(&row.id)
            .ip(Some(ip)),
    )
    .await?;
    Ok(with_cookie(
        session::set_cookie(&state, &token),
        StatusCode::OK,
        Some(json!({ "user": row.view(), "recovery_key": enrolled.recovery_key.expose() })),
    ))
}
