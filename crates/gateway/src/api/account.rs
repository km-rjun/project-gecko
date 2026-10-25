//! Password change and recovery-key regeneration.

use axum::{Json, extract::State, http::StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use vault::{SecretString, user};

use super::{UserRow, update_key_record};
use crate::{
    audit::{self, Event, Outcome},
    error::{ApiError, ApiResult},
    extract::ApiJson,
    session::{self, Unlocked},
    state::AppState,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordInput {
    current_password: SecretString,
    new_password: SecretString,
}

/// `POST /api/account/password` — re-wraps the MVK; other sessions are revoked.
pub async fn change_password(
    State(state): State<AppState>,
    u: Unlocked,
    ApiJson(input): ApiJson<PasswordInput>,
) -> ApiResult<StatusCode> {
    let s = &u.session;
    if let Some(ip) = s.ip {
        state.limits.check_auth(ip, &s.username)?;
    }
    vault::kdf::normalize_password(&input.new_password)?;
    let row = UserRow::by_id(&state, &s.user_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let record = row.key_record()?;
    let (uid, kdf, mvk) = (s.user_id.clone(), state.settings.kdf, u.mvk.clone());
    let result = state
        .run_kdf(move || {
            user::unlock(&uid, &record, &input.current_password)?;
            user::change_password(&uid, &record, &mvk, &input.new_password, kdf)
        })
        .await?;
    let new_record = match result {
        Ok(r) => r,
        Err(e) => {
            audit::record(
                &state,
                Event::new("vault.password_changed", Outcome::Failure)
                    .actor(&s.user_id)
                    .ip(s.ip),
            )
            .await?;
            return Err(e.into());
        }
    };
    update_key_record(&state, &s.user_id, &new_record, true).await?;
    session::revoke_user(&state, &s.user_id, Some(s.session_id.as_str())).await?;
    audit::record(
        &state,
        Event::new("vault.password_changed", Outcome::Success)
            .actor(&s.user_id)
            .ip(s.ip),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegenerateInput {
    password: SecretString,
}

/// `POST /api/account/recovery-key` — issues a new recovery key; the old one stops working.
pub async fn regenerate_recovery_key(
    State(state): State<AppState>,
    u: Unlocked,
    ApiJson(input): ApiJson<RegenerateInput>,
) -> ApiResult<Json<Value>> {
    let s = &u.session;
    if let Some(ip) = s.ip {
        state.limits.check_auth(ip, &s.username)?;
    }
    let row = UserRow::by_id(&state, &s.user_id)
        .await?
        .ok_or(ApiError::NotFound)?;
    let record = row.key_record()?;
    let (uid, mvk) = (s.user_id.clone(), u.mvk.clone());
    let (new_record, display) = state
        .run_kdf(move || {
            user::unlock(&uid, &record, &input.password)?;
            user::regenerate_recovery(&uid, &record, &mvk)
        })
        .await??;
    update_key_record(&state, &s.user_id, &new_record, false).await?;
    audit::record(
        &state,
        Event::new("vault.recovery_key_regenerated", Outcome::Success)
            .actor(&s.user_id)
            .ip(s.ip),
    )
    .await?;
    Ok(Json(json!({ "recovery_key": display.expose() })))
}
