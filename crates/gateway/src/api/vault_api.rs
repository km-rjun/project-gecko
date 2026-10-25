//! Vault lock / unlock.

use axum::{extract::State, http::StatusCode, response::Response};
use serde::Deserialize;
use vault::{SecretString, user};

use super::{UserRow, with_cookie};
use crate::{
    audit::{self, Event, Outcome},
    error::{ApiError, ApiResult},
    extract::{ApiJson, OptionalJson},
    session::{self, Session},
    state::AppState,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnlockInput {
    password: SecretString,
}

/// `POST /api/vault/unlock` — re-derives the MVK and rotates the session token.
pub async fn unlock(
    State(state): State<AppState>,
    s: Session,
    ApiJson(input): ApiJson<UnlockInput>,
) -> ApiResult<Response> {
    if let Some(ip) = s.ip {
        state.limits.check_auth(ip, &s.username)?;
    }
    let row = UserRow::by_id(&state, &s.user_id)
        .await?
        .ok_or(ApiError::Unauthenticated { needs_setup: false })?;
    let record = row.key_record()?;
    let uid = s.user_id.clone();
    let result = state
        .run_kdf(move || user::unlock(&uid, &record, &input.password))
        .await?;
    let mvk = match result {
        Ok(m) => m,
        Err(e) => {
            audit::record(
                &state,
                Event::new("vault.unlock", Outcome::Failure)
                    .actor(&s.user_id)
                    .ip(s.ip),
            )
            .await?;
            return Err(e.into());
        }
    };
    state.keyring.insert(s.token_hash, &s.user_id, mvk);
    let (token, _) = session::rotate(&state, &s.token_hash).await?;
    audit::record(
        &state,
        Event::new("vault.unlock", Outcome::Success)
            .actor(&s.user_id)
            .ip(s.ip),
    )
    .await?;
    Ok(with_cookie(
        session::set_cookie(&state, &token),
        StatusCode::NO_CONTENT,
        None,
    ))
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockInput {
    #[serde(default)]
    disconnect_all: bool,
}

/// `POST /api/vault/lock` — drops the MVK. `disconnect_all` also ends live sessions (none exist yet).
pub async fn lock(
    State(state): State<AppState>,
    s: Session,
    OptionalJson(input): OptionalJson<LockInput>,
) -> ApiResult<StatusCode> {
    state.keyring.remove(&s.token_hash);
    audit::record(
        &state,
        Event::new("vault.lock", Outcome::Success)
            .actor(&s.user_id)
            .ip(s.ip)
            .detail(
                "trigger",
                if input.disconnect_all {
                    "manual_disconnect_all"
                } else {
                    "manual"
                },
            ),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}
