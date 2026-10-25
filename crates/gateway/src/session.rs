//! Login sessions: cookie handling and request extractors (docs/02 §7).
//!
//! Each session has a stable `session_id` (keys the keyring and live sockets) and a cookie token
//! that is rotated on login/unlock; only SHA-256(token) is stored.

use std::{net::SocketAddr, sync::Arc};

use axum::{
    extract::{ConnectInfo, FromRequestParts},
    http::{HeaderMap, Method, header, request::Parts},
};
use vault::Mvk;

use crate::{
    error::{ApiError, ApiResult},
    keyring::VaultState,
    state::AppState,
    util::{new_id, now_ms, random_token, token_hash},
};

/// Cookie name: `__Host-` prefix whenever cookies are `Secure` (TLS modes).
pub fn cookie_name(secure: bool) -> &'static str {
    if secure {
        "__Host-gw_session"
    } else {
        "gw_session"
    }
}

/// `Set-Cookie` value for a new session token.
pub fn set_cookie(state: &AppState, token: &str) -> String {
    let s = &state.settings;
    let mut c = format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={}",
        cookie_name(s.secure_cookies),
        s.session_absolute.as_secs()
    );
    if s.secure_cookies {
        c.push_str("; Secure");
    }
    c
}

/// `Set-Cookie` value that clears the session cookie.
pub fn clear_cookie(state: &AppState) -> String {
    let secure = state.settings.secure_cookies;
    let mut c = format!(
        "{}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0",
        cookie_name(secure)
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

/// Extracts the session token from the `Cookie` header(s).
pub fn read_token(headers: &HeaderMap, secure: bool) -> Option<String> {
    let name = cookie_name(secure);
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.to_owned())
        .filter(|v| !v.is_empty())
}

/// Client socket address. Proxy headers are never trusted (only L4 passthrough is supported).
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub std::net::IpAddr);

impl FromRequestParts<AppState> for ClientIp {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .map(|ci| ClientIp(ci.0.ip()))
            .map_err(|_| ApiError::internal(anyhow::anyhow!("missing connect info")))
    }
}

/// Creates a session; returns the raw cookie token and the stable session id.
pub async fn create(
    state: &AppState,
    user_id: &str,
    ip: &str,
    user_agent: &str,
) -> ApiResult<(zeroize::Zeroizing<String>, String)> {
    let token = random_token()?;
    let session_id = new_id();
    let now = now_ms();
    let expires =
        now + i64::try_from(state.settings.session_absolute.as_millis()).unwrap_or(i64::MAX);
    sqlx::query(
        "INSERT INTO auth_sessions (token_hash, session_id, user_id, created_at, last_seen_at, expires_at, ip, user_agent) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(token_hash(&token).as_slice())
    .bind(&session_id)
    .bind(user_id)
    .bind(now)
    .bind(now)
    .bind(expires)
    .bind(ip)
    .bind(user_agent.chars().take(256).collect::<String>())
    .execute(&state.db)
    .await?;
    Ok((token, session_id))
}

/// Replaces the cookie token of a session (unlock rotation). Keeps id, creation and expiry.
pub async fn rotate(state: &AppState, session_id: &str) -> ApiResult<zeroize::Zeroizing<String>> {
    let token = random_token()?;
    let updated = sqlx::query(
        "UPDATE auth_sessions SET token_hash = ?, last_seen_at = ? WHERE session_id = ?",
    )
    .bind(token_hash(&token).as_slice())
    .bind(now_ms())
    .bind(session_id)
    .execute(&state.db)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(ApiError::Unauthenticated { needs_setup: false });
    }
    Ok(token)
}

/// Ends one session everywhere: DB row, keyring entry, live sockets.
pub async fn end(state: &AppState, session_id: &str) -> ApiResult<()> {
    sqlx::query("DELETE FROM auth_sessions WHERE session_id = ?")
        .bind(session_id)
        .execute(&state.db)
        .await?;
    state.keyring.remove(session_id);
    state.hub.close_session(session_id);
    Ok(())
}

/// Ends all sessions of a user, optionally keeping one.
pub async fn revoke_user(state: &AppState, user_id: &str, keep: Option<&str>) -> ApiResult<()> {
    let ids: Vec<String> =
        sqlx::query_scalar("SELECT session_id FROM auth_sessions WHERE user_id = ?")
            .bind(user_id)
            .fetch_all(&state.db)
            .await?;
    for id in ids.iter().filter(|id| Some(id.as_str()) != keep) {
        end(state, id).await?;
    }
    state.keyring.remove_user(user_id, keep);
    Ok(())
}

/// Refreshes the session idle timer (throttled to once per minute).
pub async fn touch(state: &AppState, session_id: &str) -> ApiResult<()> {
    let now = now_ms();
    sqlx::query(
        "UPDATE auth_sessions SET last_seen_at = ? WHERE session_id = ? AND last_seen_at < ?",
    )
    .bind(now)
    .bind(session_id)
    .bind(now - 60_000)
    .execute(&state.db)
    .await?;
    Ok(())
}

/// An authenticated login session (vault may be locked).
#[derive(Debug, Clone)]
pub struct Session {
    pub session_id: String,
    pub user_id: String,
    pub username: String,
    pub is_admin: bool,
    pub expires_at: i64,
    pub ip: Option<std::net::IpAddr>,
}

#[derive(sqlx::FromRow)]
struct SessionRow {
    session_id: String,
    user_id: String,
    last_seen_at: i64,
    expires_at: i64,
    username: String,
    is_admin: bool,
    disabled: bool,
}

async fn needs_setup(state: &AppState) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .map(|n| n == 0)
        .unwrap_or(false)
}

impl Session {
    fn validate(state: &AppState, row: SessionRow) -> Option<Self> {
        let now = now_ms();
        let idle_ms = i64::try_from(state.settings.session_idle.as_millis()).unwrap_or(i64::MAX);
        if row.disabled || now >= row.expires_at || now - row.last_seen_at > idle_ms {
            return None;
        }
        Some(Self {
            session_id: row.session_id,
            user_id: row.user_id,
            username: row.username,
            is_admin: row.is_admin,
            expires_at: row.expires_at,
            ip: None,
        })
    }

    /// Validates the cookie; `Ok(None)` when absent or invalid (an invalid session is ended).
    pub async fn load(state: &AppState, headers: &HeaderMap) -> ApiResult<Option<Self>> {
        let Some(token) = read_token(headers, state.settings.secure_cookies) else {
            return Ok(None);
        };
        let row: Option<SessionRow> = sqlx::query_as(
            "SELECT s.session_id, s.user_id, s.last_seen_at, s.expires_at, u.username, u.is_admin, u.disabled \
             FROM auth_sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
        )
        .bind(token_hash(&token).as_slice())
        .fetch_optional(&state.db)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let id = row.session_id.clone();
        match Self::validate(state, row) {
            Some(s) => {
                touch(state, &s.session_id).await?;
                Ok(Some(s))
            }
            None => {
                end(state, &id).await?;
                Ok(None)
            }
        }
    }

    /// Re-validates a session by id (used by long-lived sockets).
    pub async fn by_id(state: &AppState, session_id: &str) -> ApiResult<Option<Self>> {
        let row: Option<SessionRow> = sqlx::query_as(
            "SELECT s.session_id, s.user_id, s.last_seen_at, s.expires_at, u.username, u.is_admin, u.disabled \
             FROM auth_sessions s JOIN users u ON u.id = s.user_id WHERE s.session_id = ?",
        )
        .bind(session_id)
        .fetch_optional(&state.db)
        .await?;
        Ok(row.and_then(|r| Self::validate(state, r)))
    }
}

impl FromRequestParts<AppState> for Session {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        match Session::load(state, &parts.headers).await? {
            Some(mut s) => {
                s.ip = ClientIp::from_request_parts(parts, state)
                    .await
                    .ok()
                    .map(|c| c.0);
                Ok(s)
            }
            None => Err(ApiError::Unauthenticated {
                needs_setup: needs_setup(state).await,
            }),
        }
    }
}

/// Session whose vault is unlocked. Mutating requests count as activity for the idle lock.
#[derive(Debug, Clone)]
pub struct Unlocked {
    pub session: Session,
    pub mvk: Arc<Mvk>,
}

impl FromRequestParts<AppState> for Unlocked {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let session = Session::from_request_parts(parts, state).await?;
        match state.keyring.state(&session.session_id) {
            VaultState::Unlocked(mvk) => {
                if parts.method != Method::GET && parts.method != Method::HEAD {
                    state.keyring.touch(&session.session_id);
                }
                Ok(Self { session, mvk })
            }
            VaultState::IdleLocked => {
                crate::audit::vault_lock(state, &session.user_id, "idle").await;
                Err(ApiError::VaultLocked)
            }
            VaultState::Locked => Err(ApiError::VaultLocked),
        }
    }
}

/// Unlocked session of an administrator.
#[derive(Debug, Clone)]
pub struct Admin(pub Unlocked);

impl FromRequestParts<AppState> for Admin {
    type Rejection = ApiError;
    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> ApiResult<Self> {
        let u = Unlocked::from_request_parts(parts, state).await?;
        if !u.session.is_admin {
            return Err(ApiError::Forbidden("administrator only"));
        }
        Ok(Self(u))
    }
}

/// `User-Agent` header, truncated.
pub fn user_agent(headers: &HeaderMap) -> String {
    headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .chars()
        .take(256)
        .collect()
}
