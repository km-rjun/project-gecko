//! REST API handlers (docs/02 §10).

pub mod account;
pub mod admin;
pub mod audit_api;
pub mod auth;
pub mod invites;
pub mod nodes;
pub mod vault_api;

use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Serialize;
use vault::{KdfParams, UserKeyRecord};

use crate::{
    error::{ApiError, ApiResult},
    state::AppState,
    util::now_ms,
};

/// JSON (or empty) response with a `Set-Cookie` header.
pub fn with_cookie(
    cookie: String,
    status: StatusCode,
    body: Option<serde_json::Value>,
) -> Response {
    let mut res = match body {
        Some(b) => (status, Json(b)).into_response(),
        None => status.into_response(),
    };
    if let Ok(v) = HeaderValue::from_str(&cookie) {
        res.headers_mut().append(header::SET_COOKIE, v);
    }
    res
}

/// Public view of an account.
#[derive(Debug, Serialize)]
pub struct UserView {
    pub id: String,
    pub username: String,
    pub is_admin: bool,
}

/// Validates an account username: 3–64 chars of `[A-Za-z0-9._-]`.
pub fn validate_username(name: &str) -> ApiResult<()> {
    let ok = (3..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest(
            "username must be 3-64 characters of A-Z a-z 0-9 . _ -".into(),
        ))
    }
}

/// Account row with key material.
#[derive(Debug, sqlx::FromRow)]
pub struct UserRow {
    pub id: String,
    pub username: String,
    pub is_admin: bool,
    pub disabled: bool,
    pub kdf_m_kib: i64,
    pub kdf_t: i64,
    pub kdf_p: i64,
    pub kdf_salt: Vec<u8>,
    pub auth_verifier: Vec<u8>,
    pub mvk_nonce: Vec<u8>,
    pub mvk_wrapped: Vec<u8>,
    pub rk_salt: Vec<u8>,
    pub mvk_rk_nonce: Vec<u8>,
    pub mvk_rk_wrapped: Vec<u8>,
}

macro_rules! user_cols {
    () => {
        "id, username, is_admin, disabled, kdf_m_kib, kdf_t, kdf_p, kdf_salt, auth_verifier, \
         mvk_nonce, mvk_wrapped, rk_salt, mvk_rk_nonce, mvk_rk_wrapped"
    };
}

impl UserRow {
    pub async fn by_username(state: &AppState, username: &str) -> ApiResult<Option<Self>> {
        Ok(sqlx::query_as(concat!(
            "SELECT ",
            user_cols!(),
            " FROM users WHERE username = ?"
        ))
        .bind(username)
        .fetch_optional(&state.db)
        .await?)
    }

    pub async fn by_id(state: &AppState, id: &str) -> ApiResult<Option<Self>> {
        Ok(
            sqlx::query_as(concat!("SELECT ", user_cols!(), " FROM users WHERE id = ?"))
                .bind(id)
                .fetch_optional(&state.db)
                .await?,
        )
    }

    pub fn key_record(&self) -> ApiResult<UserKeyRecord> {
        let m = |what| ApiError::from(vault::VaultError::Malformed(what));
        let p = |v: i64| u32::try_from(v).map_err(|_| m("kdf params"));
        Ok(UserKeyRecord {
            kdf: KdfParams {
                m_kib: p(self.kdf_m_kib)?,
                t: p(self.kdf_t)?,
                p: p(self.kdf_p)?,
            },
            kdf_salt: self
                .kdf_salt
                .as_slice()
                .try_into()
                .map_err(|_| m("kdf_salt"))?,
            auth_verifier: self
                .auth_verifier
                .as_slice()
                .try_into()
                .map_err(|_| m("auth_verifier"))?,
            mvk_nonce: self
                .mvk_nonce
                .as_slice()
                .try_into()
                .map_err(|_| m("mvk_nonce"))?,
            mvk_wrapped: self.mvk_wrapped.clone(),
            rk_salt: self
                .rk_salt
                .as_slice()
                .try_into()
                .map_err(|_| m("rk_salt"))?,
            mvk_rk_nonce: self
                .mvk_rk_nonce
                .as_slice()
                .try_into()
                .map_err(|_| m("mvk_rk_nonce"))?,
            mvk_rk_wrapped: self.mvk_rk_wrapped.clone(),
        })
    }

    pub fn view(&self) -> UserView {
        UserView {
            id: self.id.clone(),
            username: self.username.clone(),
            is_admin: self.is_admin,
        }
    }
}

/// Inserts a new account.
pub async fn insert_user(
    conn: &mut sqlx::SqliteConnection,
    id: &str,
    username: &str,
    is_admin: bool,
    r: &UserKeyRecord,
) -> ApiResult<()> {
    let now = now_ms();
    let res = sqlx::query(
        "INSERT INTO users (id, username, is_admin, disabled, kdf_alg, kdf_m_kib, kdf_t, kdf_p, kdf_salt, auth_verifier, \
         mvk_nonce, mvk_wrapped, rk_salt, mvk_rk_nonce, mvk_rk_wrapped, crypto_version, created_at, updated_at, password_changed_at) \
         VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(id)
    .bind(username)
    .bind(is_admin)
    .bind(vault::kdf::KDF_ALG)
    .bind(i64::from(r.kdf.m_kib))
    .bind(i64::from(r.kdf.t))
    .bind(i64::from(r.kdf.p))
    .bind(r.kdf_salt.as_slice())
    .bind(r.auth_verifier.as_slice())
    .bind(r.mvk_nonce.as_slice())
    .bind(r.mvk_wrapped.as_slice())
    .bind(r.rk_salt.as_slice())
    .bind(r.mvk_rk_nonce.as_slice())
    .bind(r.mvk_rk_wrapped.as_slice())
    .bind(i64::from(vault::CRYPTO_VERSION))
    .bind(now)
    .bind(now)
    .bind(now)
    .execute(&mut *conn)
    .await;
    match res {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            Err(ApiError::Conflict("username already taken"))
        }
        Err(e) => Err(e.into()),
    }
}

/// Persists all key columns of an account (password change, recovery, KDF upgrade).
pub async fn update_key_record(
    state: &AppState,
    user_id: &str,
    r: &UserKeyRecord,
    password_changed: bool,
) -> ApiResult<()> {
    let now = now_ms();
    sqlx::query(
        "UPDATE users SET kdf_m_kib = ?, kdf_t = ?, kdf_p = ?, kdf_salt = ?, auth_verifier = ?, mvk_nonce = ?, \
         mvk_wrapped = ?, rk_salt = ?, mvk_rk_nonce = ?, mvk_rk_wrapped = ?, updated_at = ?, \
         password_changed_at = CASE WHEN ? THEN ? ELSE password_changed_at END WHERE id = ?",
    )
    .bind(i64::from(r.kdf.m_kib))
    .bind(i64::from(r.kdf.t))
    .bind(i64::from(r.kdf.p))
    .bind(r.kdf_salt.as_slice())
    .bind(r.auth_verifier.as_slice())
    .bind(r.mvk_nonce.as_slice())
    .bind(r.mvk_wrapped.as_slice())
    .bind(r.rk_salt.as_slice())
    .bind(r.mvk_rk_nonce.as_slice())
    .bind(r.mvk_rk_wrapped.as_slice())
    .bind(now)
    .bind(password_changed)
    .bind(now)
    .bind(user_id)
    .execute(&state.db)
    .await?;
    Ok(())
}
