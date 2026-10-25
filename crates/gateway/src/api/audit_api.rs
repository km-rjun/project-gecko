//! Audit log listing and verification.

use axum::{
    Json,
    extract::{Query, State},
};
use serde::Deserialize;
use serde_json::{Value, json};
use vault::{Mvk, seal::RecordKind};

use crate::{
    audit::{self, AuditRow, VerifyReport},
    error::{ApiError, ApiResult},
    session::{Admin, Unlocked},
    state::AppState,
};

#[derive(Debug, Deserialize)]
pub struct Page {
    before_seq: Option<i64>,
    limit: Option<i64>,
}

fn render(rows: Vec<AuditRow>, me: &str, mvk: &Mvk) -> ApiResult<Vec<Value>> {
    rows.into_iter()
        .map(|r| {
            let sealed = match (
                &r.sealed_nonce,
                &r.sealed_details,
                r.actor_user_id.as_deref(),
            ) {
                (Some(nonce), Some(ct), Some(actor)) if actor == me => {
                    let plain = mvk.open(RecordKind::Audit, actor, &r.entry_id, nonce, ct)?;
                    Some(
                        serde_json::from_slice::<Value>(plain.expose())
                            .map_err(|_| ApiError::Integrity)?,
                    )
                }
                _ => None,
            };
            Ok(json!({
                "seq": r.seq,
                "entry_id": r.entry_id,
                "ts": r.ts,
                "actor_user_id": r.actor_user_id,
                "actor_runner_id": r.actor_runner_id,
                "source_ip": r.source_ip,
                "event": r.event,
                "node_id": r.node_id,
                "outcome": r.outcome,
                "details": serde_json::from_str::<Value>(&r.details).unwrap_or(Value::Null),
                "sealed_present": r.sealed_details.is_some(),
                "sealed": sealed,
            }))
        })
        .collect()
}

fn bounds(p: &Page) -> (i64, i64) {
    (
        p.before_seq.unwrap_or(i64::MAX),
        p.limit.unwrap_or(100).clamp(1, 500),
    )
}

/// `GET /api/audit` — the caller's own events.
pub async fn own(
    State(state): State<AppState>,
    u: Unlocked,
    Query(p): Query<Page>,
) -> ApiResult<Json<Vec<Value>>> {
    let (before, limit) = bounds(&p);
    let rows = sqlx::query_as(
        "SELECT * FROM audit_logs WHERE actor_user_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?",
    )
    .bind(&u.session.user_id)
    .bind(before)
    .bind(limit)
    .fetch_all(&state.db)
    .await?;
    Ok(Json(render(rows, &u.session.user_id, &u.mvk)?))
}

/// `GET /api/admin/audit` — all events; sealed details only for the admin's own entries.
pub async fn all(
    State(state): State<AppState>,
    Admin(u): Admin,
    Query(p): Query<Page>,
) -> ApiResult<Json<Vec<Value>>> {
    let (before, limit) = bounds(&p);
    let rows = sqlx::query_as("SELECT * FROM audit_logs WHERE seq < ? ORDER BY seq DESC LIMIT ?")
        .bind(before)
        .bind(limit)
        .fetch_all(&state.db)
        .await?;
    Ok(Json(render(rows, &u.session.user_id, &u.mvk)?))
}

/// `GET /api/admin/audit/verify`
pub async fn verify(State(state): State<AppState>, _: Admin) -> ApiResult<Json<VerifyReport>> {
    Ok(Json(
        audit::verify(&state.db).await.map_err(ApiError::internal)?,
    ))
}
