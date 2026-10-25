//! Hash-chained, append-only audit log (docs/02 §8).

use serde_json::{Map, Value, json};
use sqlx::SqlitePool;
use vault::{Mvk, seal::RecordKind};

use crate::{
    error::ApiResult,
    state::AppState,
    util::{new_id, now_ms, sha256},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Success,
    Failure,
    Denied,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Denied => "denied",
        }
    }
}

/// One audit event. `details` must only contain allowlisted, non-identifying keys;
/// destinations/names go in `sealed`, encrypted under the actor's MVK.
#[derive(Debug)]
pub struct Event<'a> {
    pub event: &'static str,
    pub outcome: Outcome,
    pub actor_user_id: Option<&'a str>,
    pub source_ip: Option<String>,
    pub node_id: Option<&'a str>,
    pub details: Map<String, Value>,
    pub sealed: Option<(&'a Mvk, Value)>,
}

impl<'a> Event<'a> {
    pub fn new(event: &'static str, outcome: Outcome) -> Self {
        Self {
            event,
            outcome,
            actor_user_id: None,
            source_ip: None,
            node_id: None,
            details: Map::new(),
            sealed: None,
        }
    }
    pub fn actor(mut self, user_id: &'a str) -> Self {
        self.actor_user_id = Some(user_id);
        self
    }
    pub fn ip(mut self, ip: Option<std::net::IpAddr>) -> Self {
        self.source_ip = ip.map(|i| i.to_string());
        self
    }
    pub fn node(mut self, node_id: &'a str) -> Self {
        self.node_id = Some(node_id);
        self
    }
    pub fn detail(mut self, key: &str, value: impl Into<Value>) -> Self {
        self.details.insert(key.to_owned(), value.into());
        self
    }
    pub fn sealed(mut self, mvk: &'a Mvk, value: Value) -> Self {
        self.sealed = Some((mvk, value));
        self
    }
}

#[allow(clippy::too_many_arguments)]
fn canonical(
    entry_id: &str,
    ts: i64,
    actor_user_id: Option<&str>,
    actor_runner_id: Option<&str>,
    source_ip: Option<&str>,
    event: &str,
    node_id: Option<&str>,
    outcome: &str,
    details: &str,
    sealed_nonce: Option<&[u8]>,
    sealed_details: Option<&[u8]>,
) -> Vec<u8> {
    serde_json::to_vec(&json!([
        entry_id,
        ts,
        actor_user_id,
        actor_runner_id,
        source_ip,
        event,
        node_id,
        outcome,
        details,
        sealed_nonce.map(hex::encode),
        sealed_details.map(hex::encode),
    ]))
    .unwrap_or_default()
}

fn chain(prev: &[u8], canonical: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(prev.len() + canonical.len());
    buf.extend_from_slice(prev);
    buf.extend_from_slice(canonical);
    sha256(&buf)
}

/// Appends an event to the chain.
pub async fn record(state: &AppState, ev: Event<'_>) -> ApiResult<()> {
    let entry_id = new_id();
    let ts = now_ms();
    let details = Value::Object(ev.details).to_string();
    let sealed = match (&ev.sealed, ev.actor_user_id) {
        (Some((mvk, value)), Some(uid)) => {
            let plain = zeroize::Zeroizing::new(
                serde_json::to_vec(value).map_err(crate::error::ApiError::internal)?,
            );
            Some(mvk.seal(RecordKind::Audit, uid, &entry_id, &plain)?)
        }
        _ => None,
    };
    let outcome = ev.outcome.as_str();

    let _guard = state.audit_lock.lock().await;
    let mut tx = state.db.begin().await?;
    let prev: Vec<u8> =
        sqlx::query_scalar("SELECT entry_hash FROM audit_logs ORDER BY seq DESC LIMIT 1")
            .fetch_optional(&mut *tx)
            .await?
            .unwrap_or_else(|| vec![0u8; 32]);
    let canon = canonical(
        &entry_id,
        ts,
        ev.actor_user_id,
        None,
        ev.source_ip.as_deref(),
        ev.event,
        ev.node_id,
        outcome,
        &details,
        sealed.as_ref().map(|s| s.nonce.as_slice()),
        sealed.as_ref().map(|s| s.ciphertext.as_slice()),
    );
    let entry_hash = chain(&prev, &canon);
    sqlx::query(
        "INSERT INTO audit_logs (entry_id, ts, actor_user_id, actor_runner_id, source_ip, event, node_id, outcome, \
         details, sealed_nonce, sealed_details, prev_hash, entry_hash) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&entry_id)
    .bind(ts)
    .bind(ev.actor_user_id)
    .bind(ev.source_ip.as_deref())
    .bind(ev.event)
    .bind(ev.node_id)
    .bind(outcome)
    .bind(&details)
    .bind(sealed.as_ref().map(|s| s.nonce.to_vec()))
    .bind(sealed.as_ref().map(|s| s.ciphertext.clone()))
    .bind(&prev)
    .bind(entry_hash.as_slice())
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    tracing::info!(
        event = ev.event,
        outcome,
        actor = ev.actor_user_id,
        node = ev.node_id,
        "audit"
    );
    Ok(())
}

/// Best-effort audit of a vault lock triggered outside a handler's normal flow.
pub async fn vault_lock(state: &AppState, user_id: &str, trigger: &'static str) {
    if let Err(e) = record(
        state,
        Event::new("vault.lock", Outcome::Success)
            .actor(user_id)
            .detail("trigger", trigger),
    )
    .await
    {
        tracing::error!(error = %e, "audit write failed");
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct AuditRow {
    pub seq: i64,
    pub entry_id: String,
    pub ts: i64,
    pub actor_user_id: Option<String>,
    pub actor_runner_id: Option<String>,
    pub source_ip: Option<String>,
    pub event: String,
    pub node_id: Option<String>,
    pub outcome: String,
    pub details: String,
    pub sealed_nonce: Option<Vec<u8>>,
    pub sealed_details: Option<Vec<u8>>,
    pub prev_hash: Vec<u8>,
    pub entry_hash: Vec<u8>,
}

/// Result of recomputing the chain.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct VerifyReport {
    pub ok: bool,
    pub entries: u64,
    pub first_bad_seq: Option<i64>,
}

/// Recomputes every entry hash and link. Needs no keys.
pub async fn verify(db: &SqlitePool) -> anyhow::Result<VerifyReport> {
    let rows: Vec<AuditRow> = sqlx::query_as("SELECT * FROM audit_logs ORDER BY seq ASC")
        .fetch_all(db)
        .await?;
    let mut prev = vec![0u8; 32];
    let mut entries = 0u64;
    for r in &rows {
        entries += 1;
        let canon = canonical(
            &r.entry_id,
            r.ts,
            r.actor_user_id.as_deref(),
            r.actor_runner_id.as_deref(),
            r.source_ip.as_deref(),
            &r.event,
            r.node_id.as_deref(),
            &r.outcome,
            &r.details,
            r.sealed_nonce.as_deref(),
            r.sealed_details.as_deref(),
        );
        if r.prev_hash != prev || chain(&prev, &canon).as_slice() != r.entry_hash.as_slice() {
            return Ok(VerifyReport {
                ok: false,
                entries,
                first_bad_seq: Some(r.seq),
            });
        }
        prev.clone_from(&r.entry_hash);
    }
    Ok(VerifyReport {
        ok: true,
        entries,
        first_bad_seq: None,
    })
}
