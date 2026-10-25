//! Node CRUD. All node metadata, secrets and pinned host identities are encrypted under the
//! owner's MVK (decision D-029); secrets are write-only.

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value, json};
use vault::{Mvk, SecretString, seal::RecordKind};
use zeroize::Zeroizing;

use crate::{
    audit::{self, Event, Outcome},
    error::{ApiError, ApiResult},
    extract::ApiJson,
    session::Unlocked,
    state::AppState,
    util::{new_id, now_ms},
};

/// Encrypted metadata (plaintext form inside `nodes.meta_ciphertext`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeMeta {
    name: String,
    group_path: String,
    tags: Vec<String>,
    protocol: String,
    host: String,
    port: u16,
    username: Option<String>,
    auth_method: String,
    protocol_options: Map<String, Value>,
}

/// Credential bundle (plaintext form inside `encrypted_secrets.ciphertext`).
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    password: Option<SecretString>,
    private_key: Option<SecretString>,
    key_passphrase: Option<SecretString>,
}

#[derive(Serialize)]
struct BundleRef<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key_passphrase: Option<&'a str>,
}

impl Bundle {
    fn is_empty(&self) -> bool {
        self.password.is_none() && self.private_key.is_none() && self.key_passphrase.is_none()
    }
    fn to_json(&self) -> ApiResult<Zeroizing<Vec<u8>>> {
        let r = BundleRef {
            password: self.password.as_ref().map(SecretString::expose),
            private_key: self.private_key.as_ref().map(SecretString::expose),
            key_passphrase: self.key_passphrase.as_ref().map(SecretString::expose),
        };
        // Pre-size so serialisation does not reallocate (and leave unzeroized copies behind).
        let cap = 64
            + [&self.password, &self.private_key, &self.key_passphrase]
                .iter()
                .map(|s| s.as_ref().map_or(0, |v| v.len() * 2))
                .sum::<usize>();
        let mut out = Zeroizing::new(Vec::with_capacity(cap));
        serde_json::to_writer(&mut *out, &r).map_err(ApiError::internal)?;
        Ok(out)
    }
    fn stored(&self) -> Value {
        json!({
            "password": self.password.is_some(),
            "private_key": self.private_key.is_some(),
            "key_passphrase": self.key_passphrase.is_some(),
        })
    }
}

/// absent → `None`, `null` → `Some(None)`, value → `Some(Some(v))`.
fn double_option<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Option<SecretString>>, D::Error> {
    Option::<SecretString>::deserialize(d).map(Some)
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsPatch {
    #[serde(default, deserialize_with = "double_option")]
    password: Option<Option<SecretString>>,
    #[serde(default, deserialize_with = "double_option")]
    private_key: Option<Option<SecretString>>,
    #[serde(default, deserialize_with = "double_option")]
    key_passphrase: Option<Option<SecretString>>,
}

impl SecretsPatch {
    fn sets_anything(&self) -> bool {
        [&self.password, &self.private_key, &self.key_passphrase]
            .iter()
            .any(|f| matches!(f, Some(Some(_))))
    }
    fn touches_anything(&self) -> bool {
        self.password.is_some() || self.private_key.is_some() || self.key_passphrase.is_some()
    }
    fn apply(self, mut b: Bundle) -> Bundle {
        if let Some(v) = self.password {
            b.password = v;
        }
        if let Some(v) = self.private_key {
            b.private_key = v;
        }
        if let Some(v) = self.key_passphrase {
            b.key_passphrase = v;
        }
        b
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInput {
    name: String,
    #[serde(default)]
    group_path: String,
    #[serde(default)]
    tags: Vec<String>,
    protocol: String,
    host: String,
    port: u16,
    #[serde(default)]
    username: Option<String>,
    auth_method: String,
    #[serde(default)]
    ephemeral_auth: bool,
    #[serde(default)]
    edge_pool_id: Option<String>,
    #[serde(default)]
    edge_runner_pin: Option<String>,
    #[serde(default = "yes")]
    allow_clipboard_copy: bool,
    #[serde(default = "yes")]
    allow_clipboard_paste: bool,
    #[serde(default)]
    protocol_options: Map<String, Value>,
    #[serde(default)]
    secrets: Option<SecretsPatch>,
}

fn yes() -> bool {
    true
}

fn bad(msg: &str) -> ApiError {
    ApiError::BadRequest(msg.to_owned())
}

fn printable(s: &str) -> bool {
    !s.chars().any(char::is_control)
}

impl NodeInput {
    /// Validates and splits the input into encrypted metadata and plaintext operational flags.
    fn validate(&self) -> ApiResult<NodeMeta> {
        let name = self.name.trim();
        if name.is_empty() || name.len() > 128 || !printable(name) {
            return Err(bad("name must be 1-128 printable characters"));
        }
        if self.group_path.len() > 256 || !printable(&self.group_path) {
            return Err(bad("group_path must be at most 256 printable characters"));
        }
        if self.tags.len() > 32
            || self
                .tags
                .iter()
                .any(|t| t.trim().is_empty() || t.len() > 64 || !printable(t))
        {
            return Err(bad("at most 32 tags of 1-64 printable characters"));
        }
        let host = self.host.trim();
        if host.is_empty()
            || host.len() > 253
            || host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control() || c == '/')
        {
            return Err(bad("host must be a hostname or IP address"));
        }
        if self.port == 0 {
            return Err(bad("port must be 1-65535"));
        }
        if let Some(u) = &self.username
            && (u.is_empty() || u.len() > 128 || !printable(u))
        {
            return Err(bad("username must be 1-128 printable characters or null"));
        }
        let allowed: &[&str] = match self.protocol.as_str() {
            "ssh" => &["password", "private_key", "none"],
            "vnc" => &["password", "none"],
            "rdp" => &["password"],
            _ => return Err(bad("protocol must be ssh, vnc or rdp")),
        };
        if !allowed.contains(&self.auth_method.as_str()) {
            return Err(ApiError::BadRequest(format!(
                "auth_method for {} must be one of {}",
                self.protocol,
                allowed.join(", ")
            )));
        }
        for key in self.protocol_options.keys() {
            let k = key.to_lowercase();
            if ["password", "secret", "token", "passphrase", "key"]
                .iter()
                .any(|s| k.contains(s))
            {
                return Err(bad("protocol_options must not contain secret-like keys"));
            }
        }
        if serde_json::to_vec(&self.protocol_options).map_or(usize::MAX, |v| v.len()) > 4096 {
            return Err(bad("protocol_options too large"));
        }
        if self.edge_runner_pin.is_some() && self.edge_pool_id.is_none() {
            return Err(bad("edge_runner_pin requires edge_pool_id"));
        }
        if self.ephemeral_auth
            && self
                .secrets
                .as_ref()
                .is_some_and(SecretsPatch::sets_anything)
        {
            return Err(bad("ephemeral nodes cannot store secrets"));
        }
        if let Some(Some(Some(key))) = self.secrets.as_ref().map(|s| s.private_key.as_ref()) {
            protocol_core::ssh::check_private_key(key.expose()).map_err(bad)?;
        }
        Ok(NodeMeta {
            name: name.to_owned(),
            group_path: self.group_path.trim().to_owned(),
            tags: self.tags.iter().map(|t| t.trim().to_owned()).collect(),
            protocol: self.protocol.clone(),
            host: host.to_owned(),
            port: self.port,
            username: self.username.clone(),
            auth_method: self.auth_method.clone(),
            protocol_options: self.protocol_options.clone(),
        })
    }

    /// D-030: the clipboard-copy toggle does not exist for SSH.
    fn clipboard_copy(&self) -> bool {
        self.protocol == "ssh" || self.allow_clipboard_copy
    }
}

#[derive(Debug, sqlx::FromRow)]
struct NodeRow {
    id: String,
    owner_user_id: String,
    meta_nonce: Vec<u8>,
    meta_ciphertext: Vec<u8>,
    ephemeral_auth: bool,
    edge_pool_id: Option<String>,
    edge_runner_pin: Option<String>,
    allow_clipboard_copy: bool,
    allow_clipboard_paste: bool,
    created_at: i64,
    updated_at: i64,
}

macro_rules! node_cols {
    () => {
        "id, owner_user_id, meta_nonce, meta_ciphertext, ephemeral_auth, edge_pool_id, edge_runner_pin, \
         allow_clipboard_copy, allow_clipboard_paste, created_at, updated_at"
    };
}

async fn load_row(state: &AppState, user_id: &str, id: &str) -> ApiResult<NodeRow> {
    sqlx::query_as(concat!(
        "SELECT ",
        node_cols!(),
        " FROM nodes WHERE id = ? AND owner_user_id = ?"
    ))
    .bind(id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?
    .ok_or(ApiError::NotFound)
}

fn open_meta(mvk: &Mvk, row: &NodeRow) -> ApiResult<NodeMeta> {
    let plain = mvk.open(
        RecordKind::NodeMeta,
        &row.owner_user_id,
        &row.id,
        &row.meta_nonce,
        &row.meta_ciphertext,
    )?;
    serde_json::from_slice(plain.expose()).map_err(|_| ApiError::Integrity)
}

async fn load_bundle(
    state: &AppState,
    mvk: &Mvk,
    user_id: &str,
    node_id: &str,
) -> ApiResult<Bundle> {
    let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as(
        "SELECT nonce, ciphertext FROM encrypted_secrets WHERE node_id = ? AND owner_user_id = ?",
    )
    .bind(node_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await?;
    match row {
        None => Ok(Bundle::default()),
        Some((nonce, ct)) => {
            let plain = mvk.open(RecordKind::Secrets, user_id, node_id, &nonce, &ct)?;
            serde_json::from_slice(plain.expose()).map_err(|_| ApiError::Integrity)
        }
    }
}

async fn load_host_identity(
    state: &AppState,
    mvk: &Mvk,
    user_id: &str,
    node_id: &str,
) -> ApiResult<Value> {
    let row: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT nonce, ciphertext FROM node_host_identities WHERE node_id = ? AND owner_user_id = ?")
        .bind(node_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;
    match row {
        None => Ok(Value::Null),
        Some((nonce, ct)) => {
            let plain = mvk.open(RecordKind::HostIdentity, user_id, node_id, &nonce, &ct)?;
            let v: Value =
                serde_json::from_slice(plain.expose()).map_err(|_| ApiError::Integrity)?;
            Ok(
                json!({ "kind": v.get("kind"), "algorithm": v.get("algorithm"), "fingerprint": v.get("fingerprint") }),
            )
        }
    }
}

async fn view(state: &AppState, mvk: &Mvk, row: &NodeRow) -> ApiResult<Value> {
    let meta = open_meta(mvk, row)?;
    let bundle = load_bundle(state, mvk, &row.owner_user_id, &row.id).await?;
    let host_identity = load_host_identity(state, mvk, &row.owner_user_id, &row.id).await?;
    Ok(json!({
        "id": row.id,
        "name": meta.name,
        "group_path": meta.group_path,
        "tags": meta.tags,
        "protocol": meta.protocol,
        "host": meta.host,
        "port": meta.port,
        "username": meta.username,
        "auth_method": meta.auth_method,
        "ephemeral_auth": row.ephemeral_auth,
        "edge_pool_id": row.edge_pool_id,
        "edge_runner_pin": row.edge_runner_pin,
        "allow_clipboard_copy": row.allow_clipboard_copy,
        "allow_clipboard_paste": row.allow_clipboard_paste,
        "protocol_options": meta.protocol_options,
        "secrets_stored": bundle.stored(),
        "host_identity": host_identity,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }))
}

/// Edge pool references must exist and be granted (pools arrive with the edge runner work).
async fn check_pool(state: &AppState, u: &Unlocked, input: &NodeInput) -> ApiResult<()> {
    if let Some(pool) = &input.edge_pool_id {
        let granted: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM edge_pools p WHERE p.id = ? AND (? OR EXISTS(SELECT 1 FROM edge_pool_grants g WHERE g.pool_id = p.id AND g.user_id = ?)))",
        )
        .bind(pool)
        .bind(u.session.is_admin)
        .bind(&u.session.user_id)
        .fetch_one(&state.db)
        .await?;
        if !granted {
            return Err(bad("unknown or not granted edge_pool_id"));
        }
        if let Some(pin) = &input.edge_runner_pin {
            let ok: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM edge_runners WHERE id = ? AND pool_id = ?)",
            )
            .bind(pin)
            .bind(pool)
            .fetch_one(&state.db)
            .await?;
            if !ok {
                return Err(bad("edge_runner_pin is not a runner of edge_pool_id"));
            }
        }
    }
    Ok(())
}

fn seal_meta(mvk: &Mvk, user_id: &str, node_id: &str, meta: &NodeMeta) -> ApiResult<vault::Sealed> {
    let plain = Zeroizing::new(serde_json::to_vec(meta).map_err(ApiError::internal)?);
    Ok(mvk.seal(RecordKind::NodeMeta, user_id, node_id, &plain)?)
}

async fn write_bundle(
    conn: &mut sqlx::SqliteConnection,
    mvk: &Mvk,
    user_id: &str,
    node_id: &str,
    bundle: &Bundle,
) -> ApiResult<()> {
    if bundle.is_empty() {
        sqlx::query("DELETE FROM encrypted_secrets WHERE node_id = ?")
            .bind(node_id)
            .execute(&mut *conn)
            .await?;
        return Ok(());
    }
    let plain = bundle.to_json()?;
    let sealed = mvk.seal(RecordKind::Secrets, user_id, node_id, &plain)?;
    let now = now_ms();
    sqlx::query(
        "INSERT INTO encrypted_secrets (node_id, owner_user_id, aead, nonce, ciphertext, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?) \
         ON CONFLICT(node_id) DO UPDATE SET nonce = excluded.nonce, ciphertext = excluded.ciphertext, updated_at = excluded.updated_at",
    )
    .bind(node_id)
    .bind(user_id)
    .bind(vault::AEAD_ID)
    .bind(sealed.nonce.as_slice())
    .bind(&sealed.ciphertext)
    .bind(now)
    .bind(now)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// `GET /api/nodes`
pub async fn list(State(state): State<AppState>, u: Unlocked) -> ApiResult<Json<Vec<Value>>> {
    let rows: Vec<NodeRow> = sqlx::query_as(concat!(
        "SELECT ",
        node_cols!(),
        " FROM nodes WHERE owner_user_id = ? ORDER BY created_at"
    ))
    .bind(&u.session.user_id)
    .fetch_all(&state.db)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in &rows {
        out.push(view(&state, &u.mvk, row).await?);
    }
    Ok(Json(out))
}

/// `GET /api/nodes/{id}`
pub async fn get(
    State(state): State<AppState>,
    u: Unlocked,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let row = load_row(&state, &u.session.user_id, &id).await?;
    Ok(Json(view(&state, &u.mvk, &row).await?))
}

/// `POST /api/nodes`
pub async fn create(
    State(state): State<AppState>,
    u: Unlocked,
    ApiJson(input): ApiJson<NodeInput>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let meta = input.validate()?;
    check_pool(&state, &u, &input).await?;
    let uid = &u.session.user_id;
    let id = new_id();
    let sealed = seal_meta(&u.mvk, uid, &id, &meta)?;
    let now = now_ms();
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "INSERT INTO nodes (id, owner_user_id, meta_aead, meta_nonce, meta_ciphertext, ephemeral_auth, edge_pool_id, edge_runner_pin, \
         allow_clipboard_copy, allow_clipboard_paste, allow_file_transfer, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)",
    )
    .bind(&id)
    .bind(uid)
    .bind(vault::AEAD_ID)
    .bind(sealed.nonce.as_slice())
    .bind(&sealed.ciphertext)
    .bind(input.ephemeral_auth)
    .bind(&input.edge_pool_id)
    .bind(&input.edge_runner_pin)
    .bind(input.clipboard_copy())
    .bind(input.allow_clipboard_paste)
    .bind(now)
    .bind(now)
    .execute(&mut *tx)
    .await?;
    let secrets_set = input
        .secrets
        .as_ref()
        .is_some_and(SecretsPatch::sets_anything);
    if !input.ephemeral_auth
        && let Some(patch) = input.secrets
    {
        write_bundle(&mut tx, &u.mvk, uid, &id, &patch.apply(Bundle::default())).await?;
    }
    tx.commit().await?;
    audit::record(
        &state,
        Event::new("node.created", Outcome::Success)
            .actor(uid)
            .ip(u.session.ip)
            .node(&id)
            .detail("fields_changed", if secrets_set { json!(["metadata", "secrets"]) } else { json!(["metadata"]) })
            .sealed(&u.mvk, json!({ "node_name": meta.name, "target": format!("{}:{}", meta.host, meta.port), "protocol": meta.protocol })),
    )
    .await?;
    let row = load_row(&state, uid, &id).await?;
    Ok((StatusCode::CREATED, Json(view(&state, &u.mvk, &row).await?)))
}

/// `PUT /api/nodes/{id}`
pub async fn update(
    State(state): State<AppState>,
    u: Unlocked,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<NodeInput>,
) -> ApiResult<Json<Value>> {
    let uid = &u.session.user_id;
    let row = load_row(&state, uid, &id).await?;
    let old = open_meta(&u.mvk, &row)?;
    let meta = input.validate()?;
    check_pool(&state, &u, &input).await?;

    let mut changed: Vec<&str> = Vec::new();
    macro_rules! diff {
        ($($f:ident),*) => { $( if old.$f != meta.$f { changed.push(stringify!($f)); } )* };
    }
    diff!(
        name,
        group_path,
        tags,
        protocol,
        host,
        port,
        username,
        auth_method,
        protocol_options
    );
    if row.ephemeral_auth != input.ephemeral_auth {
        changed.push("ephemeral_auth");
    }
    if row.edge_pool_id != input.edge_pool_id || row.edge_runner_pin != input.edge_runner_pin {
        changed.push("routing");
    }
    if row.allow_clipboard_copy != input.clipboard_copy()
        || row.allow_clipboard_paste != input.allow_clipboard_paste
    {
        changed.push("policy");
    }
    let target_changed =
        old.host != meta.host || old.port != meta.port || old.protocol != meta.protocol;

    let sealed = seal_meta(&u.mvk, uid, &id, &meta)?;
    let mut tx = state.db.begin().await?;
    sqlx::query(
        "UPDATE nodes SET meta_nonce = ?, meta_ciphertext = ?, ephemeral_auth = ?, edge_pool_id = ?, edge_runner_pin = ?, \
         allow_clipboard_copy = ?, allow_clipboard_paste = ?, updated_at = ? WHERE id = ? AND owner_user_id = ?",
    )
    .bind(sealed.nonce.as_slice())
    .bind(&sealed.ciphertext)
    .bind(input.ephemeral_auth)
    .bind(&input.edge_pool_id)
    .bind(&input.edge_runner_pin)
    .bind(input.clipboard_copy())
    .bind(input.allow_clipboard_paste)
    .bind(now_ms())
    .bind(&id)
    .bind(uid)
    .execute(&mut *tx)
    .await?;
    if input.ephemeral_auth {
        // The nodes_ephemeral_purge trigger also enforces this.
        sqlx::query("DELETE FROM encrypted_secrets WHERE node_id = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    } else if let Some(patch) = input.secrets.filter(SecretsPatch::touches_anything) {
        let current = load_bundle(&state, &u.mvk, uid, &id).await?;
        write_bundle(&mut tx, &u.mvk, uid, &id, &patch.apply(current)).await?;
        changed.push("secrets");
    }
    if target_changed {
        // A pinned host identity belongs to the previous target.
        sqlx::query("DELETE FROM node_host_identities WHERE node_id = ?")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    audit::record(
        &state,
        Event::new("node.updated", Outcome::Success)
            .actor(uid)
            .ip(u.session.ip)
            .node(&id)
            .detail("fields_changed", json!(changed))
            .sealed(&u.mvk, json!({ "node_name": meta.name, "target": format!("{}:{}", meta.host, meta.port), "protocol": meta.protocol })),
    )
    .await?;
    let row = load_row(&state, uid, &id).await?;
    Ok(Json(view(&state, &u.mvk, &row).await?))
}

/// `DELETE /api/nodes/{id}`
pub async fn delete(
    State(state): State<AppState>,
    u: Unlocked,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    let uid = &u.session.user_id;
    let row = load_row(&state, uid, &id).await?;
    let name = open_meta(&u.mvk, &row).map(|m| m.name).unwrap_or_default();
    sqlx::query("DELETE FROM nodes WHERE id = ? AND owner_user_id = ?")
        .bind(&id)
        .bind(uid)
        .execute(&state.db)
        .await?;
    audit::record(
        &state,
        Event::new("node.deleted", Outcome::Success)
            .actor(uid)
            .ip(u.session.ip)
            .node(&id)
            .sealed(&u.mvk, json!({ "node_name": name })),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetInput {
    confirm_name: String,
}

/// `POST /api/nodes/{id}/host-identity/reset` — removes the pinned SSH host key / RDP certificate.
pub async fn reset_host_identity(
    State(state): State<AppState>,
    u: Unlocked,
    Path(id): Path<String>,
    ApiJson(input): ApiJson<ResetInput>,
) -> ApiResult<StatusCode> {
    let uid = &u.session.user_id;
    let row = load_row(&state, uid, &id).await?;
    let meta = open_meta(&u.mvk, &row)?;
    if input.confirm_name != meta.name {
        return Err(bad("confirm_name does not match the node name"));
    }
    let res =
        sqlx::query("DELETE FROM node_host_identities WHERE node_id = ? AND owner_user_id = ?")
            .bind(&id)
            .bind(uid)
            .execute(&state.db)
            .await?;
    audit::record(
        &state,
        Event::new("node.host_identity_reset", Outcome::Success)
            .actor(uid)
            .ip(u.session.ip)
            .node(&id)
            .detail("had_pin", res.rows_affected() > 0)
            .sealed(&u.mvk, json!({ "node_name": meta.name })),
    )
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Everything a stream needs to connect to a node (plaintext lives only in memory and is
/// zeroized on drop).
#[derive(Debug)]
pub struct ConnectTarget {
    pub node_id: String,
    pub name: String,
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    pub auth_method: String,
    pub ephemeral: bool,
    pub edge_pool_id: Option<String>,
    pub allow_clipboard_paste: bool,
    pub allow_clipboard_copy: bool,
    pub password: Option<SecretString>,
    pub private_key: Option<SecretString>,
    pub key_passphrase: Option<SecretString>,
    /// Pinned identity: (kind, algorithm, fingerprint, public key bytes).
    pub pinned: Option<PinnedIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PinnedIdentity {
    pub kind: String,
    pub algorithm: String,
    pub fingerprint: String,
    /// Base64 (standard) of the SSH wire-format public key / RDP SPKI.
    pub public_key: String,
}

/// Loads and decrypts a node for connecting (ownership enforced).
pub async fn connect_target(
    state: &AppState,
    mvk: &Mvk,
    user_id: &str,
    node_id: &str,
) -> ApiResult<ConnectTarget> {
    let row = load_row(state, user_id, node_id).await?;
    let meta = open_meta(mvk, &row)?;
    let bundle = if row.ephemeral_auth {
        Bundle::default()
    } else {
        load_bundle(state, mvk, user_id, node_id).await?
    };
    let pin: Option<(Vec<u8>, Vec<u8>)> = sqlx::query_as("SELECT nonce, ciphertext FROM node_host_identities WHERE node_id = ? AND owner_user_id = ?")
        .bind(node_id)
        .bind(user_id)
        .fetch_optional(&state.db)
        .await?;
    let pinned = match pin {
        None => None,
        Some((nonce, ct)) => {
            let plain = mvk.open(RecordKind::HostIdentity, user_id, node_id, &nonce, &ct)?;
            Some(serde_json::from_slice(plain.expose()).map_err(|_| ApiError::Integrity)?)
        }
    };
    Ok(ConnectTarget {
        node_id: row.id,
        name: meta.name,
        protocol: meta.protocol,
        host: meta.host,
        port: meta.port,
        username: meta.username,
        auth_method: meta.auth_method,
        ephemeral: row.ephemeral_auth,
        edge_pool_id: row.edge_pool_id,
        allow_clipboard_paste: row.allow_clipboard_paste,
        allow_clipboard_copy: row.allow_clipboard_copy,
        password: bundle.password,
        private_key: bundle.private_key,
        key_passphrase: bundle.key_passphrase,
        pinned,
    })
}

/// Stores (replaces) the pinned host identity of a node (TOFU approval, D-043).
pub async fn pin_host_identity(
    state: &AppState,
    mvk: &Mvk,
    user_id: &str,
    node_id: &str,
    id: &PinnedIdentity,
) -> ApiResult<()> {
    let plain = serde_json::to_vec(id).map_err(ApiError::internal)?;
    let sealed = mvk.seal(RecordKind::HostIdentity, user_id, node_id, &plain)?;
    sqlx::query(
        "INSERT INTO node_host_identities (node_id, owner_user_id, aead, nonce, ciphertext, approved_at) VALUES (?, ?, ?, ?, ?, ?) \
         ON CONFLICT(node_id) DO UPDATE SET aead = excluded.aead, nonce = excluded.nonce, ciphertext = excluded.ciphertext, approved_at = excluded.approved_at",
    )
    .bind(node_id)
    .bind(user_id)
    .bind(vault::AEAD_ID)
    .bind(sealed.nonce.as_slice())
    .bind(sealed.ciphertext.as_slice())
    .bind(now_ms())
    .execute(&state.db)
    .await?;
    Ok(())
}
