//! Test harness: a gateway on a temporary data dir with cheap KDF parameters.
#![allow(dead_code)]

pub mod ssh_target;
pub mod ws;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    extract::connect_info::MockConnectInfo,
    http::{HeaderMap, Method, Request, StatusCode, header},
};
use gateway::{
    bootstrap, db, http,
    state::{AppState, Settings},
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tempfile::TempDir;
use tower::ServiceExt;
use vault::KdfParams;

pub const ORIGIN: &str = "http://127.0.0.1:8443";
pub const ADMIN: &str = "admin";
pub const ADMIN_PW: &str = "correct horse battery staple";

pub struct TestApp {
    pub state: AppState,
    pub dir: TempDir,
    pub bootstrap_token: String,
}

impl TestApp {
    pub async fn new() -> Self {
        Self::with_vault_idle(Duration::from_secs(900)).await
    }

    pub async fn with_vault_idle(vault_idle_lock: Duration) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let pool = db::open(dir.path()).await.expect("db");
        let settings = Settings {
            public_origin: ORIGIN.into(),
            secure_cookies: false,
            session_absolute: Duration::from_secs(8 * 3600),
            session_idle: Duration::from_secs(1800),
            vault_idle_lock,
            data_dir: dir.path().to_path_buf(),
            kdf: KdfParams::INSECURE_TEST,
        };
        let state = AppState::new(pool, settings, 4);
        assert!(bootstrap::init(&state).await.expect("bootstrap"));
        let bootstrap_token =
            std::fs::read_to_string(dir.path().join(bootstrap::TOKEN_FILE)).expect("token file");
        Self {
            state,
            dir,
            bootstrap_token: bootstrap_token.trim().to_owned(),
        }
    }

    pub fn router(&self, ip: IpAddr) -> Router {
        http::router(self.state.clone()).layer(MockConnectInfo(SocketAddr::new(ip, 40000)))
    }

    pub fn client(&self) -> Client<'_> {
        self.client_from(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    }

    pub fn client_from(&self, ip: IpAddr) -> Client<'_> {
        Client {
            app: self,
            ip,
            cookie: None,
            origin: Some(ORIGIN.into()),
        }
    }

    /// Runs setup and returns a logged-in admin client plus the recovery key.
    pub async fn admin(&self) -> (Client<'_>, String) {
        let mut c = self.client();
        let (status, body) = c
            .post("/api/setup", json!({ "bootstrap_token": self.bootstrap_token, "username": ADMIN, "password": ADMIN_PW }))
            .await;
        assert_eq!(status, StatusCode::CREATED, "{body}");
        let rk = body["recovery_key"].as_str().expect("rk").to_owned();
        (c, rk)
    }

    /// Bytes of every file in the data directory (db, -wal, -shm, ...).
    pub fn raw_files(&self) -> Vec<(String, Vec<u8>)> {
        std::fs::read_dir(self.dir.path())
            .expect("read dir")
            .filter_map(Result::ok)
            .filter(|e| e.path().is_file())
            .map(|e| {
                (
                    e.file_name().to_string_lossy().into_owned(),
                    std::fs::read(e.path()).expect("read"),
                )
            })
            .collect()
    }
}

pub struct Client<'a> {
    pub app: &'a TestApp,
    pub ip: IpAddr,
    pub cookie: Option<String>,
    pub origin: Option<String>,
}

impl Client<'_> {
    pub async fn send(
        &mut self,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let mut req = Request::builder().method(method).uri(path);
        if let Some(c) = &self.cookie {
            req = req.header(header::COOKIE, format!("gw_session={c}"));
        }
        if let Some(o) = &self.origin {
            req = req.header(header::ORIGIN, o);
        }
        let req = match body {
            Some(b) => req
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(b.to_string())),
            None => req.body(Body::empty()),
        }
        .expect("request");
        let res = self
            .app
            .router(self.ip)
            .oneshot(req)
            .await
            .expect("response");
        let status = res.status();
        let headers = res.headers().clone();
        for v in headers.get_all(header::SET_COOKIE) {
            let v = v.to_str().expect("cookie");
            let value = v
                .split(';')
                .next()
                .and_then(|kv| kv.split_once('='))
                .map(|(_, v)| v.to_owned());
            self.cookie = value.filter(|v| !v.is_empty());
        }
        let bytes = res.into_body().collect().await.expect("body").to_bytes();
        let json = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(Value::Null)
        };
        (status, headers, json)
    }

    pub async fn get(&mut self, path: &str) -> (StatusCode, Value) {
        let (s, _, b) = self.send(Method::GET, path, None).await;
        (s, b)
    }
    pub async fn post(&mut self, path: &str, body: Value) -> (StatusCode, Value) {
        let (s, _, b) = self.send(Method::POST, path, Some(body)).await;
        (s, b)
    }
    pub async fn post_empty(&mut self, path: &str) -> (StatusCode, Value) {
        let (s, _, b) = self.send(Method::POST, path, None).await;
        (s, b)
    }
    pub async fn put(&mut self, path: &str, body: Value) -> (StatusCode, Value) {
        let (s, _, b) = self.send(Method::PUT, path, Some(body)).await;
        (s, b)
    }
    pub async fn delete(&mut self, path: &str) -> (StatusCode, Value) {
        let (s, _, b) = self.send(Method::DELETE, path, None).await;
        (s, b)
    }

    pub async fn login(&mut self, username: &str, password: &str) -> StatusCode {
        self.post(
            "/api/auth/login",
            json!({ "username": username, "password": password }),
        )
        .await
        .0
    }
}

/// A node with distinctive values used by the plaintext scans.
pub fn ssh_node() -> Value {
    json!({
        "name": "prod-db-zeta",
        "group_path": "prod/db",
        "tags": ["tag-sensitive"],
        "protocol": "ssh",
        "host": "db-zeta.internal.example",
        "port": 2222,
        "username": "alice-target",
        "auth_method": "private_key",
        "secrets": {
            "password": "TargetP@ss-word-91",
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nc2VjcmV0LWtleS1ib2R5LXplZXRh\n-----END OPENSSH PRIVATE KEY-----\n",
            "key_passphrase": "passphrase-omega-77"
        }
    })
}

pub fn ephemeral_node() -> Value {
    json!({
        "name": "jump-ephemeral",
        "protocol": "ssh",
        "host": "jump.ephemeral.example",
        "port": 22,
        "username": null,
        "auth_method": "password",
        "ephemeral_auth": true
    })
}
