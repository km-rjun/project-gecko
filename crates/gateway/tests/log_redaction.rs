//! Secrets never reach logs, even at TRACE level. Own test binary: tracing's callsite interest
//! cache is process-global, so this must not share a process with tests that run without a subscriber.

mod common;

use std::{
    io::Write,
    sync::{Arc, Mutex},
};

use axum::http::StatusCode;
use common::*;
use serde_json::json;

const NEEDLES: &[&str] = &[
    "TargetP@ss-word-91",
    "c2VjcmV0LWtleS1ib2R5",
    "BEGIN OPENSSH PRIVATE KEY",
    "passphrase-omega-77",
    "db-zeta.internal.example",
    "alice-target",
    ADMIN_PW,
];

fn assert_absent(haystack: &[u8], needles: &[&str]) {
    for n in needles {
        assert!(
            !haystack.windows(n.len()).any(|w| w == n.as_bytes()),
            "{n:?} found in logs"
        );
    }
}

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("lock").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn trace_logs_never_contain_secrets() {
    let capture = Capture::default();
    let sink = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || sink.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let app = TestApp::new().await;
    let (mut admin, rk) = app.admin().await;
    let (_, node) = admin.post("/api/nodes", ssh_node()).await;
    let id = node["id"].as_str().expect("id").to_owned();
    admin.get("/api/nodes").await;
    assert_eq!(
        admin.post_empty("/api/vault/lock").await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin
            .post("/api/vault/unlock", json!({ "password": ADMIN_PW }))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    let mut update = ssh_node();
    update["secrets"] = json!({ "password": "TargetP@ss-word-91" });
    admin.put(&format!("/api/nodes/{id}"), update).await;
    admin
        .post(
            "/api/auth/login",
            json!({ "username": ADMIN, "password": "wrong password here" }),
        )
        .await;
    let session = admin.cookie.clone().expect("cookie");

    let logs = capture.0.lock().expect("lock").clone();
    assert!(!logs.is_empty(), "subscriber captured nothing");
    let mut needles: Vec<&str> = NEEDLES.to_vec();
    needles.extend([
        rk.as_str(),
        session.as_str(),
        app.bootstrap_token.as_str(),
        "wrong password here",
    ]);
    assert_absent(&logs, &needles);
}
