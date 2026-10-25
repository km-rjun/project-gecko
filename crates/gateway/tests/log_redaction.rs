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
            "{n:?} found in logs: {}",
            String::from_utf8_lossy(haystack)
                .lines()
                .filter(|l| l.contains(n))
                .map(|l| l.chars().take(400).collect::<String>())
                .collect::<Vec<_>>()
                .join("\n")
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

/// A full SSH session (stored key, ephemeral password, typed text) logs no credentials and no
/// terminal content (a password typed at a `sudo` prompt is terminal content).
#[tokio::test(flavor = "current_thread")]
async fn ssh_session_trace_logs_never_contain_secrets_or_terminal_data() {
    use common::{ssh_target, ws};
    use protocol_core::wire::Opcode;

    let capture = Capture::default();
    let sink = capture.clone();
    // Same layering as production `init_tracing`, with everything enabled.
    let subscriber = {
        use tracing_subscriber::{Layer, layer::SubscriberExt};
        let fmt = tracing_subscriber::fmt::layer().with_writer(move || sink.clone());
        tracing_subscriber::registry().with(
            fmt.with_filter(tracing_subscriber::filter::LevelFilter::TRACE)
                .with_filter(gateway::logging::payload_guard()),
        )
    };
    let _guard = tracing::subscriber::set_default(subscriber);
    // Production `init()` bridges `log` records (russh logs through `log`) into tracing.
    let _ = tracing_log::LogTracer::init();

    let client_key = ssh_target::ed25519(7);
    let target = ssh_target::start(ssh_target::ed25519(1), client_key.public_key().clone()).await;
    let app = TestApp::new().await;
    let addr = ws::serve(&app).await;
    let (mut admin, _) = app.admin().await;
    let pem = client_key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("pem");
    let (_, key_node) = admin
        .post("/api/nodes", json!({ "name": "log-key", "protocol": "ssh", "host": "127.0.0.1", "port": target.addr.port(), "username": ssh_target::USER, "auth_method": "private_key", "secrets": { "private_key": pem.as_str() } }))
        .await;
    let (_, eph_node) = admin
        .post("/api/nodes", json!({ "name": "log-eph", "protocol": "ssh", "host": "127.0.0.1", "port": target.addr.port(), "username": ssh_target::USER, "auth_method": "password", "ephemeral_auth": true }))
        .await;
    let mut w = ws::open(addr, admin.cookie.as_deref().expect("cookie")).await;

    w.send_json(Opcode::StreamOpen, 1, &json!({ "node_id": key_node["id"] }))
        .await;
    w.expect(Opcode::HostIdentityPrompt).await;
    w.send_json(Opcode::HostIdentityDecision, 1, &json!({ "approve": true }))
        .await;
    w.expect(Opcode::StreamOpened).await;
    w.type_text(1, "typed-sudo-password-xyzzy\r").await;
    w.read_until(1, "xyzzy").await;

    w.send_json(Opcode::StreamOpen, 2, &json!({ "node_id": eph_node["id"] }))
        .await;
    w.expect(Opcode::CredentialRequest).await;
    w.send_json(
        Opcode::CredentialSubmit,
        2,
        &json!({ "password": ssh_target::PASSWORD }),
    )
    .await;
    w.expect(Opcode::HostIdentityPrompt).await;
    w.send_json(Opcode::HostIdentityDecision, 2, &json!({ "approve": true }))
        .await;
    w.expect(Opcode::StreamOpened).await;
    w.send(Opcode::StreamClose, 1, &[0, 100]).await;
    w.send(Opcode::StreamClose, 2, &[0, 100]).await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let logs = capture.0.lock().expect("lock").clone();
    assert!(!logs.is_empty(), "subscriber captured nothing");
    let text = String::from_utf8_lossy(&logs);
    assert!(
        text.contains("russh"),
        "russh log records were not captured"
    );
    assert!(
        text.contains("tungstenite"),
        "tungstenite log records were not captured"
    );
    let key_body: String = pem
        .lines()
        .nth(1)
        .expect("pem body")
        .chars()
        .take(40)
        .collect();
    assert_absent(
        &logs,
        &[
            ssh_target::PASSWORD,
            "typed-sudo-password",
            "BEGIN OPENSSH PRIVATE KEY",
            key_body.as_str(),
            "log-key",
            "log-eph",
        ],
    );
}
