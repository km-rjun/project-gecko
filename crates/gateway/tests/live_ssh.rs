//! Live tests against the real OpenSSH dev target from `docker-compose.dev.yml`.
//!
//! Skipped unless `GATEWAY_LIVE_SSH=127.0.0.1:2222` is set (CI's dev-harness job sets it).

mod common;

use std::time::Duration;

use common::{
    TestApp,
    ws::{self, Ws, coded},
};
use protocol_core::wire::{self, Code, Opcode, TermResize};
use serde_json::{Value, json};

fn target() -> Option<(String, u16)> {
    let v = std::env::var("GATEWAY_LIVE_SSH").ok()?;
    let (h, p) = v.rsplit_once(':')?;
    Some((h.to_owned(), p.parse().ok()?))
}

fn key_pem() -> String {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../dev/.generated/devuser_ed25519"
    );
    std::fs::read_to_string(path)
        .expect("dev key (run docker compose -f docker-compose.dev.yml up first)")
}

async fn connect(app: &TestApp, body: Value) -> (Ws, common::Client<'_>) {
    let addr = ws::serve(app).await;
    let (mut c, _) = app.admin().await;
    let (s, b) = c.post("/api/nodes", body).await;
    assert_eq!(s.as_u16(), 201, "{b}");
    let id = b["id"].as_str().expect("id").to_owned();
    let mut w = ws::open(addr, c.cookie.as_deref().expect("cookie")).await;
    w.send_json(
        Opcode::StreamOpen,
        1,
        &json!({ "node_id": id, "cols": 120, "rows": 40 }),
    )
    .await;
    w.expect(Opcode::HostIdentityPrompt).await;
    w.send_json(Opcode::HostIdentityDecision, 1, &json!({ "approve": true }))
        .await;
    w.expect(Opcode::StreamOpened).await;
    (w, c)
}

#[tokio::test]
async fn live_password_and_resize() {
    let Some((host, port)) = target() else {
        return eprintln!("GATEWAY_LIVE_SSH not set; skipping");
    };
    let app = TestApp::new().await;
    let body = json!({ "name": "live", "protocol": "ssh", "host": host, "port": port, "username": "devuser", "auth_method": "password", "secrets": { "password": "devpass" } });
    let (mut w, _c) = connect(&app, body).await;
    w.type_text(1, "stty size; echo MARK$((0+1))\r").await;
    let out = w.read_until(1, "MARK1\r\n").await;
    assert!(out.contains("40 120"), "{out:?}");
    w.send(
        Opcode::TermResize,
        1,
        &TermResize {
            cols: 200,
            rows: 50,
            px_w: 0,
            px_h: 0,
        }
        .to_bytes(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    w.type_text(1, "stty size; echo MARK$((0+2))\r").await;
    let out = w.read_until(1, "MARK2\r\n").await;
    assert!(out.contains("50 200"), "{out:?}");
}

#[tokio::test]
async fn live_key_auth_and_yes_flood_backpressure() {
    let Some((host, port)) = target() else {
        return eprintln!("GATEWAY_LIVE_SSH not set; skipping");
    };
    let app = TestApp::new().await;
    let body = json!({ "name": "live-key", "protocol": "ssh", "host": host, "port": port, "username": "devuser", "auth_method": "private_key", "secrets": { "private_key": key_pem() } });
    let (mut w, _c) = connect(&app, body).await;
    w.type_text(1, "echo READY$((1+1))\r").await;
    w.read_until(1, "READY2").await;

    w.type_text(1, "yes\r").await;
    let mut unacked = 0usize;
    while let Some(f) = w.next_within(Duration::from_millis(1000)).await {
        if f.opcode == Opcode::TermData {
            unacked += f.payload.len();
        }
    }
    assert!(
        unacked > 0 && unacked <= wire::TERM_WINDOW as usize + wire::TERM_CHUNK,
        "unacked {unacked}"
    );

    // Ctrl+C, then keep acknowledging until the shell is back.
    w.type_text(1, "\x03").await;
    w.ack(1, unacked).await;
    w.type_text(1, "echo BACK-$((40+2))\r").await;
    let start = std::time::Instant::now();
    w.read_until(1, "BACK-42").await;
    assert!(start.elapsed() < Duration::from_secs(10));

    w.type_text(1, "exit\r").await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(coded(&close).0, Code::ClosedByRemote as u16);
}

#[tokio::test]
async fn live_wrong_password() {
    let Some((host, port)) = target() else {
        return eprintln!("GATEWAY_LIVE_SSH not set; skipping");
    };
    let app = TestApp::new().await;
    let addr = ws::serve(&app).await;
    let (mut c, _) = app.admin().await;
    let (_, b) = c
        .post("/api/nodes", json!({ "name": "live-bad", "protocol": "ssh", "host": host, "port": port, "username": "devuser", "auth_method": "password", "secrets": { "password": "wrong-password" } }))
        .await;
    let mut w = ws::open(addr, c.cookie.as_deref().expect("cookie")).await;
    w.send_json(Opcode::StreamOpen, 1, &json!({ "node_id": b["id"] }))
        .await;
    w.expect(Opcode::HostIdentityPrompt).await;
    w.send_json(Opcode::HostIdentityDecision, 1, &json!({ "approve": true }))
        .await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(coded(&close).0, Code::AuthFailed as u16);
}
