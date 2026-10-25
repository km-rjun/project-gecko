//! End-to-end workspace socket + SSH engine tests against an in-process SSH target.

mod common;

use std::time::Duration;

use common::{
    TestApp,
    ssh_target::{self, FLOOD_BYTES, PASSWORD, SshTarget, USER},
    ws::{self, Ws, coded, json},
};
use protocol_core::wire::{self, Code, Opcode, TermResize};
use serde_json::{Value, json};

struct Env {
    app: TestApp,
    addr: std::net::SocketAddr,
    target: SshTarget,
}

const CLIENT_KEY_SEED: u8 = 7;

async fn env() -> Env {
    let app = TestApp::new().await;
    let client_pub = ssh_target::ed25519(CLIENT_KEY_SEED).public_key().clone();
    let target = ssh_target::start(ssh_target::ed25519(1), client_pub).await;
    let addr = ws::serve(&app).await;
    Env { app, addr, target }
}

fn node(target: &SshTarget, name: &str, extra: Value) -> Value {
    let mut n = json!({
        "name": name,
        "protocol": "ssh",
        "host": "127.0.0.1",
        "port": target.addr.port(),
        "username": USER,
        "auth_method": "password",
        "secrets": { "password": PASSWORD },
        "allow_clipboard_paste": true,
    });
    if let (Some(base), Some(extra)) = (n.as_object_mut(), extra.as_object()) {
        for (k, v) in extra {
            if v.is_null() && k == "secrets" {
                base.remove(k);
            } else {
                base.insert(k.clone(), v.clone());
            }
        }
    }
    n
}

async fn create_node(c: &mut common::Client<'_>, body: Value) -> String {
    let (s, b) = c.post("/api/nodes", body).await;
    assert_eq!(s.as_u16(), 201, "{b}");
    b["id"].as_str().expect("id").to_owned()
}

async fn open_stream(w: &mut Ws, stream: u32, node_id: &str) {
    w.send_json(
        Opcode::StreamOpen,
        stream,
        &json!({ "node_id": node_id, "cols": 100, "rows": 30 }),
    )
    .await;
}

/// Opens a stream, approves the unknown host key and waits for StreamOpened + the banner.
async fn open_approved(w: &mut Ws, stream: u32, node_id: &str) {
    open_stream(w, stream, node_id).await;
    let (_, _) = w.expect(Opcode::HostIdentityPrompt).await;
    w.send_json(
        Opcode::HostIdentityDecision,
        stream,
        &json!({ "approve": true }),
    )
    .await;
    w.expect(Opcode::StreamOpened).await;
    w.read_until(stream, "welcome").await;
}

async fn audit_events(app: &TestApp) -> Vec<(String, String, String)> {
    sqlx::query_as("SELECT event, outcome, details FROM audit_logs ORDER BY seq")
        .fetch_all(&app.state.db)
        .await
        .expect("audit")
}

#[tokio::test]
async fn upgrade_requires_subprotocol_origin_and_session() {
    let e = env().await;
    let (c, _) = e.app.admin().await;
    let cookie = c.cookie.clone().expect("cookie");
    let ok = Some(common::ORIGIN);
    assert_eq!(
        ws::connect(e.addr, Some(&cookie), ok, None).await.err(),
        Some(400)
    );
    assert_eq!(
        ws::connect(
            e.addr,
            Some(&cookie),
            Some("https://evil.example"),
            Some("workspace.v1")
        )
        .await
        .err(),
        Some(403)
    );
    assert_eq!(
        ws::connect(e.addr, Some(&cookie), None, Some("workspace.v1"))
            .await
            .err(),
        Some(403)
    );
    assert_eq!(
        ws::connect(e.addr, None, ok, Some("workspace.v1"))
            .await
            .err(),
        Some(401)
    );
    assert_eq!(
        ws::connect(e.addr, Some("forged"), ok, Some("workspace.v1"))
            .await
            .err(),
        Some(401)
    );
    let w = ws::connect(e.addr, Some(&cookie), ok, Some("workspace.v1"))
        .await
        .expect("upgrade");
    drop(w);
    // At most 8 sockets per session.
    let mut socks = Vec::new();
    for _ in 0..8 {
        socks.push(ws::open(e.addr, &cookie).await);
    }
    assert_eq!(
        ws::connect(e.addr, Some(&cookie), ok, Some("workspace.v1"))
            .await
            .err(),
        Some(429)
    );
}

#[tokio::test]
async fn password_session_pins_host_key_echoes_and_resizes() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let id = create_node(&mut c, node(&e.target, "echo-box", json!({}))).await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;

    open_stream(&mut w, 1, &id).await;
    let (prompt, _) = w.expect(Opcode::HostIdentityPrompt).await;
    let p = json(&prompt);
    assert_eq!(p["kind"], "ssh-hostkey");
    assert_eq!(p["algorithm"], "ssh-ed25519");
    assert_eq!(p["state"], "unknown");
    assert_eq!(p["fingerprint"], e.target.fingerprint());
    w.send_json(Opcode::HostIdentityDecision, 1, &json!({ "approve": true }))
        .await;
    let (opened, _) = w.expect(Opcode::StreamOpened).await;
    let o = json(&opened);
    assert_eq!(
        (o["protocol"].as_str(), o["route"].as_str()),
        (Some("ssh"), Some("direct"))
    );
    assert_eq!(o["policy"], json!({ "clipboard_paste": true }));
    w.read_until(1, "welcome").await;
    assert_eq!(
        *e.target.stats.pty.lock().expect("lock"),
        Some(("xterm-256color".into(), 100, 30))
    );

    w.type_text(1, "hello-gateway\r").await;
    w.read_until(1, "hello-gateway").await;
    w.send(Opcode::TermPaste, 1, b"pasted-text").await;
    w.read_until(1, "pasted-text").await;

    let r = TermResize {
        cols: 132,
        rows: 43,
        px_w: 0,
        px_h: 0,
    };
    w.send(Opcode::TermResize, 1, &r.to_bytes()).await;
    w.type_text(1, "sync\r").await;
    w.read_until(1, "sync").await;
    assert_eq!(
        e.target.stats.resizes.lock().expect("lock").last(),
        Some(&(132, 43))
    );

    // Pin is stored encrypted and visible through the API.
    let (_, n) = c.get(&format!("/api/nodes/{id}")).await;
    assert_eq!(n["host_identity"]["fingerprint"], e.target.fingerprint());
    let fp = e.target.fingerprint();
    for (name, bytes) in e.app.raw_files() {
        assert!(
            !bytes.windows(fp.len()).any(|x| x == fp.as_bytes()),
            "fingerprint in plaintext in {name}"
        );
    }

    // Second stream: no prompt.
    open_stream(&mut w, 2, &id).await;
    w.expect(Opcode::StreamOpened).await;

    // Remote exit closes the stream with ClosedByRemote.
    w.type_text(2, "exit\r").await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(
        (close.stream_id, coded(&close).0),
        (2, Code::ClosedByRemote as u16)
    );

    // Client close.
    w.send(
        Opcode::StreamClose,
        1,
        &(Code::ClosedByUser as u16).to_be_bytes(),
    )
    .await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(
        (close.stream_id, coded(&close).0),
        (1, Code::ClosedByUser as u16)
    );
    tokio::time::sleep(Duration::from_millis(200)).await;

    let events: Vec<String> = audit_events(&e.app)
        .await
        .into_iter()
        .map(|(ev, out, _)| format!("{ev}:{out}"))
        .collect();
    for want in [
        "session.open:success",
        "session.hostkey_pinned:success",
        "session.established:success",
        "session.closed:success",
    ] {
        assert!(
            events.iter().any(|e| e == want),
            "missing {want} in {events:?}"
        );
    }
    // Plain audit details never contain the destination.
    for (_, _, details) in audit_events(&e.app).await {
        assert!(
            !details.contains("127.0.0.1") && !details.contains("echo-box"),
            "{details}"
        );
    }
}

#[tokio::test]
async fn changed_host_key_is_a_hard_block_until_reset() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let id = create_node(&mut c, node(&e.target, "pinned-box", json!({}))).await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    open_approved(&mut w, 1, &id).await;

    e.target.set_host_key(ssh_target::ed25519(99));
    open_stream(&mut w, 2, &id).await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(
        (close.stream_id, coded(&close).0),
        (2, Code::HostIdentityMismatch as u16)
    );
    assert_eq!(
        e.target
            .stats
            .auth_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "credentials must not be sent to a mismatched host"
    );
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        audit_events(&e.app)
            .await
            .iter()
            .any(|(ev, out, _)| ev == "session.hostkey_mismatch" && out == "denied")
    );

    let (s, _) = c
        .post(
            &format!("/api/nodes/{id}/host-identity/reset"),
            json!({ "confirm_name": "pinned-box" }),
        )
        .await;
    assert_eq!(s.as_u16(), 204);
    open_stream(&mut w, 3, &id).await;
    let (prompt, _) = w.expect(Opcode::HostIdentityPrompt).await;
    assert_eq!(json(&prompt)["fingerprint"], e.target.fingerprint());
    w.send_json(Opcode::HostIdentityDecision, 3, &json!({ "approve": true }))
        .await;
    w.expect(Opcode::StreamOpened).await;
}

#[tokio::test]
async fn declined_host_key_closes_without_pinning() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let id = create_node(&mut c, node(&e.target, "decline-box", json!({}))).await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    open_stream(&mut w, 1, &id).await;
    w.expect(Opcode::HostIdentityPrompt).await;
    w.send_json(
        Opcode::HostIdentityDecision,
        1,
        &json!({ "approve": false }),
    )
    .await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(
        coded(&close),
        (Code::ClosedByUser as u16, "host key not approved".into())
    );
    let (_, n) = c.get(&format!("/api/nodes/{id}")).await;
    assert_eq!(n["host_identity"], Value::Null);
    assert_eq!(
        e.target
            .stats
            .auth_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
}

#[tokio::test]
async fn private_key_auth_from_vault() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let pem = ssh_target::ed25519(CLIENT_KEY_SEED)
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("pem");
    let body = node(
        &e.target,
        "key-box",
        json!({ "auth_method": "private_key", "secrets": { "private_key": pem.as_str() } }),
    );
    let id = create_node(&mut c, body).await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    open_approved(&mut w, 1, &id).await;
    w.type_text(1, "key-auth-ok\r").await;
    w.read_until(1, "key-auth-ok").await;
}

#[tokio::test]
async fn wrong_stored_password_fails_cleanly() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let id = create_node(
        &mut c,
        node(
            &e.target,
            "badpw-box",
            json!({ "secrets": { "password": "not-the-password" } }),
        ),
    )
    .await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    open_stream(&mut w, 1, &id).await;
    w.expect(Opcode::HostIdentityPrompt).await;
    w.send_json(Opcode::HostIdentityDecision, 1, &json!({ "approve": true }))
        .await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(coded(&close).0, Code::AuthFailed as u16);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let failed = audit_events(&e.app)
        .await
        .into_iter()
        .find(|(ev, _, _)| ev == "session.failed")
        .expect("session.failed");
    assert_eq!(failed.1, "failure");
    assert!(
        failed
            .2
            .contains(&format!("\"error_code\":{}", Code::AuthFailed as u16)),
        "{}",
        failed.2
    );
}

#[tokio::test]
async fn ephemeral_credentials_are_prompted_and_never_stored() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let body = node(
        &e.target,
        "eph-box",
        json!({ "ephemeral_auth": true, "username": null, "secrets": null }),
    );
    let id = create_node(&mut c, body).await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;

    open_stream(&mut w, 1, &id).await;
    let (req, _) = w.expect(Opcode::CredentialRequest).await;
    assert_eq!(
        json(&req),
        json!({ "fields": ["username", "password"], "username": null })
    );
    w.send_json(
        Opcode::CredentialSubmit,
        1,
        &json!({ "username": USER, "password": "wrong-one" }),
    )
    .await;
    w.expect(Opcode::HostIdentityPrompt).await;
    w.send_json(Opcode::HostIdentityDecision, 1, &json!({ "approve": true }))
        .await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(coded(&close).0, Code::AuthFailed as u16);

    open_stream(&mut w, 2, &id).await;
    w.expect(Opcode::CredentialRequest).await;
    w.send_json(
        Opcode::CredentialSubmit,
        2,
        &json!({ "username": USER, "password": PASSWORD }),
    )
    .await;
    w.expect(Opcode::StreamOpened).await;
    w.read_until(2, "welcome").await;

    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM encrypted_secrets")
        .fetch_one(&e.app.state.db)
        .await
        .expect("count");
    assert_eq!(n, 0);
    for (name, bytes) in e.app.raw_files() {
        for needle in [PASSWORD, USER] {
            assert!(
                !bytes.windows(needle.len()).any(|x| x == needle.as_bytes()),
                "{needle} found in {name}"
            );
        }
    }
}

#[tokio::test]
async fn credential_prompt_rejects_unknown_fields() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let id = create_node(
        &mut c,
        node(
            &e.target,
            "eph2",
            json!({ "ephemeral_auth": true, "secrets": null }),
        ),
    )
    .await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    open_stream(&mut w, 1, &id).await;
    let (req, _) = w.expect(Opcode::CredentialRequest).await;
    assert_eq!(json(&req)["fields"], json!(["password"]));
    w.send_json(
        Opcode::CredentialSubmit,
        1,
        &json!({ "password": PASSWORD, "extra": 1 }),
    )
    .await;
    let (err, _) = w.expect(Opcode::ControlError).await;
    assert_eq!(coded(&err).0, Code::BadFrame as u16);
}

#[tokio::test]
async fn output_flood_is_bounded_by_the_credit_window() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let id = create_node(&mut c, node(&e.target, "flood-box", json!({}))).await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    open_approved(&mut w, 1, &id).await;

    w.type_text(1, "FLOOD\r").await;
    // Read without acknowledging until the gateway stops sending.
    let mut unacked = 0usize;
    while let Some(f) = w.next_within(Duration::from_millis(700)).await {
        if f.opcode == Opcode::TermData {
            unacked += f.payload.len();
        }
    }
    let window = wire::TERM_WINDOW as usize;
    assert!(
        unacked > 0 && unacked <= window + wire::TERM_CHUNK,
        "browser received {unacked} unacked bytes"
    );
    let produced = e
        .target
        .stats
        .flood_sent
        .load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        produced < FLOOD_BYTES / 4,
        "target produced {produced} bytes while the browser was stalled"
    );

    // The priority lane is not blocked by the stalled stream.
    let ping = wire::Ping {
        pong: false,
        seq: 42,
        t_us: 1,
        upstream_rtt_us: 0,
    };
    w.send(Opcode::Ping, 0, &ping.to_bytes()).await;
    let pong = w.next_within(Duration::from_secs(2)).await.expect("pong");
    assert_eq!(pong.opcode, Opcode::Ping);
    assert_eq!(wire::Ping::parse(&pong.payload).expect("pong").seq, 42);

    // Acknowledge and drain the rest.
    w.ack(1, unacked).await;
    let rest = w.read_until(1, "FLOOD-END").await;
    assert!(unacked + rest.len() >= FLOOD_BYTES as usize);
}

#[tokio::test]
async fn locked_vault_drops_input_but_keeps_the_stream() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let id = create_node(&mut c, node(&e.target, "lock-box", json!({}))).await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    open_approved(&mut w, 1, &id).await;

    assert_eq!(c.post_empty("/api/vault/lock").await.0.as_u16(), 204);
    w.type_text(1, "while-locked\r").await;
    let (err, _) = w.expect(Opcode::ControlError).await;
    assert_eq!(coded(&err).0, Code::VaultLocked as u16);
    w.type_text(1, "still-locked\r").await;
    open_stream(&mut w, 2, &id).await;
    let (close, text) = w.expect(Opcode::StreamClose).await;
    assert_eq!(
        (close.stream_id, coded(&close).0),
        (2, Code::VaultLocked as u16)
    );
    assert!(
        !text.contains("locked\r"),
        "input leaked while locked: {text:?}"
    );

    // Unlock rotates the cookie; the open socket and stream survive.
    let (s, _) = c
        .post("/api/vault/unlock", json!({ "password": common::ADMIN_PW }))
        .await;
    assert_eq!(s.as_u16(), 204);
    w.type_text(1, "after-unlock\r").await;
    let text = w.read_until(1, "after-unlock").await;
    assert!(
        !text.contains("while-locked") && !text.contains("still-locked"),
        "{text:?}"
    );
}

#[tokio::test]
async fn ping_pong_reports_upstream_rtt() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let id = create_node(&mut c, node(&e.target, "rtt-box", json!({}))).await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    let ping = wire::Ping {
        pong: false,
        seq: 1,
        t_us: 123,
        upstream_rtt_us: 0,
    };
    w.send(Opcode::Ping, 0, &ping.to_bytes()).await;
    let p = wire::Ping::parse(&w.expect(Opcode::Ping).await.0.payload).expect("pong");
    assert_eq!(
        (p.pong, p.seq, p.t_us, p.upstream_rtt_us),
        (true, 1, 123, wire::RTT_UNKNOWN)
    );

    open_approved(&mut w, 1, &id).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    w.send(Opcode::Ping, 1, &wire::Ping { seq: 2, ..ping }.to_bytes())
        .await;
    let (f, _) = w.expect(Opcode::Ping).await;
    let p = wire::Ping::parse(&f.payload).expect("pong");
    assert_eq!((f.stream_id, p.seq), (1, 2));
    assert!(
        p.upstream_rtt_us != wire::RTT_UNKNOWN && p.upstream_rtt_us < 1_000_000,
        "rtt {}",
        p.upstream_rtt_us
    );
}

#[tokio::test]
async fn logout_closes_the_socket() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let id = create_node(&mut c, node(&e.target, "logout-box", json!({}))).await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    open_approved(&mut w, 1, &id).await;
    assert_eq!(c.post_empty("/api/auth/logout").await.0.as_u16(), 204);
    let mut closed = false;
    for _ in 0..20 {
        match w.next_within(Duration::from_secs(1)).await {
            None => {
                closed = true;
                break;
            }
            Some(_) => continue,
        }
    }
    assert!(closed, "socket stayed open after logout");
}

#[tokio::test]
async fn lock_and_disconnect_all_closes_the_socket() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    let (s, _) = c
        .post("/api/vault/lock", json!({ "disconnect_all": true }))
        .await;
    assert_eq!(s.as_u16(), 204);
    assert!(w.next_within(Duration::from_secs(3)).await.is_none());
}

#[tokio::test]
async fn malformed_and_out_of_order_frames_are_rejected() {
    let e = env().await;
    let (mut c, _) = e.app.admin().await;
    let id = create_node(
        &mut c,
        node(
            &e.target,
            "frames-box",
            json!({ "allow_clipboard_paste": false }),
        ),
    )
    .await;
    let mut w = ws::open(e.addr, c.cookie.as_deref().expect("cookie")).await;
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let err = |f: &wire::Frame| (f.opcode, f.stream_id, coded(f).0);
    w.inner
        .send(Message::Binary(vec![0x99, 0, 0, 0, 0].into()))
        .await
        .expect("send");
    assert_eq!(
        err(&w.expect(Opcode::ControlError).await.0),
        (Opcode::ControlError, 0, Code::BadFrame as u16)
    );
    w.send(Opcode::StreamOpened, 1, b"{}").await;
    assert_eq!(
        err(&w.expect(Opcode::ControlError).await.0).2,
        Code::BadFrame as u16
    );
    w.type_text(7, "x").await;
    assert_eq!(
        err(&w.expect(Opcode::ControlError).await.0),
        (Opcode::ControlError, 7, Code::UnknownStream as u16)
    );
    w.send(Opcode::StreamOpen, 5, b"not json").await;
    assert_eq!(
        err(&w.expect(Opcode::ControlError).await.0).2,
        Code::BadFrame as u16
    );
    w.send_json(Opcode::StreamOpen, 3, &json!({ "node_id": id }))
        .await;
    assert_eq!(
        err(&w.expect(Opcode::ControlError).await.0).2,
        Code::BadFrame as u16,
        "stream ids must increase"
    );
    w.send_json(
        Opcode::StreamOpen,
        9,
        &json!({ "node_id": "does-not-exist" }),
    )
    .await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(
        (close.stream_id, coded(&close).0),
        (9, Code::NodeNotFound as u16)
    );

    open_approved(&mut w, 10, &id).await;
    w.send(Opcode::TermPaste, 10, b"blocked").await;
    assert_eq!(
        err(&w.expect(Opcode::ControlError).await.0),
        (Opcode::ControlError, 10, Code::PolicyDenied as u16)
    );
    w.send(Opcode::InputKey, 10, &[1, 0, 0, 0, 0x61, 0, 0])
        .await;
    assert_eq!(
        err(&w.expect(Opcode::ControlError).await.0).2,
        Code::BadFrame as u16
    );

    // A text message closes the socket with 1003.
    w.inner
        .send(Message::Text("hello".into()))
        .await
        .expect("send");
    let mut code = None;
    while let Ok(Some(Ok(m))) = tokio::time::timeout(
        Duration::from_secs(3),
        futures_util::StreamExt::next(&mut w.inner),
    )
    .await
    {
        if let Message::Close(Some(f)) = m {
            code = Some(u16::from(f.code));
        }
    }
    assert_eq!(code, Some(1003));
}

#[tokio::test]
async fn other_users_nodes_are_not_found() {
    let e = env().await;
    let (mut admin, _) = e.app.admin().await;
    let id = create_node(&mut admin, node(&e.target, "admin-only", json!({}))).await;
    let (_, inv) = admin.post("/api/admin/invites", json!({})).await;
    let mut bob = e.app.client();
    let (s, b) = bob
        .post(
            "/api/invites/redeem",
            json!({ "token": inv["token"], "username": "bob", "password": "bob password 12345" }),
        )
        .await;
    assert_eq!(s.as_u16(), 201, "{b}");
    let mut w = ws::open(e.addr, bob.cookie.as_deref().expect("cookie")).await;
    open_stream(&mut w, 1, &id).await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(coded(&close).0, Code::NodeNotFound as u16);
}

fn rsa_pem() -> String {
    let k = russh::keys::PrivateKey::random(
        &mut rand::rng(),
        russh::keys::Algorithm::Rsa { hash: None },
    )
    .expect("rsa keygen");
    k.to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .expect("pem")
        .to_string()
}

#[tokio::test]
async fn rsa_user_keys_are_rejected_but_rsa_host_keys_work() {
    let app = TestApp::new().await;
    let client_pub = ssh_target::ed25519(CLIENT_KEY_SEED).public_key().clone();
    let rsa_host = russh::keys::PrivateKey::random(
        &mut rand::rng(),
        russh::keys::Algorithm::Rsa { hash: None },
    )
    .expect("rsa keygen");
    let target = ssh_target::start(rsa_host, client_pub).await;
    let addr = ws::serve(&app).await;
    let (mut c, _) = app.admin().await;

    // Stored RSA private key: rejected by the API.
    let (s, b) = c
        .post(
            "/api/nodes",
            node(
                &target,
                "rsa-user",
                json!({ "auth_method": "private_key", "secrets": { "private_key": rsa_pem() } }),
            ),
        )
        .await;
    assert_eq!(s.as_u16(), 400, "{b}");
    assert!(
        b["message"]
            .as_str()
            .unwrap_or_default()
            .contains("RUSTSEC-2023-0071"),
        "{b}"
    );

    // Ephemeral RSA private key: rejected at connect time, after the host key check.
    let id = create_node(
        &mut c,
        node(
            &target,
            "rsa-eph",
            json!({ "auth_method": "private_key", "ephemeral_auth": true, "secrets": null }),
        ),
    )
    .await;
    let mut w = ws::open(addr, c.cookie.as_deref().expect("cookie")).await;
    open_stream(&mut w, 1, &id).await;
    w.expect(Opcode::CredentialRequest).await;
    w.send_json(
        Opcode::CredentialSubmit,
        1,
        &json!({ "private_key": rsa_pem() }),
    )
    .await;
    let (prompt, _) = w.expect(Opcode::HostIdentityPrompt).await;
    assert_eq!(
        json(&prompt)["algorithm"],
        "ssh-rsa",
        "RSA host key offered"
    );
    w.send_json(Opcode::HostIdentityDecision, 1, &json!({ "approve": true }))
        .await;
    let (close, _) = w.expect(Opcode::StreamClose).await;
    assert_eq!(
        coded(&close).0,
        Code::PolicyDenied as u16,
        "{:?}",
        coded(&close)
    );
    assert_eq!(
        target
            .stats
            .auth_attempts
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );

    // RSA host key + password auth works.
    let id = create_node(&mut c, node(&target, "rsa-host", json!({}))).await;
    open_approved(&mut w, 2, &id).await;
    w.type_text(2, "rsa-host-ok\r").await;
    w.read_until(2, "rsa-host-ok").await;
}
