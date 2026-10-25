//! Security properties of the vault and storage engine (docs/02).

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::*;
use serde_json::json;

const NEEDLES: &[&str] = &[
    "TargetP@ss-word-91",
    "c2VjcmV0LWtleS1ib2R5",
    "BEGIN OPENSSH PRIVATE KEY",
    "passphrase-omega-77",
    "db-zeta.internal.example",
    "prod-db-zeta",
    "alice-target",
    "tag-sensitive",
    "jump.ephemeral.example",
    "jump-ephemeral",
    ADMIN_PW,
];

fn assert_absent(haystack: &[u8], needles: &[&str], context: &str) {
    for n in needles {
        assert!(
            !haystack.windows(n.len()).any(|w| w == n.as_bytes()),
            "plaintext {n:?} found in {context}"
        );
    }
}

#[tokio::test]
async fn raw_database_files_contain_no_plaintext() {
    let app = TestApp::new().await;
    let (mut admin, rk) = app.admin().await;
    let session_token = admin.cookie.clone().expect("cookie");
    let (s, node) = admin.post("/api/nodes", ssh_node()).await;
    assert_eq!(s, StatusCode::CREATED, "{node}");
    assert_eq!(
        admin.post("/api/nodes", ephemeral_node()).await.0,
        StatusCode::CREATED
    );
    let (s, invite) = admin.post("/api/admin/invites", json!({})).await;
    assert_eq!(s, StatusCode::CREATED);
    let invite_token = invite["token"].as_str().expect("token").to_owned();

    // The API returns metadata but never secrets.
    let id = node["id"].as_str().expect("id");
    let (_, fetched) = admin.get(&format!("/api/nodes/{id}")).await;
    assert_eq!(fetched["host"], "db-zeta.internal.example");
    assert_eq!(
        fetched["secrets_stored"],
        json!({ "password": true, "private_key": true, "key_passphrase": true })
    );
    assert_absent(
        fetched.to_string().as_bytes(),
        &[
            "TargetP@ss-word-91",
            "c2VjcmV0LWtleS1ib2R5",
            "passphrase-omega-77",
        ],
        "API response",
    );

    app.state.db.close().await;
    let mut needles: Vec<&str> = NEEDLES.to_vec();
    needles.extend([
        rk.as_str(),
        session_token.as_str(),
        invite_token.as_str(),
        app.bootstrap_token.as_str(),
    ]);
    let files = app.raw_files();
    assert!(files.iter().any(|(n, _)| n == "gateway.db"));
    // Positive control: non-secret plaintext (the account username) IS visible, so the scan reads real data.
    let all: Vec<u8> = files.iter().flat_map(|(_, b)| b.iter().copied()).collect();
    assert!(
        all.windows(b"auth.bootstrap".len())
            .any(|w| w == b"auth.bootstrap"),
        "scan control failed"
    );
    for (name, bytes) in &files {
        assert_absent(bytes, &needles, name);
    }
}

#[tokio::test]
async fn tampered_or_swapped_ciphertext_fails_cleanly() {
    let app = TestApp::new().await;
    let (mut admin, _) = app.admin().await;
    let (_, a) = admin.post("/api/nodes", ssh_node()).await;
    let mut other = ssh_node();
    other["name"] = json!("second-node");
    let (_, b) = admin.post("/api/nodes", other).await;
    let (a, b) = (
        a["id"].as_str().expect("a").to_owned(),
        b["id"].as_str().expect("b").to_owned(),
    );
    let db = &app.state.db;

    // Flip one byte of node A's metadata ciphertext.
    sqlx::query("UPDATE nodes SET meta_ciphertext = CAST(substr(meta_ciphertext, 1, 20) || X'FF' || substr(meta_ciphertext, 22) AS BLOB) WHERE id = ?")
        .bind(&a)
        .execute(db)
        .await
        .expect("tamper");
    let (s, body) = admin.get(&format!("/api/nodes/{a}")).await;
    assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body["error"], "integrity_error");

    // Copy node B's (valid) metadata into node A: AAD binds node_id, so it must not open.
    sqlx::query("UPDATE nodes SET meta_nonce = (SELECT meta_nonce FROM nodes WHERE id = ?1), meta_ciphertext = (SELECT meta_ciphertext FROM nodes WHERE id = ?1) WHERE id = ?2")
        .bind(&b)
        .bind(&a)
        .execute(db)
        .await
        .expect("swap meta");
    assert_eq!(
        admin.get(&format!("/api/nodes/{a}")).await.1["error"],
        "integrity_error"
    );

    // Swap the secret bundles of the two nodes.
    sqlx::query(
        "UPDATE nodes SET meta_nonce = (SELECT meta_nonce FROM nodes WHERE id = ?1) WHERE id = ?1",
    )
    .bind(&b)
    .execute(db)
    .await
    .expect("noop");
    let (bn, bc): (Vec<u8>, Vec<u8>) =
        sqlx::query_as("SELECT nonce, ciphertext FROM encrypted_secrets WHERE node_id = ?")
            .bind(&b)
            .fetch_one(db)
            .await
            .expect("b secrets");
    sqlx::query("DELETE FROM nodes WHERE id = ?")
        .bind(&a)
        .execute(db)
        .await
        .expect("drop a");
    let mut third = ssh_node();
    third["name"] = json!("third-node");
    let (_, c) = admin.post("/api/nodes", third).await;
    let c = c["id"].as_str().expect("c").to_owned();
    sqlx::query("UPDATE encrypted_secrets SET nonce = ?, ciphertext = ? WHERE node_id = ?")
        .bind(&bn)
        .bind(&bc)
        .bind(&c)
        .execute(db)
        .await
        .expect("swap secrets");
    assert_eq!(
        admin.get(&format!("/api/nodes/{c}")).await.1["error"],
        "integrity_error"
    );
    // Untouched node B still decrypts.
    assert_eq!(
        admin.get(&format!("/api/nodes/{b}")).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn ephemeral_nodes_never_store_secrets() {
    let app = TestApp::new().await;
    let (mut admin, _) = app.admin().await;

    let mut bad = ephemeral_node();
    bad["secrets"] = json!({ "password": "nope-nope-nope" });
    let (s, body) = admin.post("/api/nodes", bad).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");

    let (_, eph) = admin.post("/api/nodes", ephemeral_node()).await;
    let eph_id = eph["id"].as_str().expect("id").to_owned();
    // The database itself refuses secrets for ephemeral nodes.
    let direct = sqlx::query("INSERT INTO encrypted_secrets (node_id, owner_user_id, aead, nonce, ciphertext, created_at, updated_at) SELECT id, owner_user_id, 'xchacha20poly1305-v1', zeroblob(24), zeroblob(528), 0, 0 FROM nodes WHERE id = ?")
        .bind(&eph_id)
        .execute(&app.state.db)
        .await;
    let err = direct.expect_err("trigger must reject").to_string();
    assert!(err.contains("ephemeral node cannot store secrets"), "{err}");

    // Switching a vault node to ephemeral purges its secrets.
    let (_, node) = admin.post("/api/nodes", ssh_node()).await;
    let id = node["id"].as_str().expect("id").to_owned();
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM encrypted_secrets WHERE node_id = ?")
            .bind(&id)
            .fetch_one(&app.state.db)
            .await
            .expect("count")
    };
    assert_eq!(count().await, 1);
    let mut update = ssh_node();
    update["ephemeral_auth"] = json!(true);
    update.as_object_mut().expect("obj").remove("secrets");
    let (s, updated) = admin.put(&format!("/api/nodes/{id}"), update).await;
    assert_eq!(s, StatusCode::OK, "{updated}");
    assert_eq!(
        updated["secrets_stored"],
        json!({ "password": false, "private_key": false, "key_passphrase": false })
    );
    assert_eq!(count().await, 0);
}

#[tokio::test]
async fn audit_chain_verifies_and_detects_tampering() {
    let app = TestApp::new().await;
    let (mut admin, _) = app.admin().await;
    admin.post("/api/nodes", ssh_node()).await;
    admin.post_empty("/api/vault/lock").await;
    let report = gateway::audit::verify(&app.state.db).await.expect("verify");
    assert!(report.ok && report.entries >= 3, "{report:?}");

    // Audit rows are append-only at the database level.
    let upd = sqlx::query("UPDATE audit_logs SET outcome = 'failure' WHERE seq = 2")
        .execute(&app.state.db)
        .await;
    assert!(
        upd.expect_err("append-only")
            .to_string()
            .contains("append-only")
    );

    // Simulate an attacker with raw DB write access bypassing the trigger.
    sqlx::query("DROP TRIGGER audit_no_update")
        .execute(&app.state.db)
        .await
        .expect("drop trigger");
    sqlx::query("UPDATE audit_logs SET outcome = 'failure' WHERE seq = 2")
        .execute(&app.state.db)
        .await
        .expect("tamper");
    let report = gateway::audit::verify(&app.state.db).await.expect("verify");
    assert!(!report.ok);
    assert_eq!(report.first_bad_seq, Some(2));
}

#[tokio::test]
async fn audit_destinations_are_sealed_from_admins() {
    let app = TestApp::new().await;
    let (mut admin, _) = app.admin().await;
    let (_, invite) = admin.post("/api/admin/invites", json!({})).await;
    let mut bob = app.client();
    let (s, _) = bob
        .post("/api/invites/redeem", json!({ "token": invite["token"], "username": "bob", "password": "bob password 12345" }))
        .await;
    assert_eq!(s, StatusCode::CREATED);
    let (_, node) = bob.post("/api/nodes", ssh_node()).await;
    let node_id = node["id"].as_str().expect("id");

    // Bob sees his own destination.
    let (_, own) = bob.get("/api/audit").await;
    let created = own
        .as_array()
        .expect("arr")
        .iter()
        .find(|e| e["event"] == "node.created")
        .expect("event")
        .clone();
    assert_eq!(created["sealed"]["target"], "db-zeta.internal.example:2222");

    // The admin sees the event but not where it points.
    let (_, all) = admin.get("/api/admin/audit").await;
    let seen = all
        .as_array()
        .expect("arr")
        .iter()
        .find(|e| e["node_id"] == node_id)
        .expect("event")
        .clone();
    assert_eq!(seen["sealed_present"], true);
    assert!(seen["sealed"].is_null());
    assert!(!all.to_string().contains("db-zeta"));

    // And cannot read Bob's node.
    assert_eq!(
        admin.get(&format!("/api/nodes/{node_id}")).await.0,
        StatusCode::NOT_FOUND
    );
    let (_, list) = admin.get("/api/nodes").await;
    assert_eq!(list, json!([]));
}

#[tokio::test]
async fn vault_idle_lock_engages() {
    let app = TestApp::with_vault_idle(Duration::from_millis(300)).await;
    let (mut admin, _) = app.admin().await;
    assert_eq!(admin.get("/api/nodes").await.0, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(450)).await;
    let (s, body) = admin.get("/api/nodes").await;
    assert_eq!(s, StatusCode::LOCKED);
    assert_eq!(body["error"], "vault_locked");
    let (_, me) = admin.get("/api/me").await;
    assert_eq!(me["vault"], "locked");
    let (_, audit) = admin
        .post("/api/vault/unlock", json!({ "password": ADMIN_PW }))
        .await;
    assert!(audit.is_null());
    let (_, events) = admin.get("/api/audit").await;
    assert!(
        events
            .as_array()
            .expect("arr")
            .iter()
            .any(|e| e["event"] == "vault.lock" && e["details"]["trigger"] == "idle")
    );
}
