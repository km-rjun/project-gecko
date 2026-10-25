//! REST API behaviour: setup, auth, sessions, nodes, invites, admin, hardening.

mod common;

use std::net::{IpAddr, Ipv4Addr};

use axum::http::{Method, StatusCode, header};
use common::*;
use serde_json::json;

#[tokio::test]
async fn health_and_security_headers() {
    let app = TestApp::new().await;
    let mut c = app.client();
    let (s, h, body) = c.send(Method::GET, "/api/health", None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(body, json!({ "status": "ok" }));
    assert!(
        h[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .expect("csp")
            .contains("frame-ancestors 'none'")
    );
    assert_eq!(h[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(h[header::REFERRER_POLICY], "no-referrer");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
}

#[tokio::test]
async fn setup_requires_bootstrap_token_and_runs_once() {
    let app = TestApp::new().await;
    let mut c = app.client();
    let (s, me) = c.get("/api/me").await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert_eq!(me["needs_setup"], true);

    let (s, _) = c
        .post(
            "/api/setup",
            json!({ "bootstrap_token": "wrong", "username": ADMIN, "password": ADMIN_PW }),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = c.post("/api/setup", json!({ "bootstrap_token": app.bootstrap_token, "username": ADMIN, "password": "short" })).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);

    let (mut admin, rk) = app.admin().await;
    assert!(rk.starts_with("RK1-"));
    assert!(
        !app.dir.path().join(gateway::bootstrap::TOKEN_FILE).exists(),
        "token file must be deleted"
    );
    let (s, me) = admin.get("/api/me").await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["user"]["is_admin"], true);
    assert_eq!(me["vault"], "unlocked");

    let (s, _) = app.client().post("/api/setup", json!({ "bootstrap_token": app.bootstrap_token, "username": "again", "password": ADMIN_PW })).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mutating_requests_require_exact_origin() {
    let app = TestApp::new().await;
    for origin in [
        None,
        Some("http://evil.example"),
        Some("http://127.0.0.1:8443/"),
    ] {
        let mut c = app.client();
        c.origin = origin.map(str::to_owned);
        let (s, body) = c
            .post(
                "/api/auth/login",
                json!({ "username": "x", "password": "y" }),
            )
            .await;
        assert_eq!(s, StatusCode::FORBIDDEN, "{origin:?} {body}");
    }
    // GET is allowed without Origin.
    let mut c = app.client();
    c.origin = None;
    assert_eq!(c.get("/api/health").await.0, StatusCode::OK);
}

#[tokio::test]
async fn login_errors_are_generic_and_rate_limited() {
    let app = TestApp::new().await;
    app.admin().await;
    let ip = IpAddr::V4(Ipv4Addr::new(10, 9, 8, 7));
    let mut c = app.client_from(ip);
    let (s1, wrong_pw) = c
        .post(
            "/api/auth/login",
            json!({ "username": ADMIN, "password": "not the password" }),
        )
        .await;
    let (s2, unknown) = c
        .post(
            "/api/auth/login",
            json!({ "username": "nobody", "password": "not the password" }),
        )
        .await;
    assert_eq!(
        (s1, s2),
        (StatusCode::UNAUTHORIZED, StatusCode::UNAUTHORIZED)
    );
    assert_eq!(
        wrong_pw, unknown,
        "unknown user and wrong password must be indistinguishable"
    );

    let mut limited = false;
    for _ in 0..10 {
        let (s, h, _) = c
            .send(
                Method::POST,
                "/api/auth/login",
                Some(json!({ "username": "nobody", "password": "x" })),
            )
            .await;
        if s == StatusCode::TOO_MANY_REQUESTS {
            assert!(h.contains_key(header::RETRY_AFTER));
            limited = true;
            break;
        }
    }
    assert!(limited, "login was never rate limited");
}

#[tokio::test]
async fn cookie_flags_and_logout() {
    let app = TestApp::new().await;
    let mut c = app.client();
    let (_, h, _) = c
        .send(Method::POST, "/api/setup", Some(json!({ "bootstrap_token": app.bootstrap_token, "username": ADMIN, "password": ADMIN_PW })))
        .await;
    let cookie = h[header::SET_COOKIE].to_str().expect("cookie");
    assert!(cookie.starts_with("gw_session="));
    for flag in ["HttpOnly", "SameSite=Strict", "Path=/", "Max-Age=28800"] {
        assert!(cookie.contains(flag), "{cookie}");
    }
    assert_eq!(
        c.post_empty("/api/auth/logout").await.0,
        StatusCode::NO_CONTENT
    );
    assert!(c.cookie.is_none());
    assert_eq!(c.get("/api/me").await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn lock_unlock_rotates_session() {
    let app = TestApp::new().await;
    let (mut admin, _) = app.admin().await;
    let (_, node) = admin.post("/api/nodes", ssh_node()).await;
    let id = node["id"].as_str().expect("id").to_owned();

    assert_eq!(
        admin
            .post("/api/vault/lock", json!({ "disconnect_all": false }))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(admin.get("/api/nodes").await.0, StatusCode::LOCKED);
    assert_eq!(admin.get("/api/me").await.1["vault"], "locked");

    assert_eq!(
        admin
            .post(
                "/api/vault/unlock",
                json!({ "password": "wrong password!!" })
            )
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let old_cookie = admin.cookie.clone();
    assert_eq!(
        admin
            .post("/api/vault/unlock", json!({ "password": ADMIN_PW }))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_ne!(
        admin.cookie, old_cookie,
        "unlock must rotate the session token"
    );
    assert_eq!(
        admin.get(&format!("/api/nodes/{id}")).await.1["name"],
        "prod-db-zeta"
    );

    let mut stale = app.client();
    stale.cookie = old_cookie;
    assert_eq!(stale.get("/api/me").await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn node_crud_and_secret_patch_semantics() {
    let app = TestApp::new().await;
    let (mut admin, _) = app.admin().await;
    let (s, node) = admin.post("/api/nodes", ssh_node()).await;
    assert_eq!(s, StatusCode::CREATED);
    let id = node["id"].as_str().expect("id").to_owned();
    assert_eq!(
        node["allow_clipboard_copy"], true,
        "ssh nodes have no copy toggle (D-030)"
    );
    assert_eq!(node["host_identity"], serde_json::Value::Null);

    // Remove only the passphrase, keep the rest.
    let mut upd = ssh_node();
    upd["secrets"] = json!({ "key_passphrase": null });
    upd["port"] = json!(22);
    let (s, updated) = admin.put(&format!("/api/nodes/{id}"), upd).await;
    assert_eq!(s, StatusCode::OK, "{updated}");
    assert_eq!(
        updated["secrets_stored"],
        json!({ "password": true, "private_key": true, "key_passphrase": false })
    );
    assert_eq!(updated["port"], 22);

    // No `secrets` field keeps everything.
    let mut keep = ssh_node();
    keep.as_object_mut().expect("obj").remove("secrets");
    let (_, kept) = admin.put(&format!("/api/nodes/{id}"), keep).await;
    assert_eq!(kept["secrets_stored"]["password"], true);

    // Validation.
    for (field, value) in [
        ("protocol", json!("telnet")),
        ("port", json!(0)),
        ("auth_method", json!("private_key")),
        ("host", json!("bad host")),
    ] {
        let mut b = ssh_node();
        b[field] = value.clone();
        if field == "auth_method" {
            b["protocol"] = json!("rdp");
        }
        let (s, body) = admin.post("/api/nodes", b).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{field}={value} {body}");
    }
    let mut leaky = ssh_node();
    leaky["protocol_options"] = json!({ "api_token": "x" });
    assert_eq!(
        admin.post("/api/nodes", leaky).await.0,
        StatusCode::BAD_REQUEST
    );
    let mut unknown_pool = ssh_node();
    unknown_pool["edge_pool_id"] = json!("does-not-exist");
    assert_eq!(
        admin.post("/api/nodes", unknown_pool).await.0,
        StatusCode::BAD_REQUEST
    );

    // Host identity reset requires the exact node name.
    let path = format!("/api/nodes/{id}/host-identity/reset");
    assert_eq!(
        admin.post(&path, json!({ "confirm_name": "nope" })).await.0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        admin
            .post(&path, json!({ "confirm_name": "prod-db-zeta" }))
            .await
            .0,
        StatusCode::NO_CONTENT
    );

    assert_eq!(
        admin
            .get("/api/nodes")
            .await
            .1
            .as_array()
            .expect("arr")
            .len(),
        1
    );
    assert_eq!(
        admin.delete(&format!("/api/nodes/{id}")).await.0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        admin.get(&format!("/api/nodes/{id}")).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn password_change_revokes_other_sessions() {
    let app = TestApp::new().await;
    let (mut admin, _) = app.admin().await;
    admin.post("/api/nodes", ssh_node()).await;
    let mut second = app.client();
    assert_eq!(second.login(ADMIN, ADMIN_PW).await, StatusCode::OK);

    let new_pw = "a completely new password";
    let (s, _) = admin
        .post(
            "/api/account/password",
            json!({ "current_password": "wrong password!!", "new_password": new_pw }),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, _) = admin
        .post(
            "/api/account/password",
            json!({ "current_password": ADMIN_PW, "new_password": new_pw }),
        )
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);

    assert_eq!(
        second.get("/api/me").await.0,
        StatusCode::UNAUTHORIZED,
        "other session revoked"
    );
    assert_eq!(
        admin.get("/api/nodes").await.1[0]["name"],
        "prod-db-zeta",
        "current session keeps working"
    );
    let mut fresh = app.client();
    assert_eq!(fresh.login(ADMIN, ADMIN_PW).await, StatusCode::UNAUTHORIZED);
    assert_eq!(fresh.login(ADMIN, new_pw).await, StatusCode::OK);
    assert_eq!(
        fresh.get("/api/nodes").await.1[0]["host"],
        "db-zeta.internal.example"
    );
}

#[tokio::test]
async fn recovery_key_restores_access_and_rotates() {
    let app = TestApp::new().await;
    let (mut admin, rk) = app.admin().await;
    admin.post("/api/nodes", ssh_node()).await;

    let mut c = app.client_from(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    let new_pw = "recovered password 1";
    let (s, _) = c
        .post(
            "/api/auth/recover",
            json!({ "username": ADMIN, "recovery_key": "RK1-AAAA", "new_password": new_pw }),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, body) = c
        .post(
            "/api/auth/recover",
            json!({ "username": ADMIN, "recovery_key": rk, "new_password": new_pw }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let new_rk = body["recovery_key"].as_str().expect("rk").to_owned();
    assert_ne!(new_rk, rk);
    assert_eq!(
        c.get("/api/nodes").await.1[0]["username"],
        "alice-target",
        "secrets survive recovery"
    );
    assert_eq!(
        admin.get("/api/me").await.0,
        StatusCode::UNAUTHORIZED,
        "all old sessions revoked"
    );

    let mut d = app.client_from(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)));
    let (s, _) = d
        .post(
            "/api/auth/recover",
            json!({ "username": ADMIN, "recovery_key": rk, "new_password": "another password!" }),
        )
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "old recovery key is dead");

    // Regenerate from an unlocked session.
    let (s, regen) = c
        .post("/api/account/recovery-key", json!({ "password": new_pw }))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_ne!(regen["recovery_key"], new_rk);
}

#[tokio::test]
async fn invites_users_and_admin_boundaries() {
    let app = TestApp::new().await;
    let (mut admin, _) = app.admin().await;
    let (s, invite) = admin
        .post("/api/admin/invites", json!({ "ttl_hours": 1 }))
        .await;
    assert_eq!(s, StatusCode::CREATED);
    assert!(
        invite["path"]
            .as_str()
            .expect("path")
            .starts_with("/invite#")
    );
    assert!(
        admin.get("/api/admin/invites").await.1[0]
            .get("token")
            .is_none(),
        "tokens are never listed"
    );

    let mut bob = app.client();
    let redeem =
        json!({ "token": invite["token"], "username": "bob", "password": "bob password 12345" });
    let (s, body) = bob.post("/api/invites/redeem", redeem.clone()).await;
    assert_eq!(s, StatusCode::CREATED, "{body}");
    assert_eq!(body["user"]["is_admin"], false);
    let mut eve = app.client_from(IpAddr::V4(Ipv4Addr::new(10, 1, 1, 1)));
    let mut again = redeem.clone();
    again["username"] = json!("eve");
    assert_eq!(
        eve.post("/api/invites/redeem", again).await.0,
        StatusCode::UNAUTHORIZED,
        "single use"
    );

    // Non-admins cannot reach admin endpoints.
    assert_eq!(bob.get("/api/admin/users").await.0, StatusCode::FORBIDDEN);
    assert_eq!(
        bob.post("/api/admin/invites", json!({})).await.0,
        StatusCode::FORBIDDEN
    );

    let (_, users) = admin.get("/api/admin/users").await;
    let bob_id = users
        .as_array()
        .expect("arr")
        .iter()
        .find(|u| u["username"] == "bob")
        .expect("bob")["id"]
        .as_str()
        .expect("id")
        .to_owned();
    let my_id = admin.get("/api/me").await.1["user"]["id"]
        .as_str()
        .expect("id")
        .to_owned();
    assert_eq!(
        admin
            .post_empty(&format!("/api/admin/users/{my_id}/disable"))
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        admin
            .post_empty(&format!("/api/admin/users/{bob_id}/disable"))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        bob.get("/api/me").await.0,
        StatusCode::UNAUTHORIZED,
        "disabled user's sessions revoked"
    );
    assert_eq!(
        app.client().login("bob", "bob password 12345").await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        admin
            .post_empty(&format!("/api/admin/users/{bob_id}/enable"))
            .await
            .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        app.client().login("bob", "bob password 12345").await,
        StatusCode::OK
    );
    assert_eq!(
        admin.delete(&format!("/api/admin/users/{bob_id}")).await.0,
        StatusCode::NO_CONTENT
    );

    let (_, verify) = admin.get("/api/admin/audit/verify").await;
    assert_eq!(verify["ok"], true);
}

#[tokio::test]
async fn body_rejections_use_api_error_format() {
    let app = TestApp::new().await;
    let (mut admin, _) = app.admin().await;
    // Optional bodies may be empty even with a JSON content type.
    let (s, _, _) = admin.send(Method::POST, "/api/vault/lock", None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    admin
        .post("/api/vault/unlock", json!({ "password": ADMIN_PW }))
        .await;
    // Unknown fields and wrong types are rejected with the JSON error body.
    let (s, body) = admin
        .post("/api/nodes", json!({ "name": "x", "bogus": true }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "bad_request");
    let (s, body) = admin
        .post("/api/auth/login", json!({ "username": 5 }))
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "bad_request");
}

#[test]
fn brand_name_comes_from_branding_toml() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../branding.toml"))
        .expect("branding.toml");
    assert!(raw.contains(gateway::BRAND_DISPLAY_NAME));
}
