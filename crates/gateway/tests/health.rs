use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use tower::ServiceExt;

#[tokio::test]
async fn health_returns_ok_without_build_details() {
    let response = gateway::http::router()
        .oneshot(
            Request::get("/api/health")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), 200);
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("json");
    assert_eq!(body, serde_json::json!({ "status": "ok" }));
}

#[tokio::test]
async fn unknown_route_is_404() {
    let response = gateway::http::router()
        .oneshot(
            Request::get("/api/nope")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), 404);
}

#[test]
fn brand_name_comes_from_branding_toml() {
    let raw = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../branding.toml"))
        .expect("branding.toml");
    assert!(raw.contains(gateway::BRAND_DISPLAY_NAME));
}
