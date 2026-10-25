//! Web hardening middleware: Origin enforcement and security headers (docs/02 §7).

use axum::{
    extract::{Request, State},
    http::{HeaderName, HeaderValue, Method, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::{error::ApiError, state::AppState};

const CSP: &str = "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
style-src-attr 'unsafe-inline'; img-src 'self' blob: data:; worker-src 'self' blob:; connect-src 'self'; \
frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

/// Rejects mutating requests whose `Origin` is not the configured public origin (CSRF defence).
pub async fn require_origin(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let mutating = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if mutating {
        let origin = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok());
        if origin != Some(state.settings.public_origin.as_str()) {
            return ApiError::Forbidden("origin not allowed").into_response();
        }
    }
    next.run(req).await
}

/// Adds security headers to every response; `no-store` for API responses.
pub async fn headers(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    let set = |h: &mut axum::http::HeaderMap, k: HeaderName, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(h, header::CONTENT_SECURITY_POLICY, CSP);
    set(h, header::X_CONTENT_TYPE_OPTIONS, "nosniff");
    set(h, header::REFERRER_POLICY, "no-referrer");
    set(
        h,
        HeaderName::from_static("permissions-policy"),
        "camera=(), microphone=(), geolocation=()",
    );
    set(
        h,
        HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    );
    set(h, header::X_FRAME_OPTIONS, "DENY");
    if state.settings.secure_cookies {
        set(h, header::STRICT_TRANSPORT_SECURITY, "max-age=63072000");
    }
    if is_api {
        set(h, header::CACHE_CONTROL, "no-store");
    }
    res
}
