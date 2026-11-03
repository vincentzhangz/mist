//! Router wiring: main app, ingest-only mTLS router, SPA fallback.

use axum::{
    Router,
    body::Body,
    extract::State,
    http::{Request, StatusCode, Uri},
    response::{IntoResponse, Json},
    routing::{delete, get, post},
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{
    handlers::{
        ack_alert, create_silence, delete_silence, get_alert, health_overview, healthz, ingest,
        list_alerts, list_flows, list_silences, login, metrics_handler, recommend_policy,
        resolve_alert,
    },
    middleware::require_auth,
    state::AppState,
    ws::ws_handler,
};

/// Serves the dashboard SPA shell for browser navigations while keeping
/// unknown `/api/*` paths a JSON 404 instead of HTML.
async fn spa_handler(
    State(state): State<AppState>,
    uri: Uri,
    request: Request<Body>,
) -> axum::response::Response {
    if uri.path() == "/api" || uri.path().starts_with("/api/") {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": "not found" })),
        )
            .into_response();
    }
    match state.inner.spa.clone() {
        Some(spa) => match tower::ServiceExt::oneshot(spa, request).await {
            Ok(response) => response.map(Body::new),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

pub(crate) fn router(state: AppState) -> Router {
    app_router(state, true)
}

/// Full app router; `with_ingest` false drops `/api/ingest` (mTLS mode
/// serves it on a separate, client-cert-gated listener instead, so the
/// main port can never bypass the handshake gate).
pub(crate) fn app_router(state: AppState, with_ingest: bool) -> Router {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_handler))
        .route("/api/auth/login", post(login))
        .route("/api/flows", get(list_flows))
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/{id}", get(get_alert))
        .route("/api/alerts/{id}/resolve", post(resolve_alert))
        .route("/api/alerts/{id}/ack", post(ack_alert))
        .route("/api/silences", get(list_silences).post(create_silence))
        .route("/api/silences/{id}", delete(delete_silence))
        .route("/api/policies/recommend", get(recommend_policy))
        .route("/api/health/overview", get(health_overview))
        .route("/api/ws", get(ws_handler));
    let app = if with_ingest {
        app.route("/api/ingest", post(ingest))
    } else {
        app
    };
    let app = if state.inner.spa.is_some() {
        app.route("/", get(spa_handler))
            .route("/{*path}", get(spa_handler))
    } else {
        app
    };
    finalize(app, state)
}

/// Ingest-only router for the mTLS listener: same middleware and token
/// semantics as the main port, minimal surface.
pub(crate) fn ingest_router(state: AppState) -> Router {
    finalize(Router::new().route("/api/ingest", post(ingest)), state)
}

/// Shared middleware stack (CORS, path-only tracing, auth) plus state.
fn finalize(app: Router<AppState>, state: AppState) -> Router {
    app.layer(CorsLayer::permissive())
        // WS sessions travel in `?token=`, so spans log the path only —
        // the default span would log the full URI (query included).
        .layer(
            TraceLayer::new_for_http().make_span_with(|request: &Request<Body>| {
                tracing::debug_span!(
                    "http.request",
                    method = %request.method(),
                    path = %request.uri().path(),
                )
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::test_helpers::*;

    #[tokio::test]
    async fn mtls_mode_removes_ingest_from_main_router() {
        let (state, _rx) = crate::test_helpers::test_state();
        let mut shipment = batch();
        shipment.flows.push(test_flow("node-1", None));
        let body = serde_json::to_string(&shipment).unwrap();
        let main = app_router(state.clone(), false)
            .oneshot(
                Request::post("/api/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(main.status(), StatusCode::NOT_FOUND);
        let mtls = ingest_router(state)
            .oneshot(
                Request::post("/api/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mtls.status(), StatusCode::ACCEPTED);
    }
    #[tokio::test]
    async fn spa_shell_serves_client_routes_but_not_unknown_api_paths() {
        // Minimal dist dir so the SPA routes are registered.
        let dir = std::env::temp_dir().join(format!("mist-spa-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), "<html>spa shell</html>").unwrap();

        let (state, _rx) = test_state_with_spa(&dir);
        let token =
            crate::auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
        let app = || router(state.clone());

        // Unknown /api/* path with a valid token: JSON 404, never the shell.
        let response = app()
            .oneshot(
                Request::get("/api/does-not-exist")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "not found");

        // Client-side routes and / still get the SPA shell (public).
        for uri in ["/", "/alerts"] {
            let response = app()
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "for {uri}");
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let html = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(html.contains("spa shell"), "unexpected body for {uri}");
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }
}
