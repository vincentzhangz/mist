//! mist-api: HTTP API for flows and alerts.
//!
//! - `POST /api/ingest` accepts flow batches from agents and forwards them to
//!   the analyzer task (bounded channel; 503 when saturated).
//! - `GET /api/flows`, `GET /api/alerts`, `GET /api/alerts/:id`,
//!   `POST /api/alerts/:id/resolve` serve history and alert lifecycle.
//! - `GET /api/ws` streams live flows and alerts over WebSocket.
//!
//! Storage is Postgres when `DATABASE_URL` is set, otherwise in-memory.
//! Alerts are mirrored to the operator webhook when `OPERATOR_WEBHOOK_URL`
//! is set.
//!
//! Dashboard access uses email+password login (`POST /api/auth/login`)
//! issuing HS256 JWTs; every `/api/*` route except the login and the WS
//! handshake (which takes `?token=`) requires one. Agent ingest requires
//! the provisioned `INGEST_TOKEN` as `Bearer` when configured, and stays
//! open otherwise. `JWT_SECRET` is required at startup (fail closed).

mod analyzer;
mod auth;
mod metrics;
mod store;

use std::{net::SocketAddr, sync::Arc};

use analyzer::AlertEvent;
use axum::{
    Router,
    body::Body,
    extract::{Path, Query, State, WebSocketUpgrade},
    http::{Request, StatusCode, Uri, header},
    middleware::Next,
    response::{IntoResponse, Json},
    routing::{get, post},
};
use mist_types::{FlowBatch, FlowRecord};
use serde::{Deserialize, Serialize};
use store::{AlertView, FlowFilter, MemStore, PgStore, Store};
use tokio::sync::{broadcast, mpsc};
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
struct AppState {
    inner: Arc<AppStateInner>,
}

struct AppStateInner {
    store: Store,
    ingest_tx: mpsc::Sender<FlowBatch>,
    events_tx: broadcast::Sender<AlertEvent>,
    jwt_secret: String,
    /// Required `Bearer` token for `/api/ingest`; `None` leaves ingest open.
    ingest_token: Option<String>,
    metrics: std::sync::Arc<metrics::Metrics>,
    /// Dashboard SPA file service; `None` runs API-only.
    spa: Option<ServeDir<ServeFile>>,
}

#[derive(Debug, thiserror::Error)]
enum AppError {
    #[error("storage error: {0}")]
    Store(#[from] anyhow::Error),
    #[error("not found")]
    NotFound,
    #[error("ingest saturated; retry later")]
    Saturated,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            Self::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::Saturated => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

#[derive(Debug, Default, Deserialize)]
struct FlowQuery {
    node: Option<String>,
    namespace: Option<String>,
    pod: Option<String>,
    since_ms: Option<u64>,
    limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
struct AlertQuery {
    state: Option<String>,
    severity: Option<String>,
    limit: Option<usize>,
}

async fn healthz() -> &'static str {
    "ok"
}

async fn list_flows(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
) -> Result<Json<Vec<FlowRecord>>, AppError> {
    let filter = FlowFilter {
        node: query.node,
        namespace: query.namespace,
        pod: query.pod,
        since_ms: query.since_ms,
        limit: query.limit.unwrap_or(100),
    };
    Ok(Json(state.inner.store.list_flows(&filter).await?))
}

async fn list_alerts(
    State(state): State<AppState>,
    Query(query): Query<AlertQuery>,
) -> Result<Json<Vec<AlertView>>, AppError> {
    let mut alerts = state
        .inner
        .store
        .list_alerts(query.state.as_deref())
        .await?;
    if let Some(severity) = query.severity {
        alerts.retain(|view| format!("{:?}", view.alert.severity).eq_ignore_ascii_case(&severity));
    }
    alerts.truncate(query.limit.unwrap_or(500));
    Ok(Json(alerts))
}

async fn get_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AlertView>, AppError> {
    state
        .inner
        .store
        .get_alert(&id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

async fn resolve_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AlertView>, AppError> {
    state
        .inner
        .store
        .resolve_alert(&id)
        .await?
        .map(Json)
        .ok_or(AppError::NotFound)
}

async fn ingest(
    State(state): State<AppState>,
    Json(batch): Json<FlowBatch>,
) -> Result<StatusCode, AppError> {
    tracing::debug!(
        node = %batch.node,
        flows = batch.flows.len(),
        "ingest received batch"
    );
    let flows = batch.flows.len();
    state.inner.ingest_tx.try_send(batch).map_err(|_| {
        tracing::warn!("ingest channel saturated; shedding batch");
        state.inner.metrics.batch_shed();
        AppError::Saturated
    })?;
    state.inner.metrics.batch_accepted(flows);
    Ok(StatusCode::ACCEPTED)
}

/// Prometheus exposition scrape. Public like `/healthz` (outside `/api/`,
/// so [`require_auth`] lets it through) for in-cluster scraping.
async fn metrics_handler(State(state): State<AppState>) -> Result<impl IntoResponse, AppError> {
    let counts = state.inner.store.counts().await?;
    let body = state.inner.metrics.render(&counts);
    Ok((
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    ))
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
    email: String,
}

async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> impl IntoResponse {
    let stored = match state.inner.store.get_password_hash(&request.email).await {
        Ok(stored) => stored,
        Err(error) => {
            tracing::error!(?error, "login storage lookup failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "login failed" })),
            )
                .into_response();
        }
    };
    // Unknown users and wrong passwords both yield 401 with no oracle:
    // unknown users still pay one argon2 verification (against a dummy
    // hash) so response timing doesn't reveal which emails exist.
    let valid = if let Some(hash) = stored {
        auth::verify_password(&request.password, &hash)
            .await
            .unwrap_or(false)
    } else {
        let _ = auth::verify_password(&request.password, auth::DUMMY_HASH).await;
        false
    };
    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "invalid email or password" })),
        )
            .into_response();
    }
    match auth::create_token(&request.email, &state.inner.jwt_secret) {
        Ok(token) => (
            StatusCode::OK,
            Json(LoginResponse {
                token,
                email: request.email,
            }),
        )
            .into_response(),
        Err(error) => {
            tracing::error!(?error, "token issuance failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": "login failed" })),
            )
                .into_response()
        }
    }
}

/// Bearer token from the `Authorization` header, if syntactically present.
fn bearer_token(req: &Request<Body>) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

/// Rejects unauthenticated `/api/*` requests with 401.
///
/// Public without a token: `/healthz`, `/metrics`, `POST /api/auth/login`,
/// and `/api/ws` (the token travels in `?token=` instead, checked in
/// [`ws_handler`]). `/api/ingest` requires the provisioned `INGEST_TOKEN`
/// as `Bearer` when one is configured, and stays open otherwise.
/// Everything else under `/api/` requires `Authorization: Bearer <jwt>`.
async fn require_auth(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response()
    };
    let path = req.uri().path().to_owned();
    if !path.starts_with("/api/") || path == "/api/auth/login" || path == "/api/ws" {
        return next.run(req).await;
    }
    if path == "/api/ingest" {
        let open = state.inner.ingest_token.is_none();
        let token_ok = state
            .inner
            .ingest_token
            .as_deref()
            .is_some_and(|expected| bearer_token(&req) == Some(expected));
        if open || token_ok {
            return next.run(req).await;
        }
        return unauthorized();
    }
    let authorized = bearer_token(&req)
        .and_then(|token| auth::verify_token(token, &state.inner.jwt_secret))
        .is_some();
    if !authorized {
        return unauthorized();
    }
    next.run(req).await
}

#[derive(Debug, Default, Deserialize)]
struct WsQuery {
    token: Option<String>,
}

async fn ws_handler(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let authorized = query
        .token
        .as_deref()
        .and_then(|token| auth::verify_token(token, &state.inner.jwt_secret))
        .is_some();
    if !authorized {
        // Reject before upgrading: no socket is opened for bad tokens.
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid token" })),
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| drive_socket(socket, state.inner.events_tx.subscribe()))
        .into_response()
}

async fn drive_socket(
    socket: axum::extract::ws::WebSocket,
    mut events: broadcast::Receiver<AlertEvent>,
) {
    use axum::extract::ws::Message;
    use futures::{SinkExt as _, StreamExt as _};
    let (mut sender, mut receiver) = socket.split();
    // Forward broadcast events until either side closes. A lagged receiver
    // skips missed events rather than stalling the broadcast.
    let forward = async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let text = match serde_json::to_string(&event) {
                        Ok(text) => text,
                        Err(error) => {
                            tracing::warn!(?error, "event serialization failed");
                            continue;
                        }
                    };
                    if sender.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::debug!(skipped, "websocket receiver lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    // Drain client messages (pings/pongs/closes) so the connection stays alive.
    let drain = async move {
        while let Some(message) = receiver.next().await {
            match message {
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => {}
            }
        }
    };
    tokio::select! {
        () = forward => {},
        () = drain => {},
    }
}

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

fn router(state: AppState) -> Router {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_handler))
        .route("/api/auth/login", post(login))
        .route("/api/flows", get(list_flows))
        .route("/api/alerts", get(list_alerts))
        .route("/api/alerts/{id}", get(get_alert))
        .route("/api/alerts/{id}/resolve", post(resolve_alert))
        .route("/api/ingest", post(ingest))
        .route("/api/ws", get(ws_handler));
    let app = if state.inner.spa.is_some() {
        app.route("/", get(spa_handler))
            .route("/{*path}", get(spa_handler))
    } else {
        app
    };
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

/// Hashes `ADMIN_PASSWORD` and upserts the `ADMIN_EMAIL` user when both are
/// set; otherwise warns and leaves login failing closed (401 for everyone).
async fn seed_admin(store: &Store) {
    let email = std::env::var("ADMIN_EMAIL")
        .ok()
        .filter(|value| !value.is_empty());
    let password = std::env::var("ADMIN_PASSWORD")
        .ok()
        .filter(|value| !value.is_empty());
    let (Some(email), Some(password)) = (email, password) else {
        tracing::warn!(
            "ADMIN_EMAIL or ADMIN_PASSWORD unset; no users seeded, login will fail closed (401)"
        );
        return;
    };
    match auth::hash_password(&password).await {
        Ok(hash) => match store.upsert_user(&email, &hash).await {
            Ok(()) => tracing::info!(%email, "admin user seeded"),
            Err(error) => tracing::error!(?error, "admin seeding failed"),
        },
        Err(error) => tracing::error!(?error, "admin password hashing failed"),
    }
}

#[cfg(test)]
fn test_state() -> (AppState, mpsc::Receiver<FlowBatch>) {
    test_state_with_ingest_token(None)
}

#[cfg(test)]
fn test_state_with_ingest_token(
    ingest_token: Option<String>,
) -> (AppState, mpsc::Receiver<FlowBatch>) {
    let (ingest_tx, ingest_rx) = mpsc::channel(16);
    let (events_tx, _) = broadcast::channel(16);
    let state = AppState {
        inner: Arc::new(AppStateInner {
            store: Store::Memory(MemStore::default()),
            ingest_tx,
            events_tx,
            jwt_secret: String::from("test-secret"),
            ingest_token,
            metrics: Arc::new(metrics::Metrics::default()),
            spa: None,
        }),
    };
    (state, ingest_rx)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls auto-detect panics when both ring and aws-lc-rs are enabled (our
    // tree has both via kube/reqwest/sqlx); pin an explicit process default.
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let store = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.is_empty() => {
            let pool = sqlx::PgPool::connect(&url).await?;
            PgStore::migrate(&pool).await?;
            tracing::info!("using Postgres storage");
            Store::Postgres(PgStore::new(pool))
        }
        _ => {
            tracing::warn!(
                "DATABASE_URL unset; using in-memory storage (data will not survive restarts)"
            );
            Store::Memory(MemStore::default())
        }
    };
    let webhook_url = std::env::var("OPERATOR_WEBHOOK_URL")
        .ok()
        .filter(|url| !url.is_empty());
    if webhook_url.is_none() {
        tracing::warn!("OPERATOR_WEBHOOK_URL unset; AnomalyAlert mirroring disabled");
    }

    let jwt_secret = auth::jwt_secret()?;
    let ingest_token = auth::ingest_token();
    seed_admin(&store).await;

    let (ingest_tx, ingest_rx) = mpsc::channel(64);
    let (events_tx, _) = broadcast::channel(256);
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    let api_metrics = Arc::new(metrics::Metrics::default());
    tokio::spawn(analyzer::run_analyzer(
        analyzer::AnalyzerDeps {
            rx: ingest_rx,
            store: store.clone(),
            alerts_tx: events_tx.clone(),
            http,
            webhook_url,
            config: analyzer::DetectorConfig::default(),
            metrics: api_metrics.clone(),
        },
        analyzer::NoopExplainer,
    ));

    // Dashboard SPA: served at / with index.html fallback for client routes.
    // Missing dist dir means API-only mode; it must not crash startup.
    let serve_dir =
        std::env::var("SERVE_DIR").unwrap_or_else(|_| "crates/mist-dashboard/dist".to_owned());
    let index = std::path::Path::new(&serve_dir).join("index.html");
    let spa = if index.is_file() {
        tracing::info!(%serve_dir, "serving dashboard SPA");
        Some(ServeDir::new(&serve_dir).fallback(ServeFile::new(index)))
    } else {
        tracing::warn!(%serve_dir, "dashboard dist missing; running API-only");
        None
    };
    let state = AppState {
        inner: Arc::new(AppStateInner {
            store,
            ingest_tx,
            events_tx,
            jwt_secret,
            ingest_token,
            metrics: api_metrics,
            spa,
        }),
    };
    let app = router(state);
    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_owned())
        .parse()?;
    tracing::info!(%addr, "mist-api listening");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt as _;

    use super::*;

    fn batch() -> FlowBatch {
        FlowBatch {
            node: "node-1".to_owned(),
            flows: Vec::new(),
        }
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let (state, _rx) = test_state();
        let response = router(state)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ingest_accepts_batch() {
        let (state, mut rx) = test_state();
        let response = router(state)
            .oneshot(
                Request::post("/api/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&batch()).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        // The batch reaches the analyzer channel.
        assert_eq!(rx.recv().await.unwrap().node, "node-1");
    }

    #[tokio::test]
    async fn ingest_requires_token_when_configured() {
        let (state, _rx) = test_state_with_ingest_token(Some("s3cret".to_owned()));
        let post = |bearer: Option<&str>| {
            let mut request = Request::post("/api/ingest")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&batch()).unwrap()))
                .unwrap();
            if let Some(token) = bearer {
                request
                    .headers_mut()
                    .insert("authorization", format!("Bearer {token}").parse().unwrap());
            }
            router(state.clone()).oneshot(request)
        };
        let missing = post(None).await.unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        let wrong = post(Some("nope")).await.unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let ok = post(Some("s3cret")).await.unwrap();
        assert_eq!(ok.status(), StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn metrics_exposes_counters_and_storage_gauges() {
        let (state, _rx) = test_state();
        // Seed two flows and one firing + one resolved alert.
        let flow = || FlowRecord {
            key: mist_types::FlowKey {
                src_ip: "10.0.1.4".parse().unwrap(),
                src_port: 51234,
                dst_ip: "10.0.2.9".parse().unwrap(),
                dst_port: 443,
                protocol: 6,
            },
            direction: mist_types::TrafficDirection::Egress,
            bytes: 100,
            packets: 2,
            start_unix_ms: 1000,
            last_seen_unix_ms: 2000,
            node: "node-1".to_owned(),
            src_pod: None,
            dst_pod: None,
        };
        state
            .inner
            .store
            .save_flows(&[flow(), flow()])
            .await
            .unwrap();
        let alert = |id: &str| mist_types::Alert {
            id: id.to_owned(),
            severity: mist_types::Severity::Warning,
            title: "t".to_owned(),
            detail: "d".to_owned(),
            first_seen_unix_ms: 1000,
            last_seen_unix_ms: 2000,
            labels: HashMap::default(),
            explanation: None,
        };
        state.inner.store.upsert_alert(&alert("a1")).await.unwrap();
        state.inner.store.upsert_alert(&alert("a2")).await.unwrap();
        state.inner.store.resolve_alert("a2").await.unwrap();

        // One ingested batch with two flows exercises the accept counters.
        let accepted = router(state.clone())
            .oneshot(
                Request::post("/api/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&FlowBatch {
                            node: "node-1".to_owned(),
                            flows: vec![flow(), flow()],
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);

        // /metrics is public (no token) for in-cluster scraping.
        let response = router(state)
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("content-type").unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        for line in [
            "mist_api_ingest_batches_accepted_total 1",
            "mist_api_ingest_flows_accepted_total 2",
            "mist_api_ingest_batches_shed_total 0",
            "mist_api_flows_stored 2",
            "mist_api_alerts_firing 1",
            "mist_api_alerts_resolved 1",
            "mist_api_build_info{version=\"",
        ] {
            assert!(body.contains(line), "missing {line:?} in:\n{body}");
        }
    }

    #[tokio::test]
    async fn alerts_roundtrip_through_rest() {
        let (state, _rx) = test_state();
        // Seed one alert through the store.
        let alert = mist_types::Alert {
            id: "scan:1.2.3.4".to_owned(),
            severity: mist_types::Severity::Critical,
            title: "scan".to_owned(),
            detail: "detail".to_owned(),
            first_seen_unix_ms: 1000,
            last_seen_unix_ms: 2000,
            labels: HashMap::default(),
            explanation: None,
        };
        state.inner.store.upsert_alert(&alert).await.unwrap();

        let app = || router(state.clone());
        let token = auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
        let bearer = format!("Bearer {token}");
        let get = |uri: &str| {
            app().oneshot(
                Request::get(uri)
                    .header("authorization", bearer.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        let body_json = async |response: axum::response::Response| {
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };

        let list = get("/api/alerts").await.unwrap();
        assert_eq!(list.status(), StatusCode::OK);
        assert_eq!(body_json(list).await.as_array().unwrap().len(), 1);

        let one = get("/api/alerts/scan:1.2.3.4").await.unwrap();
        assert_eq!(one.status(), StatusCode::OK);
        assert_eq!(body_json(one).await["state"], "firing");

        let missing = get("/api/alerts/nope").await.unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let resolved = app()
            .oneshot(
                Request::post("/api/alerts/scan:1.2.3.4/resolve")
                    .header("authorization", bearer.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resolved.status(), StatusCode::OK);
        assert_eq!(body_json(resolved).await["state"], "resolved");
    }

    async fn serve_addr(state: AppState) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        addr
    }

    fn ws_url(addr: &std::net::SocketAddr, state: &AppState) -> String {
        let token = auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
        format!("ws://{addr}/api/ws?token={token}")
    }

    async fn seed_user(state: &AppState) {
        let hash = auth::hash_password("s3cret").await.unwrap();
        state
            .inner
            .store
            .upsert_user("admin@example.com", &hash)
            .await
            .unwrap();
    }

    fn login_request(email: &str, password: &str) -> Request<Body> {
        Request::post("/api/auth/login")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "email": email, "password": password }).to_string(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn login_success_issues_token() {
        let (state, _rx) = test_state();
        seed_user(&state).await;
        let response = router(state.clone())
            .oneshot(login_request("admin@example.com", "s3cret"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["email"], "admin@example.com");
        let token = body["token"].as_str().unwrap();
        assert_eq!(
            auth::verify_token(token, "test-secret").as_deref(),
            Some("admin@example.com")
        );
    }

    #[tokio::test]
    async fn legacy_argon2_hash_still_verifies() {
        // Reference hash produced by argon2 0.5.3 for "s3cret": rows written
        // before the 0.6 upgrade must keep verifying. Shared with the login
        // timing-equalization dummy so the two cannot drift apart.
        assert!(
            auth::verify_password("s3cret", auth::DUMMY_HASH)
                .await
                .unwrap()
        );
        assert!(
            !auth::verify_password("wrong", auth::DUMMY_HASH)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn login_rejects_wrong_password_and_unknown_user() {
        let (state, _rx) = test_state();
        seed_user(&state).await;
        for (email, password) in [
            ("admin@example.com", "wrong"),
            ("nobody@example.com", "s3cret"),
        ] {
            let response = router(state.clone())
                .oneshot(login_request(email, password))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert!(body.get("error").is_some());
        }
    }

    #[tokio::test]
    async fn protected_routes_require_token() {
        let (state, _rx) = test_state();
        let token = auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
        let bearer = format!("Bearer {token}");

        // No token and a bogus token both fail.
        for header in [None, Some(String::from("Bearer bogus"))] {
            let mut builder = Request::get("/api/alerts");
            if let Some(header) = header {
                builder = builder.header("authorization", header);
            }
            let response = router(state.clone())
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let response = router(state.clone())
            .oneshot(
                Request::get("/api/alerts")
                    .header("authorization", bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn websocket_rejects_missing_and_bad_tokens() {
        let (state, _rx) = test_state();
        let addr = serve_addr(state).await;
        let bad = format!("ws://{addr}/api/ws?token=bogus");
        for url in [format!("ws://{addr}/api/ws"), bad] {
            assert!(
                tokio_tungstenite::connect_async(url).await.is_err(),
                "handshake without a valid token must fail"
            );
        }
    }

    #[tokio::test]
    async fn websocket_streams_broadcast_events() {
        use futures::SinkExt as _;

        let (state, _rx) = test_state();
        let addr = serve_addr(state.clone()).await;

        let (mut socket, _) = tokio_tungstenite::connect_async(ws_url(&addr, &state))
            .await
            .unwrap();
        // The server drains client messages; a ping followed by a clean close
        // exercises upgrade, liveness, and teardown.
        socket
            .send(tokio_tungstenite::tungstenite::Message::Ping(
                vec![1, 2, 3].into(),
            ))
            .await
            .unwrap();
        socket.close(None).await.unwrap();
    }

    #[tokio::test]
    async fn websocket_receives_published_alert() {
        use futures::StreamExt as _;

        let (state, _rx) = test_state();
        let events_tx = state.inner.events_tx.clone();
        let addr = serve_addr(state.clone()).await;

        let (mut socket, _) = tokio_tungstenite::connect_async(ws_url(&addr, &state))
            .await
            .unwrap();
        let view = AlertView {
            alert: mist_types::Alert {
                id: "x".to_owned(),
                severity: mist_types::Severity::Info,
                title: "t".to_owned(),
                detail: "d".to_owned(),
                first_seen_unix_ms: 1,
                last_seen_unix_ms: 2,
                labels: HashMap::default(),
                explanation: None,
            },
            state: store::AlertLifecycle::Firing,
            occurrences: 1,
        };
        events_tx.send(AlertEvent::Alert { alert: view }).unwrap();
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let text = message.into_text().unwrap();
        let event: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(event["type"], "alert");
        assert_eq!(event["alert"]["id"], "x");
    }

    #[tokio::test]
    async fn spa_shell_serves_client_routes_but_not_unknown_api_paths() {
        // Minimal dist dir so the SPA routes are registered.
        let dir = std::env::temp_dir().join(format!("mist-spa-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), "<html>spa shell</html>").unwrap();

        let (ingest_tx, _ingest_rx) = mpsc::channel(16);
        let (events_tx, _) = broadcast::channel(16);
        let state = AppState {
            inner: Arc::new(AppStateInner {
                store: Store::Memory(MemStore::default()),
                ingest_tx,
                events_tx,
                jwt_secret: String::from("test-secret"),
                ingest_token: None,
                metrics: Arc::new(metrics::Metrics::default()),
                spa: Some(ServeDir::new(&dir).fallback(ServeFile::new(dir.join("index.html")))),
            }),
        };
        let token = auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
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
