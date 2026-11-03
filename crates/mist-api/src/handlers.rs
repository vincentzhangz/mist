//! HTTP endpoint handlers.

use std::net::{IpAddr, SocketAddr};

use axum::{
    extract::{ConnectInfo, Extension, FromRequestParts, Path, Query, State},
    http::{StatusCode, header},
    response::{IntoResponse, Json},
};
use mist_types::FlowBatch;
use serde::{Deserialize, Serialize};

use crate::{
    analyzer, auth, health,
    middleware::AuthedEmail,
    policy, ratelimit,
    state::{AppError, AppState},
    store::{
        AlertFilter, AlertView, AlertsPage, FlowFilter, FlowsPage, NewSilence, Silence, Store,
    },
};

#[derive(Debug, Default, Deserialize)]
pub(crate) struct FlowQuery {
    node: Option<String>,
    namespace: Option<String>,
    pod: Option<String>,
    since_ms: Option<u64>,
    before_ms: Option<u64>,
    limit: Option<i64>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AlertQuery {
    state: Option<String>,
    severity: Option<String>,
    limit: Option<i64>,
    before_ms: Option<u64>,
}

pub(crate) async fn healthz() -> &'static str {
    "ok"
}

pub(crate) async fn list_flows(
    State(state): State<AppState>,
    Query(query): Query<FlowQuery>,
) -> Result<Json<FlowsPage>, AppError> {
    let limit = query.limit.unwrap_or(100).clamp(1, 10_000);
    let filter = FlowFilter {
        node: query.node,
        namespace: query.namespace,
        pod: query.pod,
        since_ms: query.since_ms,
        before_ms: query.before_ms,
        limit,
    };
    let flows = state.inner.store.list_flows(&filter).await?;
    // A short page means exhaustion. A full page MIGHT be the exact end
    // (total a multiple of the limit); the follow-up then returns only
    // boundary repeats, and clients stop when a page adds no new rows.
    let full = flows.len() >= usize::try_from(limit).unwrap_or(usize::MAX);
    let next_cursor = if full {
        flows.iter().map(|flow| flow.last_seen_unix_ms).min()
    } else {
        None
    };
    Ok(Json(FlowsPage { flows, next_cursor }))
}

/// Stamp `silenced` on views from the current silence rules. A rules
/// lookup failure leaves views unmarked (fail-open) instead of failing
/// the read.
pub(crate) async fn mark_silenced(store: &Store, views: &mut [AlertView]) {
    if views.is_empty() {
        return;
    }
    let rules = match store.list_silences().await {
        Ok(rules) => rules,
        Err(error) => {
            tracing::warn!(?error, "silence lookup failed");
            return;
        }
    };
    let now = crate::store::now_ms();
    for view in views {
        view.silenced = rules
            .iter()
            .any(|rule| crate::store::silence_matches(rule, &view.alert, now));
    }
}

pub(crate) async fn list_alerts(
    State(state): State<AppState>,
    Query(query): Query<AlertQuery>,
) -> Result<Json<AlertsPage>, AppError> {
    let limit = query.limit.unwrap_or(500).clamp(1, 10_000);
    let filter = AlertFilter {
        state: query.state,
        // Stored severities are lowercase; normalize so `Critical` still
        // matches (previously done by a case-insensitive post-filter).
        severity: query.severity.map(|severity| severity.to_lowercase()),
        before_ms: query.before_ms,
        limit,
    };
    let mut alerts = state.inner.store.list_alerts(&filter).await?;
    // Same exhaustion rule as flows: a short page ends the walk; a full
    // page at the exact end yields only boundary repeats next round.
    let full = alerts.len() >= usize::try_from(limit).unwrap_or(usize::MAX);
    let next_cursor = if full {
        alerts.iter().map(|view| view.alert.last_seen_unix_ms).min()
    } else {
        None
    };
    mark_silenced(&state.inner.store, &mut alerts).await;
    Ok(Json(AlertsPage {
        alerts,
        next_cursor,
    }))
}

pub(crate) async fn get_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AlertView>, AppError> {
    let mut view = state
        .inner
        .store
        .get_alert(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    mark_silenced(&state.inner.store, std::slice::from_mut(&mut view)).await;
    Ok(Json(view))
}

pub(crate) async fn resolve_alert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<AlertView>, AppError> {
    let mut view = state
        .inner
        .store
        .resolve_alert(&id)
        .await?
        .ok_or(AppError::NotFound)?;
    mark_silenced(&state.inner.store, std::slice::from_mut(&mut view)).await;
    Ok(Json(view))
}

#[derive(Debug, Deserialize)]
pub(crate) struct AckRequest {
    note: Option<String>,
}

pub(crate) async fn ack_alert(
    State(state): State<AppState>,
    Extension(authed): Extension<AuthedEmail>,
    Path(id): Path<String>,
    Json(request): Json<AckRequest>,
) -> Result<Json<AlertView>, AppError> {
    let note = request.note.unwrap_or_default();
    let mut view = state
        .inner
        .store
        .ack_alert(&id, &authed.0, &note)
        .await?
        .ok_or(AppError::NotFound)?;
    mark_silenced(&state.inner.store, std::slice::from_mut(&mut view)).await;
    Ok(Json(view))
}

pub(crate) async fn list_silences(
    State(state): State<AppState>,
) -> Result<Json<Vec<Silence>>, AppError> {
    Ok(Json(state.inner.store.list_silences().await?))
}

#[derive(Debug, Deserialize)]
pub(crate) struct CreateSilenceRequest {
    severity: Option<String>,
    title_contains: Option<String>,
    alert_id: Option<String>,
    label_key: Option<String>,
    label_value: Option<String>,
    starts_at_ms: Option<u64>,
    ends_at_ms: u64,
    comment: Option<String>,
}

pub(crate) async fn create_silence(
    State(state): State<AppState>,
    Extension(authed): Extension<AuthedEmail>,
    Json(request): Json<CreateSilenceRequest>,
) -> Result<Json<Silence>, AppError> {
    let severity = request
        .severity
        .map(|value| value.trim().to_lowercase())
        .filter(|value| !value.is_empty());
    if let Some(value) = &severity
        && !["info", "warning", "critical"].contains(&value.as_str())
    {
        return Err(AppError::BadRequest(format!("unknown severity: {value}")));
    }
    let starts_at_ms = request.starts_at_ms.unwrap_or_else(crate::store::now_ms);
    if request.ends_at_ms <= starts_at_ms {
        return Err(AppError::BadRequest(
            "ends_at_ms must be after starts_at_ms".to_owned(),
        ));
    }
    let clean = |value: Option<String>| {
        value
            .map(|text| text.trim().to_owned())
            .filter(|text| !text.is_empty())
    };
    let rule = NewSilence {
        severity,
        title_contains: clean(request.title_contains),
        alert_id: clean(request.alert_id),
        label_key: clean(request.label_key),
        label_value: clean(request.label_value),
        starts_at_ms,
        ends_at_ms: request.ends_at_ms,
        created_by: authed.0,
        comment: request.comment.unwrap_or_default().trim().to_owned(),
    };
    Ok(Json(state.inner.store.create_silence(&rule).await?))
}

pub(crate) async fn delete_silence(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, AppError> {
    if state.inner.store.delete_silence(id).await? {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(AppError::NotFound)
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct PolicyQuery {
    namespace: Option<String>,
    since_ms: Option<u64>,
    limit: Option<i64>,
}

/// Recommend a namespace `NetworkPolicy` from observed flows.
pub(crate) async fn recommend_policy(
    State(state): State<AppState>,
    Query(query): Query<PolicyQuery>,
) -> Result<Json<policy::Recommendation>, AppError> {
    let namespace = query
        .namespace
        .filter(|name| !name.trim().is_empty())
        .ok_or_else(|| AppError::BadRequest("namespace query param is required".to_owned()))?;
    let filter = FlowFilter {
        node: None,
        namespace: Some(namespace.clone()),
        pod: None,
        since_ms: query.since_ms,
        before_ms: None,
        limit: query.limit.unwrap_or(5000).clamp(1, 20_000),
    };
    let flows = state.inner.store.list_flows(&filter).await?;
    let cidrs = analyzer::DetectorConfig::default().internal_cidrs;
    Ok(Json(policy::recommend(&flows, &namespace, &cidrs)))
}

pub(crate) async fn ingest(
    State(state): State<AppState>,
    Json(batch): Json<FlowBatch>,
) -> Result<StatusCode, AppError> {
    tracing::debug!(
        node = %batch.node,
        flows = batch.flows.len(),
        "ingest received batch"
    );
    let flows = batch.flows.len();
    // Heartbeat first, so a node keeps reading live even when its batches
    // are shed below; empty batches are heartbeat-only and skip analysis.
    state.inner.heartbeats.record(&batch);
    if batch.flows.is_empty() {
        state.inner.metrics.batch_accepted(0);
        return Ok(StatusCode::ACCEPTED);
    }
    state.inner.ingest_tx.try_send(batch).map_err(|_| {
        tracing::warn!("ingest channel saturated; shedding batch");
        state.inner.metrics.batch_shed();
        AppError::Saturated
    })?;
    state.inner.metrics.batch_accepted(flows);
    Ok(StatusCode::ACCEPTED)
}

/// System health overview: uptime, storage backend, analyzer queue
/// pressure, websocket subscribers, and per-agent heartbeats.
pub(crate) async fn health_overview(State(state): State<AppState>) -> Json<health::HealthOverview> {
    let queue_capacity = state.inner.ingest_tx.max_capacity();
    Json(health::HealthOverview {
        uptime_secs: state.inner.metrics.uptime_secs(),
        storage: match &state.inner.store {
            Store::Postgres(_) => "postgres",
            Store::Memory(_) => "memory",
        },
        analyzer_queue: health::QueueStatus {
            depth: queue_capacity.saturating_sub(state.inner.ingest_tx.capacity()),
            capacity: queue_capacity,
        },
        ws_subscribers: state.inner.events_tx.receiver_count(),
        agents: state.inner.heartbeats.snapshot(),
    })
}

/// Prometheus exposition scrape. Public like `/healthz` (outside `/api/`,
/// so [`require_auth`] lets it through) for in-cluster scraping.
pub(crate) async fn metrics_handler(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, AppError> {
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
pub(crate) struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct LoginResponse {
    token: String,
    email: String,
}

/// Client socket address when connection info is present. Infallible:
/// unit tests serve without it, so those attempts share one bucket.
pub(crate) struct MaybePeer(Option<SocketAddr>);

impl<S> FromRequestParts<S> for MaybePeer
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        std::future::ready(Ok(Self(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|info| info.0),
        )))
    }
}

pub(crate) async fn login(
    State(state): State<AppState>,
    maybe_peer: MaybePeer,
    Json(request): Json<LoginRequest>,
) -> impl IntoResponse {
    // Brute-force guard, checked before any hashing: per-IP sliding window.
    // Without connection info (unit tests) all attempts share one bucket.
    let peer = maybe_peer
        .0
        .map_or_else(|| IpAddr::from([0, 0, 0, 0]), |addr| addr.ip());
    if let ratelimit::Verdict::Deny { retry_after_secs } = state.inner.login_limiter.check(peer) {
        state.inner.metrics.login_limited();
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after_secs.to_string())],
            Json(serde_json::json!({ "error": "too many login attempts" })),
        )
            .into_response();
    }
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use mist_types::FlowBatch;
    use tower::ServiceExt as _;

    use super::*;
    use crate::test_helpers::*;

    #[tokio::test]
    async fn healthz_returns_ok() {
        let (state, _rx) = crate::test_helpers::test_state();
        let response = crate::routes::router(state)
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    #[tokio::test]
    async fn ingest_accepts_batch() {
        let (state, mut rx) = crate::test_helpers::test_state();
        let mut shipment = batch();
        shipment.flows.push(test_flow("node-1", None));
        let response = crate::routes::router(state)
            .oneshot(
                Request::post("/api/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&shipment).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        // The batch reaches the analyzer channel.
        assert_eq!(rx.recv().await.unwrap().node, "node-1");
    }
    #[tokio::test]
    async fn ingest_empty_batch_is_heartbeat_only() {
        let (state, mut rx) = crate::test_helpers::test_state();
        let response = crate::routes::router(state.clone())
            .oneshot(
                Request::post("/api/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&batch()).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        // Heartbeat-only: the analyzer channel stays empty ...
        assert!(rx.try_recv().is_err());
        // ... but the node heartbeat is recorded.
        let beats = state.inner.heartbeats.snapshot();
        assert_eq!(beats.len(), 1);
        assert_eq!(beats[0].node, "node-1");
        assert!(!beats[0].stale);
    }
    #[tokio::test]
    async fn flows_paginate_with_cursor() {
        let (state, _rx) = crate::test_helpers::test_state();
        let mut seed = Vec::new();
        for (index, ms) in [1000, 2000, 3000, 4000, 5000].iter().enumerate() {
            let mut record = test_flow("node-1", None);
            record.node = format!("node-{index}");
            record.last_seen_unix_ms = *ms;
            seed.push(record);
        }
        state.inner.store.save_flows(&seed).await.unwrap();
        let token = auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
        let get = |path: &str| {
            crate::routes::router(state.clone()).oneshot(
                Request::get(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        let page = async |path: &str| {
            let response = get(path).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };

        // Page one: newest first, cursor at the page minimum.
        let first = page("/api/flows?limit=2").await;
        let rows = first["flows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["last_seen_unix_ms"].as_u64(), Some(5000));
        assert_eq!(rows[1]["last_seen_unix_ms"].as_u64(), Some(4000));
        assert_eq!(first["next_cursor"].as_u64(), Some(4000));

        // Page two: the boundary row repeats (inclusive cursor, no skips).
        let second = page("/api/flows?limit=2&before_ms=4000").await;
        let rows = second["flows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["last_seen_unix_ms"].as_u64(), Some(4000));
        assert_eq!(rows[1]["last_seen_unix_ms"].as_u64(), Some(3000));
        assert_eq!(second["next_cursor"].as_u64(), Some(3000));

        // Short page: exhausted, no cursor.
        let last = page("/api/flows?limit=2&before_ms=1000").await;
        assert_eq!(last["flows"].as_array().unwrap().len(), 1);
        assert_eq!(last["next_cursor"], serde_json::Value::Null);
    }
    #[tokio::test]
    async fn alerts_paginate_with_cursor() {
        let (state, _rx) = crate::test_helpers::test_state();
        for (index, ms) in [1000, 2000, 3000, 4000, 5000].iter().enumerate() {
            let alert = mist_types::Alert {
                id: format!("alert-{index}"),
                severity: if index % 2 == 0 {
                    mist_types::Severity::Critical
                } else {
                    mist_types::Severity::Info
                },
                title: "t".to_owned(),
                detail: "d".to_owned(),
                first_seen_unix_ms: *ms,
                last_seen_unix_ms: *ms,
                labels: HashMap::default(),
                explanation: None,
            };
            state.inner.store.upsert_alert(&alert).await.unwrap();
        }
        let token = auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
        let get = |path: &str| {
            crate::routes::router(state.clone()).oneshot(
                Request::get(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        let page = async |path: &str| {
            let response = get(path).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };

        // Page one: newest first, cursor at the page minimum.
        let first = page("/api/alerts?limit=2").await;
        let rows = first["alerts"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["last_seen_unix_ms"].as_u64(), Some(5000));
        assert_eq!(rows[1]["last_seen_unix_ms"].as_u64(), Some(4000));
        assert_eq!(first["next_cursor"].as_u64(), Some(4000));

        // Page two: the boundary row repeats (inclusive cursor, no skips).
        let second = page("/api/alerts?limit=2&before_ms=4000").await;
        let rows = second["alerts"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["last_seen_unix_ms"].as_u64(), Some(4000));
        assert_eq!(rows[1]["last_seen_unix_ms"].as_u64(), Some(3000));

        // Severity pushdown: mixed-case params still match, and only the
        // matching rows come back (post-filter parity).
        let critical = page("/api/alerts?severity=Critical").await;
        assert_eq!(critical["alerts"].as_array().unwrap().len(), 3);
        let info = page("/api/alerts?severity=info").await;
        assert_eq!(info["alerts"].as_array().unwrap().len(), 2);
        let bogus = page("/api/alerts?severity=bogus").await;
        assert_eq!(bogus["alerts"].as_array().unwrap().len(), 0);

        // Short page: exhausted, no cursor.
        let last = page("/api/alerts?limit=2&before_ms=1000").await;
        assert_eq!(last["alerts"].as_array().unwrap().len(), 1);
        assert_eq!(last["next_cursor"], serde_json::Value::Null);

        // State filter still narrows server-side.
        state.inner.store.resolve_alert("alert-0").await.unwrap();
        let resolved = page("/api/alerts?state=resolved").await;
        assert_eq!(resolved["alerts"].as_array().unwrap().len(), 1);
        let firing = page("/api/alerts?state=firing").await;
        assert_eq!(firing["alerts"].as_array().unwrap().len(), 4);
    }
    #[tokio::test]
    async fn health_overview_reports_agents_and_queue() {
        let (state, _rx) = crate::test_helpers::test_state();
        let mut shipment = batch();
        shipment.updated = 42;
        shipment.flows.push(test_flow("node-1", None));
        let accepted = crate::routes::router(state.clone())
            .oneshot(
                Request::post("/api/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&shipment).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);
        let token = auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
        let response = crate::routes::router(state)
            .oneshot(
                Request::get("/api/health/overview")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let overview: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(overview["storage"], "memory");
        // The un-consumed batch is still sitting in the analyzer queue.
        assert_eq!(overview["analyzer_queue"]["depth"].as_u64(), Some(1));
        assert_eq!(overview["analyzer_queue"]["capacity"].as_u64(), Some(16));
        let agents = overview["agents"].as_array().unwrap();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0]["node"], "node-1");
        assert_eq!(agents[0]["updated"].as_u64(), Some(42));
        assert_eq!(agents[0]["stale"], false);
    }
    #[tokio::test]
    async fn ingest_requires_token_when_configured() {
        let (state, _rx) = crate::test_helpers::test_state_with_ingest_tokens(vec![
            "s3cret".to_owned(),
            "r0tated".to_owned(),
        ]);
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
            crate::routes::router(state.clone()).oneshot(request)
        };
        let missing = post(None).await.unwrap();
        assert_eq!(missing.status(), StatusCode::UNAUTHORIZED);
        let wrong = post(Some("nope")).await.unwrap();
        assert_eq!(wrong.status(), StatusCode::UNAUTHORIZED);
        let ok = post(Some("s3cret")).await.unwrap();
        assert_eq!(ok.status(), StatusCode::ACCEPTED);
        // Any token in the set is accepted (rotation / per-agent tokens).
        let rotated = post(Some("r0tated")).await.unwrap();
        assert_eq!(rotated.status(), StatusCode::ACCEPTED);
    }
    #[tokio::test]
    async fn metrics_exposes_counters_and_storage_gauges() {
        let (state, _rx) = crate::test_helpers::test_state();
        // Seed two flows and one firing + one resolved alert.
        let flow = test_flow("node-1", None);
        state
            .inner
            .store
            .save_flows(&[flow.clone(), flow.clone()])
            .await
            .unwrap();
        state
            .inner
            .store
            .upsert_alert(&test_alert("a1"))
            .await
            .unwrap();
        state
            .inner
            .store
            .upsert_alert(&test_alert("a2"))
            .await
            .unwrap();
        state.inner.store.resolve_alert("a2").await.unwrap();

        // One ingested batch with two flows exercises the accept counters.
        let accepted = crate::routes::router(state.clone())
            .oneshot(
                Request::post("/api/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::to_string(&FlowBatch {
                            node: "node-1".to_owned(),
                            flows: vec![flow.clone(), flow],
                            updated: 0,
                            skipped: 0,
                            map_full: 0,
                        })
                        .unwrap(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);

        // /metrics is public (no token) for in-cluster scraping.
        let response = crate::routes::router(state)
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
        let (state, _rx) = crate::test_helpers::test_state();
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

        let app = || crate::routes::router(state.clone());
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
        assert_eq!(body_json(list).await["alerts"].as_array().unwrap().len(), 1);

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
    #[tokio::test]
    async fn ack_roundtrip_through_rest() {
        let (state, _rx) = crate::test_helpers::test_state();
        let alert = mist_types::Alert {
            id: "scan:1.2.3.4".to_owned(),
            severity: mist_types::Severity::Warning,
            title: "scan".to_owned(),
            detail: "detail".to_owned(),
            first_seen_unix_ms: 1000,
            last_seen_unix_ms: 2000,
            labels: HashMap::default(),
            explanation: None,
        };
        state.inner.store.upsert_alert(&alert).await.unwrap();

        let app = || crate::routes::router(state.clone());
        let token = auth::create_token("acker@example.com", &state.inner.jwt_secret).unwrap();
        let bearer = format!("Bearer {token}");
        let body_json = async |response: axum::response::Response| {
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };
        let ack = |uri: &str, note: &str| {
            app().oneshot(
                Request::post(uri)
                    .header("authorization", bearer.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(format!(r#"{{"note":"{note}"}}"#)))
                    .unwrap(),
            )
        };
        let acked = ack("/api/alerts/scan:1.2.3.4/ack", "on it").await.unwrap();
        assert_eq!(acked.status(), StatusCode::OK);
        let body = body_json(acked).await;
        assert_eq!(body["state"], "acknowledged");
        assert_eq!(body["acked_by"], "acker@example.com");
        assert_eq!(body["ack_note"], "on it");

        let missing = ack("/api/alerts/nope/ack", "").await.unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        // Acking a resolved alert is a no-op.
        state
            .inner
            .store
            .resolve_alert("scan:1.2.3.4")
            .await
            .unwrap();
        let reack = ack("/api/alerts/scan:1.2.3.4/ack", "").await.unwrap();
        assert_eq!(reack.status(), StatusCode::NOT_FOUND);
    }
    #[tokio::test]
    async fn silences_roundtrip_through_rest() {
        let (state, _rx) = crate::test_helpers::test_state();
        let alert = mist_types::Alert {
            id: "scan:1.2.3.4".to_owned(),
            severity: mist_types::Severity::Critical,
            title: "Port scan of node-1".to_owned(),
            detail: "detail".to_owned(),
            first_seen_unix_ms: 1000,
            last_seen_unix_ms: 2000,
            labels: HashMap::default(),
            explanation: None,
        };
        state.inner.store.upsert_alert(&alert).await.unwrap();

        let app = || crate::routes::router(state.clone());
        let token = auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
        let bearer = format!("Bearer {token}");
        let body_json = async |response: axum::response::Response| {
            let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
        };
        let get = |uri: &str| {
            app().oneshot(
                Request::get(uri)
                    .header("authorization", bearer.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
        };
        let post = |uri: &str, body: serde_json::Value| {
            app().oneshot(
                Request::post(uri)
                    .header("authorization", bearer.clone())
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
        };

        let empty = get("/api/silences").await.unwrap();
        assert_eq!(empty.status(), StatusCode::OK);
        assert_eq!(body_json(empty).await.as_array().unwrap().len(), 0);

        let bad_severity = post(
            "/api/silences",
            serde_json::json!({"severity": "bogus", "ends_at_ms": u64::MAX}),
        )
        .await
        .unwrap();
        assert_eq!(bad_severity.status(), StatusCode::BAD_REQUEST);

        let bad_window = post(
            "/api/silences",
            serde_json::json!({"starts_at_ms": 2000, "ends_at_ms": 1000}),
        )
        .await
        .unwrap();
        assert_eq!(bad_window.status(), StatusCode::BAD_REQUEST);

        let created = post(
            "/api/silences",
            serde_json::json!({
                "severity": "CRITICAL",
                "title_contains": "port scan",
                "ends_at_ms": u64::MAX,
                "comment": "investigating",
            }),
        )
        .await
        .unwrap();
        assert_eq!(created.status(), StatusCode::OK);
        let rule = body_json(created).await;
        assert_eq!(rule["severity"], "critical");
        assert_eq!(rule["created_by"], "tester@example.com");
        let id = rule["id"].as_i64().expect("numeric id");

        // The matching alert now reads back silenced.
        let one = get("/api/alerts/scan:1.2.3.4").await.unwrap();
        assert_eq!(body_json(one).await["silenced"], true);

        let missing = app()
            .oneshot(
                Request::delete("/api/silences/9999")
                    .header("authorization", bearer.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);

        let deleted = app()
            .oneshot(
                Request::delete(format!("/api/silences/{id}"))
                    .header("authorization", bearer.clone())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        let one = get("/api/alerts/scan:1.2.3.4").await.unwrap();
        assert_eq!(body_json(one).await["silenced"], false);
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
        let (state, _rx) = crate::test_helpers::test_state();
        seed_user(&state).await;
        let response = crate::routes::router(state.clone())
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
    async fn login_rate_limits_after_ten_attempts() {
        let (state, _rx) = crate::test_helpers::test_state();
        seed_user(&state).await;
        for attempt in 1..=11 {
            let response = crate::routes::router(state.clone())
                .oneshot(login_request("admin@example.com", "wrong"))
                .await
                .unwrap();
            if attempt <= 10 {
                assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            } else {
                assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
                let retry_after: u64 = response
                    .headers()
                    .get("retry-after")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .parse()
                    .unwrap();
                assert!((1..=60).contains(&retry_after));
                let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .unwrap();
                let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(body["error"], "too many login attempts");
            }
        }
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
        let (state, _rx) = crate::test_helpers::test_state();
        seed_user(&state).await;
        for (email, password) in [
            ("admin@example.com", "wrong"),
            ("nobody@example.com", "s3cret"),
        ] {
            let response = crate::routes::router(state.clone())
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
}
