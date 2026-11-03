//! Shared application state and the API error type.

use std::sync::Arc;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Json},
};
use mist_types::FlowBatch;
use tokio::sync::{broadcast, mpsc};
use tower_http::services::{ServeDir, ServeFile};

use crate::{analyzer::AlertEvent, health, metrics, ratelimit, store::Store};

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) inner: Arc<AppStateInner>,
}

pub(crate) struct AppStateInner {
    pub(crate) store: Store,
    pub(crate) ingest_tx: mpsc::Sender<FlowBatch>,
    pub(crate) events_tx: broadcast::Sender<AlertEvent>,
    pub(crate) jwt_secret: String,
    /// Accepted `Bearer` tokens for `/api/ingest`; empty leaves ingest open.
    pub(crate) ingest_tokens: Vec<String>,
    pub(crate) metrics: std::sync::Arc<metrics::Metrics>,
    /// Per-node agent heartbeats folded from ingest batches.
    pub(crate) heartbeats: health::HeartbeatTracker,
    /// Per-IP sliding-window guard for the login endpoint.
    pub(crate) login_limiter: ratelimit::LoginLimiter,
    /// Dashboard SPA file service; `None` runs API-only.
    pub(crate) spa: Option<ServeDir<ServeFile>>,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum AppError {
    #[error("storage error: {0}")]
    Store(#[from] anyhow::Error),
    #[error("not found")]
    NotFound,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("ingest saturated; retry later")]
    Saturated,
}

impl IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            Self::Store(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Saturated => StatusCode::SERVICE_UNAVAILABLE,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}
