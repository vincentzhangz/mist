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
//! one of the provisioned `INGEST_TOKEN`/`INGEST_TOKENS` as `Bearer` when
//! configured, and stays open otherwise. `JWT_SECRET` is required at
//! startup (fail closed).

mod analyzer;
mod auth;
mod handlers;
mod health;
mod llm;
mod metrics;
mod middleware;
mod mtls;
mod notify;
mod policy;
mod ratelimit;
mod routes;
mod serve;
mod state;
mod store;
#[cfg(test)]
mod test_helpers;
mod ws;

use std::{net::SocketAddr, sync::Arc};

use tokio::sync::{broadcast, mpsc};
use tower_http::services::{ServeDir, ServeFile};
use tracing_subscriber::EnvFilter;

use crate::{
    state::{AppState, AppStateInner},
    store::{MemStore, PgStore, Store},
};

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
    let ingest_tokens = auth::ingest_tokens();
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
        llm::explainer_from_env(),
        notify::NotifyConfig::from_env(),
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
            ingest_tokens,
            metrics: api_metrics,
            heartbeats: health::HeartbeatTracker::new(),
            login_limiter: ratelimit::LoginLimiter::default(),
            spa,
        }),
    };
    let addr: SocketAddr = std::env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:3000".to_owned())
        .parse()?;
    tracing::info!(%addr, "mist-api listening");
    let (main_tls, mtls) = serve::tls_setup().await?;
    serve::serve(state, addr, main_tls, mtls).await
}
