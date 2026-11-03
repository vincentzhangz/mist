//! Shared fixtures for unit tests (test builds only).

use std::{collections::HashMap, sync::Arc};

use mist_types::{Alert, FlowBatch, FlowRecord, PodRef, Severity, TrafficDirection};
use tokio::sync::{broadcast, mpsc};

use crate::{
    health, metrics, ratelimit,
    state::{AppState, AppStateInner},
    store::{MemStore, NewSilence, Silence, Store},
};

pub(crate) fn test_state() -> (AppState, mpsc::Receiver<FlowBatch>) {
    test_state_with_ingest_tokens(Vec::new())
}

pub(crate) fn test_state_with_ingest_tokens(
    ingest_tokens: Vec<String>,
) -> (AppState, mpsc::Receiver<FlowBatch>) {
    build_state(ingest_tokens, None)
}

/// Test state with the dashboard SPA served from `dir` (must contain
/// `index.html`); mirrors [`test_state`] otherwise.
pub(crate) fn test_state_with_spa(dir: &std::path::Path) -> (AppState, mpsc::Receiver<FlowBatch>) {
    let spa = tower_http::services::ServeDir::new(dir)
        .fallback(tower_http::services::ServeFile::new(dir.join("index.html")));
    build_state(Vec::new(), Some(spa))
}

fn build_state(
    ingest_tokens: Vec<String>,
    spa: Option<tower_http::services::ServeDir<tower_http::services::ServeFile>>,
) -> (AppState, mpsc::Receiver<FlowBatch>) {
    let (ingest_tx, ingest_rx) = mpsc::channel(16);
    let (events_tx, _) = broadcast::channel(16);
    let state = AppState {
        inner: Arc::new(AppStateInner {
            store: Store::Memory(MemStore::default()),
            ingest_tx,
            events_tx,
            jwt_secret: String::from("test-secret"),
            ingest_tokens,
            metrics: Arc::new(metrics::Metrics::default()),
            heartbeats: health::HeartbeatTracker::new(),
            login_limiter: ratelimit::LoginLimiter::default(),
            spa,
        }),
    };
    (state, ingest_rx)
}

pub(crate) fn batch() -> FlowBatch {
    FlowBatch {
        node: "node-1".to_owned(),
        flows: Vec::new(),
        updated: 0,
        skipped: 0,
        map_full: 0,
    }
}
/// Fixed-tuple flow fixture; callers pick node/pod and override the rest.
pub(crate) fn test_flow(node: &str, pod: Option<(&str, &str)>) -> FlowRecord {
    FlowRecord {
        key: mist_types::FlowKey {
            src_ip: "10.0.1.4".parse().unwrap(),
            src_port: 51234,
            dst_ip: "10.0.2.9".parse().unwrap(),
            dst_port: 443,
            protocol: 6,
        },
        direction: TrafficDirection::Egress,
        bytes: 100,
        packets: 2,
        start_unix_ms: 1_700_000_000_000,
        last_seen_unix_ms: 1_700_000_001_000,
        node: node.to_owned(),
        src_pod: pod.map(|(namespace, name)| PodRef {
            namespace: namespace.to_owned(),
            name: name.to_owned(),
            labels: HashMap::new(),
        }),
        dst_pod: None,
    }
}

/// Fixed warning fixture with caller-chosen id.
pub(crate) fn test_alert(id: &str) -> Alert {
    Alert {
        id: id.to_owned(),
        severity: Severity::Warning,
        title: "scan".to_owned(),
        detail: "detail".to_owned(),
        first_seen_unix_ms: 1_700_000_000_000,
        last_seen_unix_ms: 1_700_000_060_000,
        labels: HashMap::new(),
        explanation: None,
    }
}

/// Bare silence rule with a 1000..2000 window.
pub(crate) fn test_silence() -> Silence {
    Silence {
        id: 0,
        severity: None,
        title_contains: None,
        alert_id: None,
        label_key: None,
        label_value: None,
        starts_at_ms: 1_000,
        ends_at_ms: 2_000,
        created_by: "tester@example.com".to_owned(),
        comment: String::new(),
    }
}

/// Bare new silence rule with a caller-chosen expiry.
pub(crate) fn test_new_silence(ends_at_ms: u64) -> NewSilence {
    NewSilence {
        severity: None,
        title_contains: None,
        alert_id: None,
        label_key: None,
        label_value: None,
        starts_at_ms: 0,
        ends_at_ms,
        created_by: "tester@example.com".to_owned(),
        comment: String::new(),
    }
}
