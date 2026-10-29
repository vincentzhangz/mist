//! Anomaly detection over flow batches: statistical baselines first (no
//! external dependencies), with alert explanations left to Phase 5.
//!
//! Detectors (all pure over [`AnalyzerState`], unit-tested below):
//! - volumetric spike vs per-endpoint EWMA baseline,
//! - first outbound connection to an external endpoint,
//! - port scan (many distinct ports per remote in a window),
//! - beaconing (suspiciously regular outbound connections).
//!
//! [`run_analyzer`] wires the detectors into a background task: it persists
//! flows, scores batches, stores alerts, broadcasts live events, and mirrors
//! alerts to the operator webhook.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::IpAddr,
};

use mist_types::{Alert, FlowBatch, FlowRecord, Severity, TrafficDirection};
use tokio::sync::{broadcast, mpsc};

use crate::store::{AlertView, Store};

/// Events fanned out to WebSocket subscribers.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum AlertEvent {
    Flows { flows: Vec<FlowRecord> },
    Alert { alert: AlertView },
}

/// Detector tuning. All fields have sane defaults; the API server overrides
/// from environment.
#[derive(Clone, Debug)]
pub struct DetectorConfig {
    /// CIDRs considered internal, as (network, `prefix_len`) in host order.
    pub internal_cidrs: Vec<(u32, u8)>,
    /// Spike factor over the EWMA baseline.
    pub spike_factor: f64,
    /// Minimum bytes for a spike alert (guards tiny flows).
    pub spike_min_bytes: u64,
    /// Distinct ports in the window that constitute a scan.
    pub scan_ports: usize,
    /// Scan window in seconds.
    pub scan_window_secs: u64,
    /// Minimum beacon samples before scoring.
    pub beacon_min_samples: usize,
    /// Maximum coefficient of variation (std/mean gap) for beaconing.
    pub beacon_max_cv: f64,
    /// Minimum mean gap in seconds for beaconing (excludes tight loops).
    pub beacon_min_mean_secs: u32,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            internal_cidrs: [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "127.0.0.0/8",
            ]
            .into_iter()
            .filter_map(parse_cidr)
            .collect(),
            spike_factor: 5.0,
            spike_min_bytes: 1_000_000,
            scan_ports: 20,
            scan_window_secs: 60,
            beacon_min_samples: 10,
            beacon_max_cv: 0.15,
            beacon_min_mean_secs: 5,
        }
    }
}

/// Parse `10.244.0.0/16` into (network, `prefix_len`).
#[must_use]
pub fn parse_cidr(text: &str) -> Option<(u32, u8)> {
    let (addr, prefix) = text.split_once('/')?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    let ip: std::net::Ipv4Addr = addr.parse().ok()?;
    let bits = u32::from(ip);
    let mask = mask_for(prefix);
    Some((bits & mask, prefix))
}

const fn mask_for(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        !0u32 << (32 - prefix)
    }
}

/// True when an IPv4 address falls in any of the CIDRs. IPv6 is treated as
/// external (the sensor is IPv4-only in Phase 1).
#[must_use]
pub fn is_internal(ip: &IpAddr, cidrs: &[(u32, u8)]) -> bool {
    let IpAddr::V4(v4) = ip else {
        return false;
    };
    let bits = u32::from(*v4);
    cidrs
        .iter()
        .any(|(network, prefix)| bits & mask_for(*prefix) == *network)
}

/// Stable identity for the local side of a flow: pod when attributed,
// otherwise the node plus IP.
fn local_identity(
    record: &FlowRecord,
    local_pod: Option<&mist_types::PodRef>,
    local_ip: &IpAddr,
) -> String {
    local_pod.map_or_else(
        || format!("{}:{}", record.node, local_ip),
        |pod| format!("{}/{}", pod.namespace, pod.name),
    )
}

/// (local identity, remote ip, remote port, protocol): EWMA baseline key.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct BaselineKey {
    local: String,
    remote_ip: String,
    remote_port: u16,
    protocol: u8,
}

#[derive(Clone, Debug)]
struct EmaState {
    ema: f64,
    intervals: u64,
    last_seen_ms: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct PairKey {
    local: String,
    remote: String,
}

#[derive(Default)]
pub struct AnalyzerState {
    baselines: HashMap<BaselineKey, EmaState>,
    known_endpoints: HashMap<PairKey, u64>,
    port_hits: HashMap<PairKey, VecDeque<(u16, u64)>>,
    beacons: HashMap<PairKey, VecDeque<u64>>,
    batches: u64,
}

/// Entries idle longer than this are pruned from detector state.
const STATE_TTL_MS: u64 = 3_600_000;

/// Feed one batch through every detector. `now_ms` is event time (the batch's
/// newest observation), which keeps the detectors deterministic and testable.
pub fn process_batch(
    state: &mut AnalyzerState,
    batch: &FlowBatch,
    config: &DetectorConfig,
) -> Vec<Alert> {
    let mut alerts = Vec::new();
    for record in &batch.flows {
        if let Some(alert) = check_new_endpoint(state, record, config) {
            alerts.push(alert);
        }
        if let Some(alert) = check_spike(state, record, config) {
            alerts.push(alert);
        }
        if let Some(alert) = check_scan(state, record, config) {
            alerts.push(alert);
        }
        if let Some(alert) = check_beacon(state, record, config) {
            alerts.push(alert);
        }
    }
    state.batches = state.batches.saturating_add(1);
    if state.batches.is_multiple_of(12) {
        let horizon = batch
            .flows
            .iter()
            .map(|record| record.last_seen_unix_ms)
            .max()
            .unwrap_or(0);
        prune(state, horizon);
    }
    alerts
}

/// Drop detector state idle longer than the TTL.
fn prune(state: &mut AnalyzerState, now_ms: u64) {
    let cutoff = now_ms.saturating_sub(STATE_TTL_MS);
    state.baselines.retain(|_, ema| ema.last_seen_ms >= cutoff);
    state.known_endpoints.retain(|_, seen| *seen >= cutoff);
    state.port_hits.retain(|_, _| true);
    state.beacons.retain(|_, _| true);
    for hits in state.port_hits.values_mut() {
        while hits.front().is_some_and(|&(_, ts)| ts < cutoff) {
            hits.pop_front();
        }
    }
    for samples in state.beacons.values_mut() {
        while samples.front().is_some_and(|&ts| ts < cutoff) {
            samples.pop_front();
        }
    }
    state.port_hits.retain(|_, hits| !hits.is_empty());
    state.beacons.retain(|_, samples| !samples.is_empty());
}

/// First outbound connection from a workload to an external endpoint.
fn check_new_endpoint(
    state: &mut AnalyzerState,
    record: &FlowRecord,
    config: &DetectorConfig,
) -> Option<Alert> {
    if record.direction != TrafficDirection::Egress {
        return None;
    }
    if is_internal(&record.key.dst_ip, &config.internal_cidrs) {
        return None;
    }
    let local = local_identity(record, record.src_pod.as_ref(), &record.key.src_ip);
    let key = PairKey {
        local: local.clone(),
        remote: format!("{}:{}", record.key.dst_ip, record.key.dst_port),
    };
    if state.known_endpoints.contains_key(&key) {
        return None;
    }
    state.known_endpoints.insert(key, record.last_seen_unix_ms);
    Some(Alert {
        id: format!(
            "new-endpoint:{local}:{}:{}",
            record.key.dst_ip, record.key.dst_port
        ),
        severity: Severity::Info,
        title: format!(
            "New external endpoint: {}:{}",
            record.key.dst_ip, record.key.dst_port
        ),
        detail: format!(
            "{local} connected to external {}:{}:{} for the first time ({} bytes)",
            record.key.dst_ip, record.key.dst_port, record.key.protocol, record.bytes,
        ),
        first_seen_unix_ms: record.last_seen_unix_ms,
        last_seen_unix_ms: record.last_seen_unix_ms,
        labels: workload_labels(record, true),
        explanation: None,
    })
}

/// Volumetric spike over the per-endpoint EWMA baseline.
fn check_spike(
    state: &mut AnalyzerState,
    record: &FlowRecord,
    config: &DetectorConfig,
) -> Option<Alert> {
    let (local, remote_ip, remote_port) = sides(record);
    let key = BaselineKey {
        local: local.clone(),
        remote_ip: remote_ip.to_string(),
        remote_port,
        protocol: record.key.protocol,
    };
    let ema = state.baselines.entry(key).or_insert_with(|| EmaState {
        ema: bytes_f64(record.bytes),
        intervals: 0,
        last_seen_ms: record.last_seen_unix_ms,
    });
    // Score before updating, with a short warmup.
    let spike = ema.intervals >= 3
        && is_spike(
            record.bytes,
            ema.ema,
            config.spike_factor,
            config.spike_min_bytes,
        );
    ema.ema = 0.3 * bytes_f64(record.bytes) + 0.7 * ema.ema;
    ema.intervals = ema.intervals.saturating_add(1);
    ema.last_seen_ms = record.last_seen_unix_ms;
    if !spike {
        return None;
    }
    Some(Alert {
        id: format!("spike:{local}:{remote_ip}:{remote_port}"),
        severity: Severity::Warning,
        title: format!("Traffic spike: {local} <-> {remote_ip}:{remote_port}"),
        detail: format!(
            "{} bytes in one interval vs baseline {:.0} (factor {:.1})",
            record.bytes, ema.ema, config.spike_factor,
        ),
        first_seen_unix_ms: record.last_seen_unix_ms,
        last_seen_unix_ms: record.last_seen_unix_ms,
        labels: workload_labels(record, record.direction == TrafficDirection::Egress),
        explanation: None,
    })
}

/// Byte counts as f64. Counts here are far below 2^53, so the conversion
/// is exact.
#[allow(clippy::cast_precision_loss)]
fn bytes_f64(bytes: u64) -> f64 {
    bytes as f64
}

/// Spike test in floating point.
fn is_spike(bytes: u64, ema: f64, factor: f64, min_bytes: u64) -> bool {
    bytes >= min_bytes && bytes_f64(bytes) > ema * factor
}

/// Local/remote split by direction: the local side is the one to investigate.
fn sides(record: &FlowRecord) -> (String, IpAddr, u16) {
    if record.direction == TrafficDirection::Egress {
        (
            local_identity(record, record.src_pod.as_ref(), &record.key.src_ip),
            record.key.dst_ip,
            record.key.dst_port,
        )
    } else {
        (
            local_identity(record, record.dst_pod.as_ref(), &record.key.dst_ip),
            record.key.src_ip,
            record.key.src_port,
        )
    }
}

/// Port scan: many distinct probed ports per remote inside the window.
/// For egress the remote is scanned; for ingress we are scanned.
fn check_scan(
    state: &mut AnalyzerState,
    record: &FlowRecord,
    config: &DetectorConfig,
) -> Option<Alert> {
    let (local, remote_ip, _) = sides(record);
    // Probed port: the remote port for egress scans, the local port for
    // ingress scans (ports probed on us). Both are the flow's destination.
    let probed = record.key.dst_port;
    let key = PairKey {
        local: local.clone(),
        remote: format!("{remote_ip}:{}", record.key.protocol),
    };
    let window_ms = config.scan_window_secs.saturating_mul(1_000);
    let cutoff = record.last_seen_unix_ms.saturating_sub(window_ms);
    let hits = state.port_hits.entry(key.clone()).or_default();
    hits.push_back((probed, record.last_seen_unix_ms));
    while hits.front().is_some_and(|&(_, ts)| ts < cutoff) {
        hits.pop_front();
    }
    let distinct: HashSet<u16> = hits.iter().map(|&(port, _)| port).collect();
    if distinct.len() < config.scan_ports {
        return None;
    }
    // One-shot per window: clear so the next alert needs fresh evidence.
    hits.clear();
    Some(Alert {
        id: format!("scan:{}:{}", key.remote, local),
        severity: Severity::Critical,
        title: format!("Port scan of {local} from {remote_ip}"),
        detail: format!(
            "{} distinct ports in {}s (protocol {})",
            distinct.len(),
            config.scan_window_secs,
            record.key.protocol,
        ),
        first_seen_unix_ms: record.last_seen_unix_ms,
        last_seen_unix_ms: record.last_seen_unix_ms,
        labels: workload_labels(record, record.direction == TrafficDirection::Egress),
        explanation: None,
    })
}

/// Beaconing: suspiciously regular outbound connections (low gap variance).
fn check_beacon(
    state: &mut AnalyzerState,
    record: &FlowRecord,
    config: &DetectorConfig,
) -> Option<Alert> {
    if record.direction != TrafficDirection::Egress {
        return None;
    }
    let local = local_identity(record, record.src_pod.as_ref(), &record.key.src_ip);
    let key = PairKey {
        local: local.clone(),
        remote: format!("{}:{}", record.key.dst_ip, record.key.dst_port),
    };
    let samples = state.beacons.entry(key.clone()).or_default();
    samples.push_back(record.start_unix_ms);
    while samples.len() > 32 {
        samples.pop_front();
    }
    if samples.len() < config.beacon_min_samples {
        return None;
    }
    let (mean_ms, cv) = gap_stats(samples)?;
    if mean_ms < f64::from(config.beacon_min_mean_secs) * 1_000.0 {
        return None;
    }
    if cv >= config.beacon_max_cv {
        return None;
    }
    // One-shot: clear so the next alert needs fresh evidence.
    samples.clear();
    Some(Alert {
        id: format!("beacon:{local}:{}", key.remote),
        severity: Severity::Warning,
        title: format!("Possible beaconing: {local} -> {}", key.remote),
        detail: format!(
            "{} samples, mean gap {:.1}s, variation {cv:.3}",
            config.beacon_min_samples,
            mean_ms / 1_000.0,
        ),
        first_seen_unix_ms: record.last_seen_unix_ms,
        last_seen_unix_ms: record.last_seen_unix_ms,
        labels: workload_labels(record, true),
        explanation: None,
    })
}

/// Mean gap and coefficient of variation (std/mean) of sorted samples.
/// Returns `None` for degenerate input (fewer than 2 gaps or zero mean).
fn gap_stats(samples: &VecDeque<u64>) -> Option<(f64, f64)> {
    if samples.len() < 2 {
        return None;
    }
    let mut gaps = Vec::with_capacity(samples.len() - 1);
    for index in 0..samples.len() - 1 {
        gaps.push(samples[index + 1].saturating_sub(samples[index]));
    }
    coefficient_of_variation(&gaps)
}

#[allow(clippy::cast_precision_loss)]
fn coefficient_of_variation(gaps: &[u64]) -> Option<(f64, f64)> {
    if gaps.is_empty() {
        return None;
    }
    // Millisecond gaps are far below 2^53; the conversion is exact.
    let mean: f64 = gaps.iter().map(|gap| *gap as f64).sum::<f64>() / gaps.len() as f64;
    if mean <= 0.0 {
        return None;
    }
    let variance: f64 = gaps
        .iter()
        .map(|gap| (*gap as f64 - mean).powi(2))
        .sum::<f64>()
        / gaps.len() as f64;
    Some((mean, variance.sqrt() / mean))
}

/// Alert labels for the local side under investigation.
fn workload_labels(record: &FlowRecord, local_is_source: bool) -> HashMap<String, String> {
    let mut labels = HashMap::new();
    let pod = if local_is_source {
        record.src_pod.as_ref()
    } else {
        record.dst_pod.as_ref()
    };
    if let Some(pod) = pod {
        labels.insert("namespace".to_owned(), pod.namespace.clone());
        labels.insert("pod".to_owned(), pod.name.clone());
    }
    labels.insert("node".to_owned(), record.node.clone());
    labels
}

/// Seam for natural-language alert explanations (Phase 5: LLM).
///
/// Detectors stay pure and provider-free; anything that wants to explain an
/// alert implements this trait and is called once per fired alert in
/// [`run_analyzer`]. The future LLM implementation plugs in by implementing
/// this trait and passing it to [`run_analyzer`] from `main` — no detector,
/// store, or webhook changes needed.
pub trait Explainer: Send + Sync {
    /// Stable tag recorded on every stored alert as `explainer=<name>`.
    fn name(&self) -> &'static str;
    /// Explain `alert` in the context of the batch's `flows`. Returning
    /// `None` means "no explanation" (transient failure or stub); the store
    /// keeps any previously stored explanation in that case.
    async fn explanation_for(&self, alert: &Alert, flows: &[FlowRecord]) -> Option<String>;
}

/// Default [`Explainer`]: produces no explanations. Every stored alert is
/// still tagged `explainer=none` so a future rollout can tell stub-era
/// alerts apart from LLM-explained ones.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoopExplainer;

impl Explainer for NoopExplainer {
    fn name(&self) -> &'static str {
        "none"
    }

    // `async` is load-bearing at the trait level (future LLM impls will
    // await); the stub just has nothing to await yet.
    #[allow(clippy::unused_async_trait_impl)]
    async fn explanation_for(&self, _alert: &Alert, _flows: &[FlowRecord]) -> Option<String> {
        None
    }
}

/// Stamp the explainer label and fill `explanation` from the explainer. This
/// is the seam's call site: [`run_analyzer`] invokes it for every fired
/// alert before upsert, so swapping the explainer changes what (if anything)
/// lands in [`Alert::explanation`](mist_types::Alert::explanation).
pub async fn enrich_alert(explainer: &impl Explainer, alert: &mut Alert, flows: &[FlowRecord]) {
    alert
        .labels
        .insert("explainer".to_owned(), explainer.name().to_owned());
    alert.explanation = explainer.explanation_for(alert, flows).await;
}

/// Wires for [`run_analyzer`]: channels, storage, webhook, config, metrics.
pub struct AnalyzerDeps {
    /// Ingest batches from `/api/ingest`.
    pub rx: mpsc::Receiver<FlowBatch>,
    /// Flow + alert storage.
    pub store: Store,
    /// Live-event fan-out to websocket connections.
    pub alerts_tx: broadcast::Sender<AlertEvent>,
    /// HTTP client for the operator mirror webhook.
    pub http: reqwest::Client,
    /// Operator webhook URL; `None` disables `AnomalyAlert` mirroring.
    pub webhook_url: Option<String>,
    /// Detector thresholds.
    pub config: DetectorConfig,
    /// Process counters served by `/metrics`.
    pub metrics: std::sync::Arc<crate::metrics::Metrics>,
}

/// Background analyzer task: persist flows, score batches, store + broadcast
/// alerts, and mirror them to the operator webhook (best-effort).
pub async fn run_analyzer(deps: AnalyzerDeps, explainer: impl Explainer) {
    let AnalyzerDeps {
        mut rx,
        store,
        alerts_tx,
        http,
        webhook_url,
        config,
        metrics,
    } = deps;
    let mut state = AnalyzerState::default();
    while let Some(batch) = rx.recv().await {
        match store.save_flows(&batch.flows).await {
            Ok(()) => metrics.batch_persisted(batch.flows.len()),
            Err(error) => {
                tracing::warn!(?error, "flow persistence failed");
                metrics.persistence_failed();
            }
        }
        if !batch.flows.is_empty() {
            let _ = alerts_tx.send(AlertEvent::Flows {
                flows: batch.flows.clone(),
            });
        }
        for mut alert in process_batch(&mut state, &batch, &config) {
            enrich_alert(&explainer, &mut alert, &batch.flows).await;
            match store.upsert_alert(&alert).await {
                Ok(view) => {
                    metrics.alert_fired();
                    let _ = alerts_tx.send(AlertEvent::Alert {
                        alert: view.clone(),
                    });
                    if let Some(url) = &webhook_url
                        && let Err(error) = http.post(url).json(&alert).send().await
                    {
                        tracing::warn!(?error, url = %url, "operator webhook call failed");
                        metrics.webhook_failed();
                    }
                    tracing::info!(id = %view.alert.id, severity = ?view.alert.severity, "alert upserted");
                }
                Err(error) => tracing::warn!(?error, id = %alert.id, "alert persistence failed"),
            }
        }
    }
    tracing::warn!("analyzer channel closed; shutting down");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        direction: TrafficDirection,
        dst: &str,
        dport: u16,
        bytes: u64,
        ts: u64,
    ) -> FlowRecord {
        FlowRecord {
            key: mist_types::FlowKey {
                src_ip: "10.0.1.4".parse().unwrap(),
                src_port: 51234,
                dst_ip: dst.parse().unwrap(),
                dst_port: dport,
                protocol: 6,
            },
            direction,
            bytes,
            packets: 10,
            start_unix_ms: ts,
            last_seen_unix_ms: ts,
            node: "node-1".to_owned(),
            src_pod: Some(mist_types::PodRef {
                namespace: "prod".to_owned(),
                name: "api-0".to_owned(),
            }),
            dst_pod: None,
        }
    }

    fn batch(records: Vec<FlowRecord>) -> FlowBatch {
        FlowBatch {
            node: "node-1".to_owned(),
            flows: records,
        }
    }

    struct FixedExplainer(Option<String>);

    impl Explainer for FixedExplainer {
        fn name(&self) -> &'static str {
            "fixed-test"
        }

        #[allow(clippy::unused_async_trait_impl)]
        async fn explanation_for(&self, _alert: &Alert, _flows: &[FlowRecord]) -> Option<String> {
            self.0.clone()
        }
    }

    fn explained_alert() -> Alert {
        let mut state = AnalyzerState::default();
        let alerts = process_batch(
            &mut state,
            &batch(vec![record(
                TrafficDirection::Egress,
                "8.8.8.8",
                443,
                100,
                2000,
            )]),
            &DetectorConfig::default(),
        );
        alerts
            .into_iter()
            .find(|alert| alert.id.starts_with("new-endpoint"))
            .unwrap()
    }

    #[tokio::test]
    async fn noop_explainer_leaves_explanation_empty_but_tags_label() {
        let explainer = NoopExplainer;
        assert_eq!(explainer.name(), "none");
        let mut alert = explained_alert();
        let flows: Vec<FlowRecord> = Vec::new();
        assert_eq!(explainer.explanation_for(&alert, &flows).await, None);
        enrich_alert(&explainer, &mut alert, &flows).await;
        assert_eq!(alert.explanation, None);
        assert_eq!(
            alert.labels.get("explainer").map(String::as_str),
            Some("none")
        );
        // Pre-existing labels survive the stamping.
        assert_eq!(alert.labels.get("node").map(String::as_str), Some("node-1"));
    }

    #[tokio::test]
    async fn explainer_output_flows_into_alert_and_label() {
        let explainer = FixedExplainer(Some("likely backup traffic".to_owned()));
        let mut alert = explained_alert();
        let flows: Vec<FlowRecord> = Vec::new();
        enrich_alert(&explainer, &mut alert, &flows).await;
        assert_eq!(alert.explanation.as_deref(), Some("likely backup traffic"));
        assert_eq!(
            alert.labels.get("explainer").map(String::as_str),
            Some("fixed-test")
        );
    }

    #[test]
    fn cidr_matching() {
        assert_eq!(parse_cidr("10.244.0.0/16"), Some((0x0A_F4_00_00, 16)));
        assert_eq!(parse_cidr("nope"), None);
        assert_eq!(parse_cidr("10.0.0.0/33"), None);
        let cidrs = vec![parse_cidr("10.0.0.0/8").unwrap()];
        assert!(is_internal(&"10.1.2.3".parse().unwrap(), &cidrs));
        assert!(!is_internal(&"8.8.8.8".parse().unwrap(), &cidrs));
    }

    #[test]
    fn fires_on_first_external_egress_only() {
        let config = DetectorConfig::default();
        let mut state = AnalyzerState::default();
        // Internal egress: silent.
        let internal = process_batch(
            &mut state,
            &batch(vec![record(
                TrafficDirection::Egress,
                "10.0.9.9",
                443,
                100,
                1000,
            )]),
            &config,
        );
        assert!(
            internal
                .iter()
                .all(|alert| !alert.id.starts_with("new-endpoint"))
        );
        // First external egress: fires.
        let external = process_batch(
            &mut state,
            &batch(vec![record(
                TrafficDirection::Egress,
                "8.8.8.8",
                443,
                100,
                2000,
            )]),
            &config,
        );
        assert!(
            external
                .iter()
                .any(|alert| alert.id.starts_with("new-endpoint"))
        );
        // Repeat: silent (known endpoint).
        let repeat = process_batch(
            &mut state,
            &batch(vec![record(
                TrafficDirection::Egress,
                "8.8.8.8",
                443,
                100,
                3000,
            )]),
            &config,
        );
        assert!(
            repeat
                .iter()
                .all(|alert| !alert.id.starts_with("new-endpoint"))
        );
        // Ingress from external: silent (inbound clients are normal).
        let ingress = process_batch(
            &mut state,
            &batch(vec![record(
                TrafficDirection::Ingress,
                "1.2.3.4",
                443,
                100,
                4000,
            )]),
            &config,
        );
        assert!(
            ingress
                .iter()
                .all(|alert| !alert.id.starts_with("new-endpoint"))
        );
    }

    #[test]
    fn spike_needs_warmup_and_magnitude() {
        let config = DetectorConfig {
            spike_min_bytes: 1_000,
            ..DetectorConfig::default()
        };
        let mut state = AnalyzerState::default();
        // Warm up with 100-byte intervals.
        for ts in [1000, 2000, 3000, 4000] {
            let alerts = process_batch(
                &mut state,
                &batch(vec![record(
                    TrafficDirection::Egress,
                    "10.0.9.9",
                    443,
                    100,
                    ts,
                )]),
                &config,
            );
            assert!(alerts.iter().all(|alert| !alert.id.starts_with("spike")));
        }
        // 10x over baseline: fires.
        let alerts = process_batch(
            &mut state,
            &batch(vec![record(
                TrafficDirection::Egress,
                "10.0.9.9",
                443,
                10_000,
                5000,
            )]),
            &config,
        );
        assert!(alerts.iter().any(|alert| alert.id.starts_with("spike")));
    }

    #[test]
    fn scan_fires_on_many_ports_then_resets() {
        let config = DetectorConfig {
            scan_ports: 5,
            ..DetectorConfig::default()
        };
        let mut state = AnalyzerState::default();
        for (index, port) in (1u16..=4).enumerate() {
            let alerts = process_batch(
                &mut state,
                &batch(vec![record(
                    TrafficDirection::Ingress,
                    "10.0.9.9",
                    port,
                    60,
                    1000 + index as u64 * 1000,
                )]),
                &config,
            );
            assert!(alerts.iter().all(|alert| !alert.id.starts_with("scan")));
        }
        let alerts = process_batch(
            &mut state,
            &batch(vec![record(
                TrafficDirection::Ingress,
                "10.0.9.9",
                5,
                60,
                5000,
            )]),
            &config,
        );
        assert!(alerts.iter().any(|alert| alert.id.starts_with("scan")));
        // One-shot: needs fresh evidence after firing.
        let quiet = process_batch(
            &mut state,
            &batch(vec![record(
                TrafficDirection::Ingress,
                "10.0.9.9",
                6,
                60,
                6000,
            )]),
            &config,
        );
        assert!(quiet.iter().all(|alert| !alert.id.starts_with("scan")));
    }

    #[test]
    fn beacon_fires_on_regular_intervals() {
        let config = DetectorConfig {
            beacon_min_samples: 5,
            beacon_min_mean_secs: 1,
            ..DetectorConfig::default()
        };
        let mut state = AnalyzerState::default();
        // Exactly 10s apart: perfectly regular.
        for index in 0..4 {
            let alerts = process_batch(
                &mut state,
                &batch(vec![record(
                    TrafficDirection::Egress,
                    "8.8.8.8",
                    443,
                    100,
                    10_000 * index,
                )]),
                &config,
            );
            assert!(alerts.iter().all(|alert| !alert.id.starts_with("beacon")));
        }
        let alerts = process_batch(
            &mut state,
            &batch(vec![record(
                TrafficDirection::Egress,
                "8.8.8.8",
                443,
                100,
                40_000,
            )]),
            &config,
        );
        assert!(alerts.iter().any(|alert| alert.id.starts_with("beacon")));
    }

    #[test]
    fn beacon_ignores_irregular_and_tight_loops() {
        let config = DetectorConfig {
            beacon_min_samples: 5,
            beacon_min_mean_secs: 1,
            ..DetectorConfig::default()
        };
        let mut state = AnalyzerState::default();
        // Irregular gaps: silent.
        for ts in [0, 1_000, 50_000, 51_000, 200_000] {
            let alerts = process_batch(
                &mut state,
                &batch(vec![record(
                    TrafficDirection::Egress,
                    "8.8.8.8",
                    443,
                    100,
                    ts,
                )]),
                &config,
            );
            assert!(alerts.iter().all(|alert| !alert.id.starts_with("beacon")));
        }
        // Tight regular loop (100ms mean): silent (below min mean).
        let mut state = AnalyzerState::default();
        for index in 0..6 {
            let alerts = process_batch(
                &mut state,
                &batch(vec![record(
                    TrafficDirection::Egress,
                    "8.8.8.8",
                    443,
                    100,
                    100 * index,
                )]),
                &config,
            );
            assert!(alerts.iter().all(|alert| !alert.id.starts_with("beacon")));
        }
    }

    #[test]
    fn gap_stats_handles_edges() {
        assert!(gap_stats(&VecDeque::from([100])).is_none());
        assert!(gap_stats(&VecDeque::from([100, 100])).is_none()); // zero mean
        let (mean, cv) = gap_stats(&VecDeque::from([0, 10_000, 20_000, 30_000])).unwrap();
        assert!((mean - 10_000.0).abs() < f64::EPSILON);
        assert!(cv < 0.001);
    }
}
