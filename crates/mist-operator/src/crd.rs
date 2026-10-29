//! mist custom resources: `TrafficMonitor` (sensor config) and `AnomalyAlert`
//! (analyzer findings mirrored into the cluster).

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

fn default_sample_interval_secs() -> u64 {
    5
}

fn default_agent_image() -> String {
    "mist-agent:dev".to_owned()
}

fn default_api_url() -> String {
    "http://mist-api.mist.svc.cluster.local:3000".to_owned()
}

fn default_object_path() -> String {
    "/etc/mist/mist-ebpf.o".to_owned()
}

/// Desired state of mist traffic monitoring. The operator renders the agent
/// `DaemonSet` from the oldest instance in its namespace; any additional
/// instances are marked `Superseded` in status.
#[derive(CustomResource, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[kube(
    group = "mist.io",
    version = "v1",
    kind = "TrafficMonitor",
    namespaced,
    status = "TrafficMonitorStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct TrafficMonitorSpec {
    /// Namespaces to monitor; empty means all. Recorded for the agent
    /// (agent-side filtering lands with the analyzer).
    #[serde(default)]
    pub watched_namespaces: Vec<String>,
    /// Agent drain interval in seconds.
    #[serde(default = "default_sample_interval_secs")]
    pub sample_interval_secs: u64,
    /// Agent container image.
    #[serde(default = "default_agent_image")]
    pub agent_image: String,
    /// `DaemonSet` node selector; empty schedules on all nodes.
    #[serde(default)]
    pub node_selector: BTreeMap<String, String>,
    /// Base URL agents ship flow batches to.
    #[serde(default = "default_api_url")]
    pub api_url: String,
    /// eBPF object path inside the agent image.
    #[serde(default = "default_object_path")]
    pub object_path: String,
    /// Name of a Secret holding the agent ingest token (key
    /// `ingest-token`, same Secret/key the API reads `INGEST_TOKEN` from).
    /// When set, the agent container gets `MIST_API_TOKEN` from it and
    /// authenticates `POST /api/ingest`; when unset, agents send no token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_token_secret_name: Option<String>,
}

impl Default for TrafficMonitorSpec {
    fn default() -> Self {
        Self {
            watched_namespaces: Vec::new(),
            sample_interval_secs: default_sample_interval_secs(),
            agent_image: default_agent_image(),
            node_selector: BTreeMap::new(),
            api_url: default_api_url(),
            object_path: default_object_path(),
            api_token_secret_name: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
pub enum MonitorState {
    #[default]
    Pending,
    Ready,
    Superseded,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TrafficMonitorStatus {
    pub state: MonitorState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// An analyzer finding mirrored into the cluster. Created and updated by the
/// operator's alert webhook; deduplicated by [`AnomalyAlertSpec::alert_id`].
#[derive(CustomResource, Clone, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[kube(
    group = "mist.io",
    version = "v1",
    kind = "AnomalyAlert",
    namespaced,
    status = "AnomalyAlertStatus"
)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyAlertSpec {
    /// Stable dedupe id from the analyzer (e.g. `scan:10.0.1.4`).
    pub alert_id: String,
    pub severity: AlertSeverity,
    pub title: String,
    pub detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub explanation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_name: Option<String>,
    /// Analyzer attributes (detector name, protocol, ...).
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
pub enum AlertState {
    #[default]
    Firing,
    Resolved,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AnomalyAlertStatus {
    pub state: AlertState,
    pub first_seen_unix_ms: i64,
    pub last_seen_unix_ms: i64,
    pub occurrences: i64,
}

#[cfg(test)]
mod tests {
    use kube::CustomResourceExt as _;

    use super::*;

    #[test]
    fn spec_defaults_apply_to_empty_object() {
        let spec: TrafficMonitorSpec = serde_json::from_str("{}").unwrap();
        assert_eq!(spec, TrafficMonitorSpec::default());
        assert_eq!(spec.sample_interval_secs, 5);
        assert_eq!(spec.agent_image, "mist-agent:dev");
    }

    #[test]
    fn spec_uses_camel_case() {
        let spec = TrafficMonitorSpec {
            watched_namespaces: vec!["prod".to_owned()],
            ..TrafficMonitorSpec::default()
        };
        let json = serde_json::to_value(&spec).unwrap();
        assert_eq!(json["watchedNamespaces"], serde_json::json!(["prod"]));
        assert_eq!(json["sampleIntervalSecs"], serde_json::json!(5));
    }

    #[test]
    fn crds_generate_with_expected_names() {
        let monitor = TrafficMonitor::crd();
        assert_eq!(
            monitor.metadata.name.as_deref(),
            Some("trafficmonitors.mist.io")
        );
        let alert = AnomalyAlert::crd();
        assert_eq!(
            alert.metadata.name.as_deref(),
            Some("anomalyalerts.mist.io")
        );
        // Both schemas carry their spec properties.
        for crd in [&monitor, &alert] {
            let schema = serde_json::to_value(&crd.spec.versions[0].schema).unwrap();
            assert!(schema["openAPIV3Schema"]["properties"]["spec"].is_object());
            assert!(schema["openAPIV3Schema"]["properties"]["status"].is_object());
        }
    }
}
