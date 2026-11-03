//! Shared protocol types for mist: flow records, alerts, and ingest envelopes.

use std::{collections::HashMap, net::IpAddr};

use serde::{Deserialize, Serialize};

/// 5-tuple identifying one direction of a transport flow.
///
/// `protocol` is the IP protocol number (`IPPROTO_*`, e.g. 6 = TCP, 17 = UDP).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Reference to a Kubernetes pod an endpoint was attributed to.
///
/// `labels` is the pod's metadata labels at attribution time; it defaults
/// to empty so records from older agents keep parsing. (No `Hash`: label
/// maps are unhashable, and nothing keys on pods.)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodRef {
    pub namespace: String,
    pub name: String,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

/// Capture direction of a flow record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrafficDirection {
    Ingress,
    Egress,
}

/// Aggregated counters for one flow over an observation window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub direction: TrafficDirection,
    pub bytes: u64,
    pub packets: u64,
    /// First observation, unix millis.
    pub start_unix_ms: u64,
    /// Most recent observation, unix millis.
    pub last_seen_unix_ms: u64,
    /// Node the reporting agent runs on.
    pub node: String,
    pub src_pod: Option<PodRef>,
    pub dst_pod: Option<PodRef>,
}

/// Alert severity, ascending.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// An anomaly produced by the analyzer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Alert {
    /// Stable id for dedupe, e.g. `scan:10.0.1.4`.
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub labels: HashMap<String, String>,
    /// Optional natural-language explanation (Phase 5). Defaults to `None`
    /// so payloads from older analyzers that omit the key keep parsing.
    #[serde(default)]
    pub explanation: Option<String>,
}

/// Batch envelope agents POST to `POST /api/ingest`.
///
/// The eBPF counters are cumulative per-agent values read from the `STATS`
/// map; they default to zero so batches from older agents keep parsing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowBatch {
    pub node: String,
    pub flows: Vec<FlowRecord>,
    /// Packets for which a flow entry was created or updated.
    #[serde(default)]
    pub updated: u64,
    /// Packets skipped (non-IPv4/IPv6 or unsupported L4).
    #[serde(default)]
    pub skipped: u64,
    /// Packets dropped because the flow map was full.
    #[serde(default)]
    pub map_full: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key() -> FlowKey {
        FlowKey {
            src_ip: "10.0.1.4".parse().unwrap(),
            src_port: 443,
            dst_ip: "10.0.2.9".parse().unwrap(),
            dst_port: 51234,
            protocol: 6,
        }
    }

    #[test]
    fn flow_record_serde_roundtrip() {
        let record = FlowRecord {
            key: sample_key(),
            direction: TrafficDirection::Egress,
            bytes: 1024,
            packets: 12,
            start_unix_ms: 1_700_000_000_000,
            last_seen_unix_ms: 1_700_000_060_000,
            node: "node-1".to_owned(),
            src_pod: Some(PodRef {
                namespace: "prod".to_owned(),
                name: "api-0".to_owned(),
                labels: HashMap::from([("app".to_owned(), "api".to_owned())]),
            }),
            dst_pod: None,
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: FlowRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
        // Records from older agents omit pod labels entirely.
        let legacy: FlowRecord = serde_json::from_str(
            r#"{"key":{"src_ip":"10.0.1.4","src_port":443,"dst_ip":"10.0.2.9",
                "dst_port":51234,"protocol":6},"direction":"egress","bytes":64,
                "packets":1,"start_unix_ms":10,"last_seen_unix_ms":10,
                "node":"node-1","src_pod":{"namespace":"prod","name":"api-0"},
                "dst_pod":null}"#,
        )
        .unwrap();
        assert_eq!(legacy.src_pod.unwrap().labels, HashMap::new());
    }

    #[test]
    fn severity_serializes_lowercase() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"critical\""
        );
    }

    #[test]
    fn alert_without_explanation_key_defaults_to_none() {
        let alert: Alert = serde_json::from_str(
            r#"{
                "id": "scan:10.0.1.4",
                "severity": "warning",
                "title": "scan",
                "detail": "detail",
                "first_seen_unix_ms": 1700000000000,
                "last_seen_unix_ms": 1700000060000,
                "labels": {}
            }"#,
        )
        .unwrap();
        assert_eq!(alert.explanation, None);
        let nulled: Alert = serde_json::from_str(
            r#"{
                "id": "scan:10.0.1.4",
                "severity": "warning",
                "title": "scan",
                "detail": "detail",
                "first_seen_unix_ms": 1700000000000,
                "last_seen_unix_ms": 1700000060000,
                "labels": {},
                "explanation": null
            }"#,
        )
        .unwrap();
        assert_eq!(nulled.explanation, None);
    }

    #[test]
    fn flow_batch_serde_roundtrip() {
        let batch = FlowBatch {
            node: "node-1".to_owned(),
            updated: 7,
            skipped: 1,
            map_full: 0,
            flows: vec![FlowRecord {
                key: sample_key(),
                direction: TrafficDirection::Ingress,
                bytes: 64,
                packets: 1,
                start_unix_ms: 10,
                last_seen_unix_ms: 10,
                node: "node-1".to_owned(),
                src_pod: None,
                dst_pod: None,
            }],
        };
        let json = serde_json::to_string(&batch).unwrap();
        let back: FlowBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(batch, back);
        // Payloads from older agents omit the counters entirely.
        let legacy: FlowBatch = serde_json::from_str(r#"{"node":"n","flows":[]}"#).unwrap();
        assert_eq!((legacy.updated, legacy.skipped, legacy.map_full), (0, 0, 0));
    }
}
