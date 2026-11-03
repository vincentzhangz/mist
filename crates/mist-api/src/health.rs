//! Agent heartbeats and the system health overview payload.
//!
//! Every `POST /api/ingest` batch — including empty ones, which idle agents
//! ship as heartbeats — updates the per-node record below. Heartbeat
//! recording is infallible: lock poisoning degrades to a stale row, never a
//! failed batch.

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

use mist_types::FlowBatch;
use serde::Serialize;

/// Seconds without a batch after which a node reads stale. Agents ship every
/// 5s by default, so this tolerates several missed beats before flagging.
pub const STALE_AFTER_SECS: u64 = 30;

/// Per-node heartbeat accumulated from ingest batches.
#[derive(Debug, Clone)]
struct NodeHeartbeat {
    last_seen_ms: u64,
    batches_total: u64,
    flows_total: u64,
    updated: u64,
    skipped: u64,
    map_full: u64,
}

/// Thread-safe heartbeat tracker held in `AppStateInner`.
#[derive(Debug, Default)]
pub struct HeartbeatTracker {
    nodes: RwLock<HashMap<String, NodeHeartbeat>>,
}

impl HeartbeatTracker {
    /// Empty tracker with no known agents.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fold one ingest batch into its node's heartbeat record.
    pub fn record(&self, batch: &FlowBatch) {
        self.record_at(batch, unix_ms_now());
    }

    /// Snapshot all known agents, sorted by node name.
    #[must_use]
    pub fn snapshot(&self) -> Vec<NodeHealth> {
        self.snapshot_at(unix_ms_now())
    }

    fn record_at(&self, batch: &FlowBatch, now_ms: u64) {
        let mut nodes = self
            .nodes
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = nodes.entry(batch.node.clone()).or_insert(NodeHeartbeat {
            last_seen_ms: now_ms,
            batches_total: 0,
            flows_total: 0,
            updated: 0,
            skipped: 0,
            map_full: 0,
        });
        entry.last_seen_ms = now_ms;
        entry.batches_total = entry.batches_total.saturating_add(1);
        entry.flows_total = entry
            .flows_total
            .saturating_add(u64::try_from(batch.flows.len()).unwrap_or(u64::MAX));
        // eBPF counters are cumulative per agent: the latest wins.
        entry.updated = batch.updated;
        entry.skipped = batch.skipped;
        entry.map_full = batch.map_full;
    }

    fn snapshot_at(&self, now_ms: u64) -> Vec<NodeHealth> {
        let nodes = self
            .nodes
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut rows: Vec<NodeHealth> = nodes
            .iter()
            .map(|(node, beat)| {
                let age_secs = now_ms.saturating_sub(beat.last_seen_ms) / 1000;
                NodeHealth {
                    node: node.clone(),
                    last_seen_ms: beat.last_seen_ms,
                    age_secs,
                    stale: age_secs > STALE_AFTER_SECS,
                    batches_total: beat.batches_total,
                    flows_total: beat.flows_total,
                    updated: beat.updated,
                    skipped: beat.skipped,
                    map_full: beat.map_full,
                }
            })
            .collect();
        rows.sort_by(|a, b| a.node.cmp(&b.node));
        rows
    }
}

/// One agent row in the health overview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NodeHealth {
    /// Kubernetes node name shipping the batches.
    pub node: String,
    /// Unix millis of the last batch from this node.
    pub last_seen_ms: u64,
    /// Whole seconds since `last_seen_ms` at snapshot time.
    pub age_secs: u64,
    /// True when no batch arrived within [`STALE_AFTER_SECS`].
    pub stale: bool,
    /// Batches recorded from this node since API startup (in-memory).
    pub batches_total: u64,
    /// Flow records shipped in those batches.
    pub flows_total: u64,
    /// Latest cumulative eBPF `updated` counter from this agent.
    pub updated: u64,
    /// Latest cumulative eBPF `skipped` counter from this agent.
    pub skipped: u64,
    /// Latest cumulative eBPF `map_full` counter from this agent.
    pub map_full: u64,
}

/// Analyzer queue pressure in the overview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct QueueStatus {
    /// Batches waiting for analysis.
    pub depth: usize,
    /// Channel buffer size.
    pub capacity: usize,
}

/// `GET /api/health/overview` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HealthOverview {
    /// Seconds since API process start.
    pub uptime_secs: u64,
    /// Storage backend: `"postgres"` or `"memory"`.
    pub storage: &'static str,
    /// Analyzer input queue pressure.
    pub analyzer_queue: QueueStatus,
    /// Live `/api/ws` subscribers.
    pub ws_subscribers: usize,
    /// Per-agent heartbeats, sorted by node.
    pub agents: Vec<NodeHealth>,
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| u64::try_from(elapsed.as_millis()).ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(node: &str, flows: usize, updated: u64) -> FlowBatch {
        FlowBatch {
            node: node.to_owned(),
            flows: vec![
                mist_types::FlowRecord {
                    key: mist_types::FlowKey {
                        src_ip: "10.0.0.1".parse().unwrap(),
                        src_port: 1,
                        dst_ip: "10.0.0.2".parse().unwrap(),
                        dst_port: 2,
                        protocol: 6,
                    },
                    direction: mist_types::TrafficDirection::Egress,
                    bytes: 0,
                    packets: 0,
                    start_unix_ms: 0,
                    last_seen_unix_ms: 0,
                    node: node.to_owned(),
                    src_pod: None,
                    dst_pod: None,
                };
                flows
            ],
            updated,
            skipped: 0,
            map_full: 0,
        }
    }

    #[test]
    fn record_then_snapshot_reports_live_node() {
        let tracker = HeartbeatTracker::new();
        tracker.record_at(&batch("node-a", 3, 42), 1_000);
        let rows = tracker.snapshot_at(6_000);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.node, "node-a");
        assert_eq!(row.last_seen_ms, 1_000);
        assert_eq!(row.age_secs, 5);
        assert!(!row.stale);
        assert_eq!(row.batches_total, 1);
        assert_eq!(row.flows_total, 3);
        assert_eq!(row.updated, 42);
    }

    #[test]
    fn re_record_accumulates_totals_but_replaces_counters() {
        let tracker = HeartbeatTracker::new();
        tracker.record_at(&batch("node-a", 3, 42), 1_000);
        tracker.record_at(&batch("node-a", 2, 99), 2_000);
        let rows = tracker.snapshot_at(2_000);
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.batches_total, 2);
        assert_eq!(row.flows_total, 5);
        assert_eq!(row.updated, 99);
        assert_eq!(row.last_seen_ms, 2_000);
    }

    #[test]
    fn quiet_node_reads_stale_past_threshold() {
        let tracker = HeartbeatTracker::new();
        tracker.record_at(&batch("node-a", 0, 0), 1_000);
        let live = tracker.snapshot_at(1_000 + STALE_AFTER_SECS * 1000);
        assert!(!live[0].stale);
        let stale = tracker.snapshot_at(1_000 + (STALE_AFTER_SECS + 1) * 1000);
        assert!(stale[0].stale);
        assert_eq!(stale[0].age_secs, STALE_AFTER_SECS + 1);
    }

    #[test]
    fn snapshot_sorts_by_node() {
        let tracker = HeartbeatTracker::new();
        tracker.record_at(&batch("node-b", 0, 0), 1_000);
        tracker.record_at(&batch("node-a", 0, 0), 1_000);
        let rows = tracker.snapshot_at(1_000);
        assert_eq!(
            rows.iter().map(|row| &row.node).collect::<Vec<_>>(),
            vec!["node-a", "node-b"]
        );
    }

    #[test]
    fn empty_tracker_snapshots_to_no_rows() {
        assert_eq!(HeartbeatTracker::new().snapshot_at(1_000).len(), 0);
    }
}
