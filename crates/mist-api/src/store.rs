//! Flow and alert storage: Postgres for production, in-memory for tests
//! and DB-less development. Selected by `Store` at startup.

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use mist_types::{Alert, FlowRecord, PodRef, Severity, TrafficDirection};
use serde::{Deserialize, Serialize};

/// Alert lifecycle state (storage-level; the wire `Alert` carries no state).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertLifecycle {
    Firing,
    Resolved,
}

impl AlertLifecycle {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "firing" => Some(Self::Firing),
            "resolved" => Some(Self::Resolved),
            _ => None,
        }
    }
}

/// An alert plus its lifecycle. This is what the REST API returns.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AlertView {
    #[serde(flatten)]
    pub alert: Alert,
    pub state: AlertLifecycle,
    pub occurrences: u64,
}

/// Filters for flow history queries. All fields optional except the limit.
#[derive(Clone, Debug, Default)]
pub struct FlowFilter {
    pub node: Option<String>,
    pub namespace: Option<String>,
    pub pod: Option<String>,
    pub since_ms: Option<u64>,
    pub limit: i64,
}

#[derive(Clone)]
pub enum Store {
    Postgres(PgStore),
    Memory(MemStore),
}

impl Store {
    pub async fn save_flows(&self, flows: &[FlowRecord]) -> anyhow::Result<()> {
        match self {
            Self::Postgres(store) => store.save_flows(flows).await,
            Self::Memory(store) => store.save_flows(flows),
        }
    }

    pub async fn upsert_alert(&self, alert: &Alert) -> anyhow::Result<AlertView> {
        match self {
            Self::Postgres(store) => store.upsert_alert(alert).await,
            Self::Memory(store) => store.upsert_alert(alert),
        }
    }

    pub async fn resolve_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        match self {
            Self::Postgres(store) => store.resolve_alert(id).await,
            Self::Memory(store) => store.resolve_alert(id),
        }
    }

    pub async fn list_flows(&self, filter: &FlowFilter) -> anyhow::Result<Vec<FlowRecord>> {
        match self {
            Self::Postgres(store) => store.list_flows(filter).await,
            Self::Memory(store) => store.list_flows(filter),
        }
    }

    pub async fn list_alerts(&self, state: Option<&str>) -> anyhow::Result<Vec<AlertView>> {
        match self {
            Self::Postgres(store) => store.list_alerts(state).await,
            Self::Memory(store) => store.list_alerts(state),
        }
    }

    pub async fn get_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        match self {
            Self::Postgres(store) => store.get_alert(id).await,
            Self::Memory(store) => store.get_alert(id),
        }
    }

    /// Live storage gauges for the `/metrics` scrape.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub async fn counts(&self) -> anyhow::Result<crate::metrics::StoreCounts> {
        match self {
            Self::Postgres(store) => store.counts().await,
            Self::Memory(store) => store.counts(),
        }
    }

    /// Insert or replace the password hash for `email`.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub async fn upsert_user(&self, email: &str, password_hash: &str) -> anyhow::Result<()> {
        match self {
            Self::Postgres(store) => store.upsert_user(email, password_hash).await,
            Self::Memory(store) => store.upsert_user(email, password_hash),
        }
    }

    /// Fetch the stored password hash for `email`, if the user exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the storage backend fails.
    pub async fn get_password_hash(&self, email: &str) -> anyhow::Result<Option<String>> {
        match self {
            Self::Postgres(store) => store.get_password_hash(email).await,
            Self::Memory(store) => store.get_password_hash(email),
        }
    }
}

#[derive(Clone)]
pub struct PgStore {
    pool: sqlx::PgPool,
}

impl PgStore {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    pub async fn migrate(pool: &sqlx::PgPool) -> anyhow::Result<()> {
        sqlx::migrate!("./migrations").run(pool).await?;
        Ok(())
    }

    async fn save_flows(&self, flows: &[FlowRecord]) -> anyhow::Result<()> {
        for flow in flows {
            sqlx::query(
                "INSERT INTO flows (node, src_ip, src_port, dst_ip, dst_port, protocol, \
                 direction, bytes, packets, start_ms, last_seen_ms, \
                 src_namespace, src_pod, dst_namespace, dst_pod) \
                 VALUES ($1, $2::INET, $3, $4::INET, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
            )
            .bind(&flow.node)
            .bind(flow.key.src_ip.to_string())
            .bind(i32::from(flow.key.src_port))
            .bind(flow.key.dst_ip.to_string())
            .bind(i32::from(flow.key.dst_port))
            .bind(i16::from(flow.key.protocol))
            .bind(direction_str(flow.direction))
            .bind(i64::try_from(flow.bytes).unwrap_or(i64::MAX))
            .bind(i64::try_from(flow.packets).unwrap_or(i64::MAX))
            .bind(i64::try_from(flow.start_unix_ms).unwrap_or(i64::MAX))
            .bind(i64::try_from(flow.last_seen_unix_ms).unwrap_or(i64::MAX))
            .bind(flow.src_pod.as_ref().map(|pod| pod.namespace.as_str()))
            .bind(flow.src_pod.as_ref().map(|pod| pod.name.as_str()))
            .bind(flow.dst_pod.as_ref().map(|pod| pod.namespace.as_str()))
            .bind(flow.dst_pod.as_ref().map(|pod| pod.name.as_str()))
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn upsert_alert(&self, alert: &Alert) -> anyhow::Result<AlertView> {
        // `COALESCE` keeps the stored explanation when a re-fire carries
        // none (e.g. the stub explainer), and refreshes it when the re-fire
        // carries one. Resolve only flips `state`, so it never wipes it.
        let row: AlertRow = sqlx::query_as(
            "INSERT INTO alerts (id, severity, title, detail, first_seen_ms, last_seen_ms, \
             labels, explanation, state, occurrences) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'firing', 1) \
             ON CONFLICT (id) DO UPDATE SET \
               severity = EXCLUDED.severity, \
               title = EXCLUDED.title, \
               detail = EXCLUDED.detail, \
               first_seen_ms = LEAST(alerts.first_seen_ms, EXCLUDED.first_seen_ms), \
               last_seen_ms = GREATEST(alerts.last_seen_ms, EXCLUDED.last_seen_ms), \
               labels = EXCLUDED.labels, \
               explanation = COALESCE(EXCLUDED.explanation, alerts.explanation), \
               state = 'firing', \
               occurrences = alerts.occurrences + 1, \
               updated_at = now() \
             RETURNING id, severity, title, detail, first_seen_ms, last_seen_ms, \
               labels, explanation, state, occurrences",
        )
        .bind(&alert.id)
        .bind(severity_str(alert.severity))
        .bind(&alert.title)
        .bind(&alert.detail)
        .bind(i64::try_from(alert.first_seen_unix_ms).unwrap_or(i64::MAX))
        .bind(i64::try_from(alert.last_seen_unix_ms).unwrap_or(i64::MAX))
        .bind(sqlx::types::Json(&alert.labels))
        .bind(alert.explanation.as_deref())
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into_view())
    }

    async fn resolve_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        let row: Option<AlertRow> = sqlx::query_as(
            "UPDATE alerts SET state = 'resolved', updated_at = now() WHERE id = $1 \
             RETURNING id, severity, title, detail, first_seen_ms, last_seen_ms, \
               labels, explanation, state, occurrences",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(AlertRow::into_view))
    }

    async fn list_flows(&self, filter: &FlowFilter) -> anyhow::Result<Vec<FlowRecord>> {
        let mut builder = sqlx::QueryBuilder::new(
            "SELECT node, host(src_ip) AS src_ip, src_port, host(dst_ip) AS dst_ip, \
             dst_port, protocol, direction, bytes, packets, start_ms, last_seen_ms, \
             src_namespace, src_pod, dst_namespace, dst_pod \
             FROM flows WHERE TRUE",
        );
        if let Some(node) = &filter.node {
            builder.push(" AND node = ");
            builder.push_bind(node);
        }
        if let Some(namespace) = &filter.namespace {
            builder.push(" AND (src_namespace = ");
            builder.push_bind(namespace);
            builder.push(" OR dst_namespace = ");
            builder.push_bind(namespace);
            builder.push(")");
        }
        if let Some(pod) = &filter.pod {
            builder.push(" AND (src_pod = ");
            builder.push_bind(pod);
            builder.push(" OR dst_pod = ");
            builder.push_bind(pod);
            builder.push(")");
        }
        if let Some(since_ms) = filter.since_ms {
            builder.push(" AND last_seen_ms >= ");
            builder.push_bind(i64::try_from(since_ms).unwrap_or(i64::MAX));
        }
        builder.push(" ORDER BY last_seen_ms DESC LIMIT ");
        builder.push_bind(filter.limit.clamp(1, 10_000));
        let rows: Vec<FlowRow> = builder.build_query_as().fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(FlowRow::into_record).collect())
    }

    async fn list_alerts(&self, state: Option<&str>) -> anyhow::Result<Vec<AlertView>> {
        let rows: Vec<AlertRow> = if let Some(state) = state {
            sqlx::query_as(
                "SELECT id, severity, title, detail, first_seen_ms, last_seen_ms, \
                 labels, explanation, state, occurrences FROM alerts \
                 WHERE state = $1 ORDER BY last_seen_ms DESC LIMIT 500",
            )
            .bind(state)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                "SELECT id, severity, title, detail, first_seen_ms, last_seen_ms, \
                 labels, explanation, state, occurrences FROM alerts \
                 ORDER BY last_seen_ms DESC LIMIT 500",
            )
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows.into_iter().map(AlertRow::into_view).collect())
    }

    async fn get_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        let row: Option<AlertRow> = sqlx::query_as(
            "SELECT id, severity, title, detail, first_seen_ms, last_seen_ms, \
             labels, explanation, state, occurrences FROM alerts WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(AlertRow::into_view))
    }

    async fn counts(&self) -> anyhow::Result<crate::metrics::StoreCounts> {
        let flows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM flows")
            .fetch_one(&self.pool)
            .await?;
        let states: Vec<(String, i64)> =
            sqlx::query_as("SELECT state, COUNT(*) FROM alerts GROUP BY state")
                .fetch_all(&self.pool)
                .await?;
        let mut counts = crate::metrics::StoreCounts {
            flows: u64::try_from(flows).unwrap_or(0),
            ..crate::metrics::StoreCounts::default()
        };
        for (state, count) in states {
            let count = u64::try_from(count).unwrap_or(0);
            match state.as_str() {
                "firing" => counts.alerts_firing = count,
                "resolved" => counts.alerts_resolved = count,
                _ => {}
            }
        }
        Ok(counts)
    }

    async fn upsert_user(&self, email: &str, password_hash: &str) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO users (email, password_hash) VALUES ($1, $2) \
             ON CONFLICT (email) DO UPDATE SET password_hash = EXCLUDED.password_hash",
        )
        .bind(email)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_password_hash(&self, email: &str) -> anyhow::Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT password_hash FROM users WHERE email = $1")
                .bind(email)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|row| row.0))
    }
}

#[derive(sqlx::FromRow)]
struct FlowRow {
    node: String,
    src_ip: String,
    src_port: i32,
    dst_ip: String,
    dst_port: i32,
    protocol: i16,
    direction: String,
    bytes: i64,
    packets: i64,
    start_ms: i64,
    last_seen_ms: i64,
    src_namespace: Option<String>,
    src_pod: Option<String>,
    dst_namespace: Option<String>,
    dst_pod: Option<String>,
}

impl FlowRow {
    fn into_record(self) -> FlowRecord {
        let pod = |namespace: Option<String>, name: Option<String>| {
            namespace.and_then(|namespace| name.map(|name| PodRef { namespace, name }))
        };
        // `host(INET)` always renders parseable addresses; fall back to
        // unspecified rather than failing the whole listing.
        let unspecified = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        FlowRecord {
            key: mist_types::FlowKey {
                src_ip: self.src_ip.parse().unwrap_or(unspecified),
                src_port: u16::try_from(self.src_port).unwrap_or(0),
                dst_ip: self.dst_ip.parse().unwrap_or(unspecified),
                dst_port: u16::try_from(self.dst_port).unwrap_or(0),
                protocol: u8::try_from(self.protocol).unwrap_or(0),
            },
            direction: match self.direction.as_str() {
                "egress" => TrafficDirection::Egress,
                _ => TrafficDirection::Ingress,
            },
            bytes: u64::try_from(self.bytes).unwrap_or(0),
            packets: u64::try_from(self.packets).unwrap_or(0),
            start_unix_ms: u64::try_from(self.start_ms).unwrap_or(0),
            last_seen_unix_ms: u64::try_from(self.last_seen_ms).unwrap_or(0),
            node: self.node,
            src_pod: pod(self.src_namespace, self.src_pod),
            dst_pod: pod(self.dst_namespace, self.dst_pod),
        }
    }
}

#[derive(sqlx::FromRow)]
struct AlertRow {
    id: String,
    severity: String,
    title: String,
    detail: String,
    first_seen_ms: i64,
    last_seen_ms: i64,
    labels: sqlx::types::Json<HashMap<String, String>>,
    explanation: Option<String>,
    state: String,
    occurrences: i64,
}

impl AlertRow {
    fn into_view(self) -> AlertView {
        AlertView {
            alert: Alert {
                id: self.id,
                severity: match self.severity.as_str() {
                    "info" => Severity::Info,
                    "critical" => Severity::Critical,
                    _ => Severity::Warning,
                },
                title: self.title,
                detail: self.detail,
                first_seen_unix_ms: u64::try_from(self.first_seen_ms).unwrap_or(0),
                last_seen_unix_ms: u64::try_from(self.last_seen_ms).unwrap_or(0),
                labels: self.labels.0,
                explanation: self.explanation,
            },
            state: AlertLifecycle::parse(&self.state).unwrap_or(AlertLifecycle::Firing),
            occurrences: u64::try_from(self.occurrences).unwrap_or(0),
        }
    }
}

fn direction_str(direction: TrafficDirection) -> &'static str {
    match direction {
        TrafficDirection::Ingress => "ingress",
        TrafficDirection::Egress => "egress",
    }
}

fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

#[derive(Clone, Default)]
pub struct MemStore {
    inner: Arc<RwLock<MemState>>,
}

/// In-memory store cap: flow history beyond this is pruned oldest-first.
const MEM_FLOW_CAP: usize = 20_000;

#[derive(Default)]
struct MemState {
    flows: Vec<FlowRecord>,
    alerts: HashMap<String, StoredAlert>,
    users: HashMap<String, String>,
}

struct StoredAlert {
    alert: Alert,
    state: AlertLifecycle,
    occurrences: u64,
}

impl MemStore {
    fn save_flows(&self, flows: &[FlowRecord]) -> anyhow::Result<()> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        state.flows.extend_from_slice(flows);
        let overflow = state.flows.len().saturating_sub(MEM_FLOW_CAP);
        state.flows.drain(..overflow);
        Ok(())
    }

    fn upsert_alert(&self, alert: &Alert) -> anyhow::Result<AlertView> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        let stored = state
            .alerts
            .entry(alert.id.clone())
            .or_insert_with(|| StoredAlert {
                alert: alert.clone(),
                state: AlertLifecycle::Firing,
                occurrences: 0,
            });
        // A re-fire without an explanation (e.g. the stub explainer) keeps
        // the stored one; a re-fire carrying one refreshes it.
        let explanation = alert
            .explanation
            .clone()
            .or_else(|| stored.alert.explanation.clone());
        stored.alert = alert.clone();
        stored.alert.explanation = explanation;
        stored.alert.first_seen_unix_ms = stored
            .alert
            .first_seen_unix_ms
            .min(alert.first_seen_unix_ms);
        stored.alert.last_seen_unix_ms =
            stored.alert.last_seen_unix_ms.max(alert.last_seen_unix_ms);
        stored.state = AlertLifecycle::Firing;
        stored.occurrences = stored.occurrences.saturating_add(1);
        Ok(AlertView {
            alert: stored.alert.clone(),
            state: stored.state,
            occurrences: stored.occurrences,
        })
    }

    fn resolve_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        Ok(state.alerts.get_mut(id).map(|stored| {
            stored.state = AlertLifecycle::Resolved;
            AlertView {
                alert: stored.alert.clone(),
                state: stored.state,
                occurrences: stored.occurrences,
            }
        }))
    }

    fn list_flows(&self, filter: &FlowFilter) -> anyhow::Result<Vec<FlowRecord>> {
        let state = self
            .inner
            .read()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        let limit = usize::try_from(filter.limit.clamp(1, 10_000)).unwrap_or(100);
        Ok(state
            .flows
            .iter()
            .rev()
            .filter(|flow| {
                filter.node.as_deref().is_none_or(|node| flow.node == node)
                    && filter
                        .since_ms
                        .is_none_or(|since| flow.last_seen_unix_ms >= since)
                    && filter.namespace.as_deref().is_none_or(|namespace| {
                        flow.src_pod
                            .as_ref()
                            .is_some_and(|pod| pod.namespace == namespace)
                            || flow
                                .dst_pod
                                .as_ref()
                                .is_some_and(|pod| pod.namespace == namespace)
                    })
                    && filter.pod.as_deref().is_none_or(|pod| {
                        flow.src_pod
                            .as_ref()
                            .is_some_and(|candidate| candidate.name == pod)
                            || flow
                                .dst_pod
                                .as_ref()
                                .is_some_and(|candidate| candidate.name == pod)
                    })
            })
            .take(limit)
            .cloned()
            .collect())
    }

    fn list_alerts(&self, state: Option<&str>) -> anyhow::Result<Vec<AlertView>> {
        let wanted = state.and_then(AlertLifecycle::parse);
        let state = self
            .inner
            .read()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        let mut alerts: Vec<AlertView> = state
            .alerts
            .values()
            .filter(|stored| wanted.is_none_or(|lifecycle| stored.state == lifecycle))
            .map(|stored| AlertView {
                alert: stored.alert.clone(),
                state: stored.state,
                occurrences: stored.occurrences,
            })
            .collect();
        alerts.sort_by_key(|view| std::cmp::Reverse(view.alert.last_seen_unix_ms));
        alerts.truncate(500);
        Ok(alerts)
    }

    fn get_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        let state = self
            .inner
            .read()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        Ok(state.alerts.get(id).map(|stored| AlertView {
            alert: stored.alert.clone(),
            state: stored.state,
            occurrences: stored.occurrences,
        }))
    }

    fn counts(&self) -> anyhow::Result<crate::metrics::StoreCounts> {
        let state = self
            .inner
            .read()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        let mut counts = crate::metrics::StoreCounts {
            flows: u64::try_from(state.flows.len()).unwrap_or(u64::MAX),
            ..crate::metrics::StoreCounts::default()
        };
        for stored in state.alerts.values() {
            match stored.state {
                AlertLifecycle::Firing => {
                    counts.alerts_firing = counts.alerts_firing.saturating_add(1);
                }
                AlertLifecycle::Resolved => {
                    counts.alerts_resolved = counts.alerts_resolved.saturating_add(1);
                }
            }
        }
        Ok(counts)
    }

    fn upsert_user(&self, email: &str, password_hash: &str) -> anyhow::Result<()> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        state
            .users
            .insert(email.to_owned(), password_hash.to_owned());
        Ok(())
    }

    fn get_password_hash(&self, email: &str) -> anyhow::Result<Option<String>> {
        let state = self
            .inner
            .read()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        Ok(state.users.get(email).cloned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flow(node: &str, pod: Option<(&str, &str)>) -> FlowRecord {
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
            }),
            dst_pod: None,
        }
    }

    fn alert() -> Alert {
        Alert {
            id: "scan:10.0.1.4".to_owned(),
            severity: Severity::Warning,
            title: "scan".to_owned(),
            detail: "detail".to_owned(),
            first_seen_unix_ms: 1_700_000_000_000,
            last_seen_unix_ms: 1_700_000_060_000,
            labels: HashMap::new(),
            explanation: None,
        }
    }

    #[tokio::test]
    async fn mem_flows_filter_and_order() {
        let store = Store::Memory(MemStore::default());
        store
            .save_flows(&[
                flow("node-1", Some(("prod", "api-0"))),
                flow("node-2", Some(("dev", "worker-0"))),
            ])
            .await
            .unwrap();
        let all = store
            .list_flows(&FlowFilter {
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(all.len(), 2);
        // Newest first.
        assert_eq!(all[0].node, "node-2");
        let prod = store
            .list_flows(&FlowFilter {
                namespace: Some("prod".to_owned()),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(prod.len(), 1);
        assert_eq!(prod[0].node, "node-1");
        let none = store
            .list_flows(&FlowFilter {
                since_ms: Some(1_800_000_000_000),
                limit: 10,
                ..Default::default()
            })
            .await
            .unwrap();
        assert_eq!(none, Vec::new());
    }

    #[tokio::test]
    async fn mem_alerts_merge_and_resolve() {
        let store = Store::Memory(MemStore::default());
        let first = store.upsert_alert(&alert()).await.unwrap();
        assert_eq!(first.occurrences, 1);
        assert_eq!(first.state, AlertLifecycle::Firing);
        let mut again = alert();
        again.last_seen_unix_ms = 1_700_000_120_000;
        let second = store.upsert_alert(&again).await.unwrap();
        assert_eq!(second.occurrences, 2);
        assert_eq!(second.alert.first_seen_unix_ms, 1_700_000_000_000);
        assert_eq!(second.alert.last_seen_unix_ms, 1_700_000_120_000);
        let resolved = store.resolve_alert("scan:10.0.1.4").await.unwrap().unwrap();
        assert_eq!(resolved.state, AlertLifecycle::Resolved);
        // A re-report re-fires.
        let refired = store.upsert_alert(&alert()).await.unwrap();
        assert_eq!(refired.state, AlertLifecycle::Firing);
        assert_eq!(refired.occurrences, 3);
        assert!(store.resolve_alert("missing").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mem_alerts_keep_explanation_across_resolve_and_refire() {
        let store = Store::Memory(MemStore::default());
        let mut explained = alert();
        explained.explanation = Some("likely backup traffic".to_owned());
        let first = store.upsert_alert(&explained).await.unwrap();
        assert_eq!(
            first.alert.explanation.as_deref(),
            Some("likely backup traffic")
        );
        // Resolving flips state only; the explanation survives.
        let resolved = store.resolve_alert(&explained.id).await.unwrap().unwrap();
        assert_eq!(resolved.state, AlertLifecycle::Resolved);
        assert_eq!(
            resolved.alert.explanation.as_deref(),
            Some("likely backup traffic")
        );
        // A re-fire without an explanation preserves the stored one ...
        let refired = store.upsert_alert(&alert()).await.unwrap();
        assert_eq!(refired.state, AlertLifecycle::Firing);
        assert_eq!(
            refired.alert.explanation.as_deref(),
            Some("likely backup traffic")
        );
        // ... while a re-fire carrying one refreshes it.
        let mut updated = alert();
        updated.explanation = Some("confirmed exfiltration pattern".to_owned());
        let refreshed = store.upsert_alert(&updated).await.unwrap();
        assert_eq!(
            refreshed.alert.explanation.as_deref(),
            Some("confirmed exfiltration pattern")
        );
    }
}
