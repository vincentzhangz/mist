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
    Acknowledged,
    Resolved,
}

impl AlertLifecycle {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "firing" => Some(Self::Firing),
            "acknowledged" => Some(Self::Acknowledged),
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
    /// Who acknowledged the current firing episode, if anyone.
    pub acked_by: Option<String>,
    /// Ack note left with `acked_by`, if any.
    pub ack_note: Option<String>,
    /// Whether a silence rule currently mutes this alert (no notifications).
    /// Computed at read time, not stored.
    pub silenced: bool,
}

/// A mute rule: matching alerts stay stored and visible but skip
/// notifications while the window is open. All matchers must match; an
/// absent matcher matches everything.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Silence {
    pub id: i64,
    /// Lowercase severity filter, if set.
    pub severity: Option<String>,
    /// Case-insensitive title substring, if set.
    pub title_contains: Option<String>,
    /// Exact alert id, if set (mute one alert).
    pub alert_id: Option<String>,
    /// Label key; matches presence when `label_value` is `None`.
    pub label_key: Option<String>,
    /// Exact label value, if set.
    pub label_value: Option<String>,
    pub starts_at_ms: u64,
    pub ends_at_ms: u64,
    pub created_by: String,
    pub comment: String,
}

/// A rule to create; the store assigns `id`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NewSilence {
    pub severity: Option<String>,
    pub title_contains: Option<String>,
    pub alert_id: Option<String>,
    pub label_key: Option<String>,
    pub label_value: Option<String>,
    pub starts_at_ms: u64,
    pub ends_at_ms: u64,
    pub created_by: String,
    pub comment: String,
}

/// Wall-clock unix millis. Saturates instead of failing on exotic clocks.
#[must_use]
pub(crate) fn now_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_millis()),
    )
    .unwrap_or(u64::MAX)
}

/// Whether `rule` mutes `alert` at `now_ms`: the window must be open
/// (`starts_at_ms <= now < ends_at_ms`) and every set matcher must hit.
#[must_use]
pub fn silence_matches(rule: &Silence, alert: &Alert, now_ms: u64) -> bool {
    if now_ms < rule.starts_at_ms || now_ms >= rule.ends_at_ms {
        return false;
    }
    if let Some(severity) = rule.severity.as_deref()
        && !severity_str(alert.severity).eq_ignore_ascii_case(severity)
    {
        return false;
    }
    if let Some(query) = rule.title_contains.as_deref()
        && !alert.title.to_lowercase().contains(&query.to_lowercase())
    {
        return false;
    }
    if let Some(id) = rule.alert_id.as_deref()
        && alert.id != id
    {
        return false;
    }
    if let Some(key) = rule.label_key.as_deref() {
        let hit = rule.label_value.as_deref().map_or_else(
            || alert.labels.contains_key(key),
            |want| alert.labels.get(key).is_some_and(|got| got == want),
        );
        if !hit {
            return false;
        }
    }
    true
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

    /// Acknowledge a firing alert as `by` with `note`. Returns `None` when
    /// the alert is missing or already resolved.
    pub async fn ack_alert(
        &self,
        id: &str,
        by: &str,
        note: &str,
    ) -> anyhow::Result<Option<AlertView>> {
        match self {
            Self::Postgres(store) => store.ack_alert(id, by, note).await,
            Self::Memory(store) => store.ack_alert(id, by, note),
        }
    }

    /// Store a silence rule, pruning expired ones first.
    pub async fn create_silence(&self, rule: &NewSilence) -> anyhow::Result<Silence> {
        match self {
            Self::Postgres(store) => store.create_silence(rule).await,
            Self::Memory(store) => store.create_silence(rule),
        }
    }

    /// All silence rules, earliest expiry first.
    pub async fn list_silences(&self) -> anyhow::Result<Vec<Silence>> {
        match self {
            Self::Postgres(store) => store.list_silences().await,
            Self::Memory(store) => store.list_silences(),
        }
    }

    /// Delete a silence rule. Returns whether one existed.
    pub async fn delete_silence(&self, id: i64) -> anyhow::Result<bool> {
        match self {
            Self::Postgres(store) => store.delete_silence(id).await,
            Self::Memory(store) => store.delete_silence(id),
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
        // One statement per chunk via UNNEST: a burst drain can hold 16k+
        // rows, and row-by-row INSERTs stall the analyzer for minutes.
        // Postgres caps parameters at 65535 (15 columns -> chunk at 2000).
        let to_i64 = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
        for chunk in flows.chunks(2000) {
            if chunk.is_empty() {
                continue;
            }
            let mut nodes = Vec::with_capacity(chunk.len());
            let mut src_ips = Vec::with_capacity(chunk.len());
            let mut src_ports = Vec::with_capacity(chunk.len());
            let mut dst_ips = Vec::with_capacity(chunk.len());
            let mut dst_ports = Vec::with_capacity(chunk.len());
            let mut protocols = Vec::with_capacity(chunk.len());
            let mut directions = Vec::with_capacity(chunk.len());
            let mut bytes = Vec::with_capacity(chunk.len());
            let mut packets = Vec::with_capacity(chunk.len());
            let mut starts = Vec::with_capacity(chunk.len());
            let mut lasts = Vec::with_capacity(chunk.len());
            let mut src_namespaces: Vec<Option<String>> = Vec::with_capacity(chunk.len());
            let mut src_pods: Vec<Option<String>> = Vec::with_capacity(chunk.len());
            let mut dst_namespaces: Vec<Option<String>> = Vec::with_capacity(chunk.len());
            let mut dst_pods: Vec<Option<String>> = Vec::with_capacity(chunk.len());
            for flow in chunk {
                nodes.push(flow.node.clone());
                src_ips.push(flow.key.src_ip.to_string());
                src_ports.push(i32::from(flow.key.src_port));
                dst_ips.push(flow.key.dst_ip.to_string());
                dst_ports.push(i32::from(flow.key.dst_port));
                protocols.push(i16::from(flow.key.protocol));
                directions.push(direction_str(flow.direction).to_owned());
                bytes.push(to_i64(flow.bytes));
                packets.push(to_i64(flow.packets));
                starts.push(to_i64(flow.start_unix_ms));
                lasts.push(to_i64(flow.last_seen_unix_ms));
                src_namespaces.push(flow.src_pod.as_ref().map(|pod| pod.namespace.clone()));
                src_pods.push(flow.src_pod.as_ref().map(|pod| pod.name.clone()));
                dst_namespaces.push(flow.dst_pod.as_ref().map(|pod| pod.namespace.clone()));
                dst_pods.push(flow.dst_pod.as_ref().map(|pod| pod.name.clone()));
            }
            sqlx::query(
                "INSERT INTO flows (node, src_ip, src_port, dst_ip, dst_port, protocol, \
                 direction, bytes, packets, start_ms, last_seen_ms, \
                 src_namespace, src_pod, dst_namespace, dst_pod) \
                 SELECT node, src_ip::INET, src_port, dst_ip::INET, dst_port, protocol, \
                 direction, bytes, packets, start_ms, last_seen_ms, \
                 src_namespace, src_pod, dst_namespace, dst_pod \
                 FROM UNNEST($1::TEXT[], $2::TEXT[], $3::INT[], $4::TEXT[], $5::INT[], \
                 $6::SMALLINT[], $7::TEXT[], $8::BIGINT[], $9::BIGINT[], $10::BIGINT[], \
                 $11::BIGINT[], $12::TEXT[], $13::TEXT[], $14::TEXT[], $15::TEXT[]) \
                 AS batch(node, src_ip, src_port, dst_ip, dst_port, protocol, \
                 direction, bytes, packets, start_ms, last_seen_ms, \
                 src_namespace, src_pod, dst_namespace, dst_pod)",
            )
            .bind(nodes)
            .bind(src_ips)
            .bind(src_ports)
            .bind(dst_ips)
            .bind(dst_ports)
            .bind(protocols)
            .bind(directions)
            .bind(bytes)
            .bind(packets)
            .bind(starts)
            .bind(lasts)
            .bind(src_namespaces)
            .bind(src_pods)
            .bind(dst_namespaces)
            .bind(dst_pods)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    async fn upsert_alert(&self, alert: &Alert) -> anyhow::Result<AlertView> {
        // `COALESCE` keeps the stored explanation when a re-fire carries
        // none (e.g. the stub explainer), and refreshes it when the re-fire
        // carries one. Resolve only flips `state`, so it never wipes it.
        // A re-fire reopens `resolved` alerts to `firing` (dropping the old
        // ack) but leaves `acknowledged` ones acked.
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
               state = CASE WHEN alerts.state = 'resolved' THEN 'firing' ELSE alerts.state END, \
               acked_by = CASE WHEN alerts.state = 'resolved' THEN NULL ELSE alerts.acked_by END, \
               ack_note = CASE WHEN alerts.state = 'resolved' THEN NULL ELSE alerts.ack_note END, \
               occurrences = alerts.occurrences + 1, \
               updated_at = now() \
             RETURNING id, severity, title, detail, first_seen_ms, last_seen_ms, \
               labels, explanation, acked_by, ack_note, state, occurrences",
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
               labels, explanation, acked_by, ack_note, state, occurrences",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(AlertRow::into_view))
    }

    async fn ack_alert(&self, id: &str, by: &str, note: &str) -> anyhow::Result<Option<AlertView>> {
        let row: Option<AlertRow> = sqlx::query_as(
            "UPDATE alerts SET state = 'acknowledged', acked_by = $2, ack_note = $3, \
             updated_at = now() WHERE id = $1 AND state != 'resolved' \
             RETURNING id, severity, title, detail, first_seen_ms, last_seen_ms, \
               labels, explanation, acked_by, ack_note, state, occurrences",
        )
        .bind(id)
        .bind(by)
        .bind(note)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(AlertRow::into_view))
    }

    async fn create_silence(&self, rule: &NewSilence) -> anyhow::Result<Silence> {
        let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
        sqlx::query("DELETE FROM silences WHERE ends_at_ms < $1")
            .bind(now)
            .execute(&self.pool)
            .await?;
        let row: SilenceRow = sqlx::query_as(
            "INSERT INTO silences (severity, title_contains, alert_id, label_key, label_value, \
             starts_at_ms, ends_at_ms, created_by, comment) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) \
             RETURNING id, severity, title_contains, alert_id, label_key, label_value, \
               starts_at_ms, ends_at_ms, created_by, comment",
        )
        .bind(rule.severity.as_deref())
        .bind(rule.title_contains.as_deref())
        .bind(rule.alert_id.as_deref())
        .bind(rule.label_key.as_deref())
        .bind(rule.label_value.as_deref())
        .bind(i64::try_from(rule.starts_at_ms).unwrap_or(i64::MAX))
        .bind(i64::try_from(rule.ends_at_ms).unwrap_or(i64::MAX))
        .bind(&rule.created_by)
        .bind(&rule.comment)
        .fetch_one(&self.pool)
        .await?;
        Ok(row.into_silence())
    }

    async fn list_silences(&self) -> anyhow::Result<Vec<Silence>> {
        let rows: Vec<SilenceRow> = sqlx::query_as(
            "SELECT id, severity, title_contains, alert_id, label_key, label_value, \
             starts_at_ms, ends_at_ms, created_by, comment FROM silences \
             ORDER BY ends_at_ms ASC LIMIT 500",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(SilenceRow::into_silence).collect())
    }

    async fn delete_silence(&self, id: i64) -> anyhow::Result<bool> {
        let done = sqlx::query("DELETE FROM silences WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
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
                 labels, explanation, acked_by, ack_note, state, occurrences FROM alerts \
                 WHERE state = $1 ORDER BY last_seen_ms DESC LIMIT 500",
            )
            .bind(state)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query_as(
                "SELECT id, severity, title, detail, first_seen_ms, last_seen_ms, \
                 labels, explanation, acked_by, ack_note, state, occurrences FROM alerts \
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
             labels, explanation, acked_by, ack_note, state, occurrences FROM alerts WHERE id = $1",
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
                "acknowledged" => counts.alerts_acknowledged = count,
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
    acked_by: Option<String>,
    ack_note: Option<String>,
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
            acked_by: self.acked_by,
            ack_note: self.ack_note,
            silenced: false,
        }
    }
}

#[derive(sqlx::FromRow)]
struct SilenceRow {
    id: i64,
    severity: Option<String>,
    title_contains: Option<String>,
    alert_id: Option<String>,
    label_key: Option<String>,
    label_value: Option<String>,
    starts_at_ms: i64,
    ends_at_ms: i64,
    created_by: String,
    comment: String,
}

impl SilenceRow {
    fn into_silence(self) -> Silence {
        Silence {
            id: self.id,
            severity: self.severity,
            title_contains: self.title_contains,
            alert_id: self.alert_id,
            label_key: self.label_key,
            label_value: self.label_value,
            starts_at_ms: u64::try_from(self.starts_at_ms).unwrap_or(0),
            ends_at_ms: u64::try_from(self.ends_at_ms).unwrap_or(0),
            created_by: self.created_by,
            comment: self.comment,
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
    silences: HashMap<i64, Silence>,
    next_silence_id: i64,
}

struct StoredAlert {
    alert: Alert,
    state: AlertLifecycle,
    occurrences: u64,
    acked_by: Option<String>,
    ack_note: Option<String>,
}

impl StoredAlert {
    fn view(&self) -> AlertView {
        AlertView {
            alert: self.alert.clone(),
            state: self.state,
            occurrences: self.occurrences,
            acked_by: self.acked_by.clone(),
            ack_note: self.ack_note.clone(),
            silenced: false,
        }
    }
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
                acked_by: None,
                ack_note: None,
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
        // A re-fire reopens `resolved` alerts (dropping the old ack) but
        // leaves `acknowledged` ones acked.
        if stored.state == AlertLifecycle::Resolved {
            stored.state = AlertLifecycle::Firing;
            stored.acked_by = None;
            stored.ack_note = None;
        }
        stored.occurrences = stored.occurrences.saturating_add(1);
        Ok(stored.view())
    }

    fn resolve_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        Ok(state.alerts.get_mut(id).map(|stored| {
            stored.state = AlertLifecycle::Resolved;
            stored.view()
        }))
    }

    fn ack_alert(&self, id: &str, by: &str, note: &str) -> anyhow::Result<Option<AlertView>> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        Ok(state.alerts.get_mut(id).and_then(|stored| {
            if stored.state == AlertLifecycle::Resolved {
                return None;
            }
            stored.state = AlertLifecycle::Acknowledged;
            stored.acked_by = Some(by.to_owned());
            stored.ack_note = Some(note.to_owned());
            Some(stored.view())
        }))
    }

    fn create_silence(&self, rule: &NewSilence) -> anyhow::Result<Silence> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        let now = now_ms();
        state.silences.retain(|_, rule| rule.ends_at_ms >= now);
        state.next_silence_id = state.next_silence_id.saturating_add(1);
        let silence = Silence {
            id: state.next_silence_id,
            severity: rule.severity.clone(),
            title_contains: rule.title_contains.clone(),
            alert_id: rule.alert_id.clone(),
            label_key: rule.label_key.clone(),
            label_value: rule.label_value.clone(),
            starts_at_ms: rule.starts_at_ms,
            ends_at_ms: rule.ends_at_ms,
            created_by: rule.created_by.clone(),
            comment: rule.comment.clone(),
        };
        state.silences.insert(silence.id, silence.clone());
        Ok(silence)
    }

    fn list_silences(&self) -> anyhow::Result<Vec<Silence>> {
        let state = self
            .inner
            .read()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        let mut rules: Vec<Silence> = state.silences.values().cloned().collect();
        rules.sort_by_key(|rule| rule.ends_at_ms);
        rules.truncate(500);
        Ok(rules)
    }

    fn delete_silence(&self, id: i64) -> anyhow::Result<bool> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| anyhow::anyhow!("mem store lock poisoned"))?;
        Ok(state.silences.remove(&id).is_some())
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
            .map(StoredAlert::view)
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
        Ok(state.alerts.get(id).map(StoredAlert::view))
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
                AlertLifecycle::Acknowledged => {
                    counts.alerts_acknowledged = counts.alerts_acknowledged.saturating_add(1);
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

    fn silence() -> Silence {
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

    #[test]
    fn silence_window_is_half_open() {
        let rule = silence();
        let alert = alert();
        assert!(!silence_matches(&rule, &alert, 999));
        assert!(silence_matches(&rule, &alert, 1_000));
        assert!(silence_matches(&rule, &alert, 1_999));
        assert!(!silence_matches(&rule, &alert, 2_000));
    }

    #[test]
    fn silence_matchers_all_must_hit() {
        let mut alert = alert();
        alert.title = "Port scan of node-1".to_owned();
        alert.labels.insert("node".to_owned(), "node-1".to_owned());
        let mut rule = silence();
        // No matchers: mutes everything in the window.
        assert!(silence_matches(&rule, &alert, 1_500));
        rule.severity = Some("warning".to_owned());
        assert!(silence_matches(&rule, &alert, 1_500));
        rule.severity = Some("critical".to_owned());
        assert!(!silence_matches(&rule, &alert, 1_500));
        rule.severity = None;
        rule.title_contains = Some("PORT SCAN".to_owned());
        assert!(silence_matches(&rule, &alert, 1_500));
        rule.title_contains = Some("egress".to_owned());
        assert!(!silence_matches(&rule, &alert, 1_500));
        rule.title_contains = None;
        rule.alert_id = Some("scan:10.0.1.4".to_owned());
        assert!(silence_matches(&rule, &alert, 1_500));
        rule.alert_id = Some("other".to_owned());
        assert!(!silence_matches(&rule, &alert, 1_500));
        rule.alert_id = None;
        rule.label_key = Some("node".to_owned());
        assert!(silence_matches(&rule, &alert, 1_500));
        rule.label_value = Some("node-1".to_owned());
        assert!(silence_matches(&rule, &alert, 1_500));
        rule.label_value = Some("node-9".to_owned());
        assert!(!silence_matches(&rule, &alert, 1_500));
        rule.label_key = Some("missing".to_owned());
        rule.label_value = None;
        assert!(!silence_matches(&rule, &alert, 1_500));
    }

    fn new_silence(ends_at_ms: u64) -> NewSilence {
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

    #[tokio::test]
    async fn mem_ack_survives_refire_and_clears_on_reopen() {
        let store = Store::Memory(MemStore::default());
        let fired = store.upsert_alert(&alert()).await.unwrap();
        assert_eq!(fired.state, AlertLifecycle::Firing);
        assert_eq!(fired.acked_by, None);
        let acked = store
            .ack_alert(&alert().id, "oncall@example.com", "looking")
            .await
            .unwrap()
            .expect("ack must apply");
        assert_eq!(acked.state, AlertLifecycle::Acknowledged);
        assert_eq!(acked.acked_by.as_deref(), Some("oncall@example.com"));
        assert_eq!(acked.ack_note.as_deref(), Some("looking"));
        // A re-fire keeps the ack.
        let refired = store.upsert_alert(&alert()).await.unwrap();
        assert_eq!(refired.state, AlertLifecycle::Acknowledged);
        assert_eq!(refired.acked_by.as_deref(), Some("oncall@example.com"));
        // Resolve, then re-fire: reopened fresh, ack dropped.
        store.resolve_alert(&alert().id).await.unwrap();
        let reopened = store.upsert_alert(&alert()).await.unwrap();
        assert_eq!(reopened.state, AlertLifecycle::Firing);
        assert_eq!(reopened.acked_by, None);
        // Acking a resolved alert is a no-op.
        store.resolve_alert(&alert().id).await.unwrap();
        assert!(
            store
                .ack_alert(&alert().id, "x", "")
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.ack_alert("missing", "x", "").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn mem_silences_crud_and_prune_expired() {
        let store = Store::Memory(MemStore::default());
        let first = store.create_silence(&new_silence(u64::MAX)).await.unwrap();
        assert_eq!(first.id, 1);
        let second = store
            .create_silence(&new_silence(u64::MAX - 1))
            .await
            .unwrap();
        assert_eq!(second.id, 2);
        let rules = store.list_silences().await.unwrap();
        assert_eq!(rules.len(), 2);
        assert!(rules[0].ends_at_ms <= rules[1].ends_at_ms);
        assert!(store.delete_silence(first.id).await.unwrap());
        assert!(!store.delete_silence(first.id).await.unwrap());
        assert_eq!(store.list_silences().await.unwrap().len(), 1);
        // Creating a live rule prunes the expired one.
        let expired = NewSilence {
            ends_at_ms: 1,
            ..new_silence(u64::MAX)
        };
        let created = store.create_silence(&expired).await.unwrap();
        let _ = store.create_silence(&new_silence(u64::MAX)).await.unwrap();
        let rules = store.list_silences().await.unwrap();
        assert!(rules.iter().all(|rule| rule.id != created.id));
    }
}
