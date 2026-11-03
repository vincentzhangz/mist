//! Postgres storage backend.

use std::collections::HashMap;

use mist_types::{Alert, FlowRecord, PodRef, Severity, TrafficDirection};

use super::model::{
    AlertFilter, AlertLifecycle, AlertView, FlowFilter, NewSilence, Silence, now_ms,
};

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

    pub(crate) async fn save_flows(&self, flows: &[FlowRecord]) -> anyhow::Result<()> {
        // One statement per chunk via UNNEST: a burst drain can hold 16k+
        // rows, and row-by-row INSERTs stall the analyzer for minutes.
        // Postgres caps parameters at 65535 (17 columns -> chunk at 2000).
        let to_i64 = |value: u64| i64::try_from(value).unwrap_or(i64::MAX);
        let to_json = |labels: &HashMap<String, String>| {
            serde_json::to_string(labels).unwrap_or_else(|_| "{}".to_owned())
        };
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
            let mut src_labels = Vec::with_capacity(chunk.len());
            let mut dst_namespaces: Vec<Option<String>> = Vec::with_capacity(chunk.len());
            let mut dst_pods: Vec<Option<String>> = Vec::with_capacity(chunk.len());
            let mut dst_labels = Vec::with_capacity(chunk.len());
            for flow in chunk {
                nodes.push(flow.node.clone());
                src_ips.push(flow.key.src_ip.to_string());
                src_ports.push(i32::from(flow.key.src_port));
                dst_ips.push(flow.key.dst_ip.to_string());
                dst_ports.push(i32::from(flow.key.dst_port));
                protocols.push(i16::from(flow.key.protocol));
                directions.push(super::model::direction_str(flow.direction).to_owned());
                bytes.push(to_i64(flow.bytes));
                packets.push(to_i64(flow.packets));
                starts.push(to_i64(flow.start_unix_ms));
                lasts.push(to_i64(flow.last_seen_unix_ms));
                src_namespaces.push(flow.src_pod.as_ref().map(|pod| pod.namespace.clone()));
                src_pods.push(flow.src_pod.as_ref().map(|pod| pod.name.clone()));
                src_labels.push(
                    flow.src_pod
                        .as_ref()
                        .map_or_else(|| "{}".to_owned(), |pod| to_json(&pod.labels)),
                );
                dst_namespaces.push(flow.dst_pod.as_ref().map(|pod| pod.namespace.clone()));
                dst_pods.push(flow.dst_pod.as_ref().map(|pod| pod.name.clone()));
                dst_labels.push(
                    flow.dst_pod
                        .as_ref()
                        .map_or_else(|| "{}".to_owned(), |pod| to_json(&pod.labels)),
                );
            }
            sqlx::query(
                "INSERT INTO flows (node, src_ip, src_port, dst_ip, dst_port, protocol, \
                 direction, bytes, packets, start_ms, last_seen_ms, \
                 src_namespace, src_pod, src_labels, dst_namespace, dst_pod, dst_labels) \
                 SELECT node, src_ip::INET, src_port, dst_ip::INET, dst_port, protocol, \
                 direction, bytes, packets, start_ms, last_seen_ms, \
                 src_namespace, src_pod, src_labels::JSONB, \
                 dst_namespace, dst_pod, dst_labels::JSONB \
                 FROM UNNEST($1::TEXT[], $2::TEXT[], $3::INT[], $4::TEXT[], $5::INT[], \
                 $6::SMALLINT[], $7::TEXT[], $8::BIGINT[], $9::BIGINT[], $10::BIGINT[], \
                 $11::BIGINT[], $12::TEXT[], $13::TEXT[], $14::TEXT[], $15::TEXT[], \
                 $16::TEXT[], $17::TEXT[]) \
                 AS batch(node, src_ip, src_port, dst_ip, dst_port, protocol, \
                 direction, bytes, packets, start_ms, last_seen_ms, \
                 src_namespace, src_pod, src_labels, dst_namespace, dst_pod, dst_labels)",
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
            .bind(src_labels)
            .bind(dst_namespaces)
            .bind(dst_pods)
            .bind(dst_labels)
            .execute(&self.pool)
            .await?;
        }
        Ok(())
    }

    pub(crate) async fn upsert_alert(&self, alert: &Alert) -> anyhow::Result<AlertView> {
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
        .bind(super::model::severity_str(alert.severity))
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

    pub(crate) async fn resolve_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
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

    pub(crate) async fn ack_alert(
        &self,
        id: &str,
        by: &str,
        note: &str,
    ) -> anyhow::Result<Option<AlertView>> {
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

    pub(crate) async fn create_silence(&self, rule: &NewSilence) -> anyhow::Result<Silence> {
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

    pub(crate) async fn list_silences(&self) -> anyhow::Result<Vec<Silence>> {
        let rows: Vec<SilenceRow> = sqlx::query_as(
            "SELECT id, severity, title_contains, alert_id, label_key, label_value, \
             starts_at_ms, ends_at_ms, created_by, comment FROM silences \
             ORDER BY ends_at_ms ASC LIMIT 500",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().map(SilenceRow::into_silence).collect())
    }

    pub(crate) async fn delete_silence(&self, id: i64) -> anyhow::Result<bool> {
        let done = sqlx::query("DELETE FROM silences WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(done.rows_affected() > 0)
    }

    pub(crate) async fn list_flows(&self, filter: &FlowFilter) -> anyhow::Result<Vec<FlowRecord>> {
        let mut builder = sqlx::QueryBuilder::new(
            "SELECT node, host(src_ip) AS src_ip, src_port, host(dst_ip) AS dst_ip, \
             dst_port, protocol, direction, bytes, packets, start_ms, last_seen_ms, \
             src_namespace, src_pod, src_labels, dst_namespace, dst_pod, dst_labels \
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
        if let Some(before_ms) = filter.before_ms {
            builder.push(" AND last_seen_ms <= ");
            builder.push_bind(i64::try_from(before_ms).unwrap_or(i64::MAX));
        }
        builder.push(" ORDER BY last_seen_ms DESC LIMIT ");
        builder.push_bind(filter.limit.clamp(1, 10_000));
        let rows: Vec<FlowRow> = builder.build_query_as().fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(FlowRow::into_record).collect())
    }

    pub(crate) async fn list_alerts(&self, filter: &AlertFilter) -> anyhow::Result<Vec<AlertView>> {
        let mut builder = sqlx::QueryBuilder::new(
            "SELECT id, severity, title, detail, first_seen_ms, last_seen_ms, \
             labels, explanation, acked_by, ack_note, state, occurrences FROM alerts WHERE TRUE",
        );
        if let Some(state) = &filter.state {
            builder.push(" AND state = ");
            builder.push_bind(state);
        }
        if let Some(severity) = &filter.severity {
            builder.push(" AND severity = ");
            builder.push_bind(severity);
        }
        if let Some(before_ms) = filter.before_ms {
            builder.push(" AND last_seen_ms <= ");
            builder.push_bind(i64::try_from(before_ms).unwrap_or(i64::MAX));
        }
        builder.push(" ORDER BY last_seen_ms DESC LIMIT ");
        builder.push_bind(filter.limit.clamp(1, 10_000));
        let rows: Vec<AlertRow> = builder.build_query_as().fetch_all(&self.pool).await?;
        Ok(rows.into_iter().map(AlertRow::into_view).collect())
    }

    pub(crate) async fn get_alert(&self, id: &str) -> anyhow::Result<Option<AlertView>> {
        let row: Option<AlertRow> = sqlx::query_as(
            "SELECT id, severity, title, detail, first_seen_ms, last_seen_ms, \
             labels, explanation, acked_by, ack_note, state, occurrences FROM alerts WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(AlertRow::into_view))
    }

    pub(crate) async fn counts(&self) -> anyhow::Result<crate::metrics::StoreCounts> {
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

    pub(crate) async fn upsert_user(&self, email: &str, password_hash: &str) -> anyhow::Result<()> {
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

    pub(crate) async fn get_password_hash(&self, email: &str) -> anyhow::Result<Option<String>> {
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
    src_labels: sqlx::types::Json<HashMap<String, String>>,
    dst_namespace: Option<String>,
    dst_pod: Option<String>,
    dst_labels: sqlx::types::Json<HashMap<String, String>>,
}

impl FlowRow {
    fn into_record(self) -> FlowRecord {
        let pod = |namespace: Option<String>,
                   name: Option<String>,
                   labels: sqlx::types::Json<HashMap<String, String>>| {
            namespace.and_then(|namespace| {
                name.map(|name| PodRef {
                    namespace,
                    name,
                    labels: labels.0,
                })
            })
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
            src_pod: pod(self.src_namespace, self.src_pod, self.src_labels),
            dst_pod: pod(self.dst_namespace, self.dst_pod, self.dst_labels),
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
