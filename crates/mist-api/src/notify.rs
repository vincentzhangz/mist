//! Outbound alert notifications: generic webhook + Slack.
//!
//! Disabled by default; enabled via `NOTIFY_WEBHOOK_URL` and/or
//! `NOTIFY_SLACK_WEBHOOK_URL`. Each alert id notifies exactly once (first
//! upsert, `occurrences == 1`) when its severity passes
//! `NOTIFY_MIN_SEVERITY`. Delivery is fail-open: failures log a warning and
//! bump `mist_api_notify_failures_total`, never blocking the pipeline.

use std::time::Duration;

use mist_types::{Alert, Severity};

/// Per-delivery timeout; notification must never stall the analyzer.
const REQUEST_TIMEOUT_SECS: u64 = 5;

/// Minimum severity that triggers a notification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MinSeverity {
    #[default]
    Info,
    Warning,
    Critical,
}

impl MinSeverity {
    /// Parse `NOTIFY_MIN_SEVERITY`. Unknown values fall back to `Info`
    /// (notify on everything) rather than silently dropping alerts.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        match text.trim().to_lowercase().as_str() {
            "warning" | "warn" => Self::Warning,
            "critical" | "crit" => Self::Critical,
            _ => Self::Info,
        }
    }

    /// Whether `severity` passes this gate.
    #[must_use]
    pub fn allows(self, severity: Severity) -> bool {
        fn rank(severity: Severity) -> u8 {
            match severity {
                Severity::Info => 0,
                Severity::Warning => 1,
                Severity::Critical => 2,
            }
        }
        rank(severity)
            >= rank(match self {
                Self::Info => Severity::Info,
                Self::Warning => Severity::Warning,
                Self::Critical => Severity::Critical,
            })
    }
}

/// JSON body sent to `NOTIFY_WEBHOOK_URL`.
#[must_use]
pub fn webhook_payload(alert: &Alert) -> serde_json::Value {
    serde_json::json!({
        "source": "mist",
        "alert": alert,
    })
}

fn format_labels(alert: &Alert) -> String {
    if alert.labels.is_empty() {
        return "-".to_owned();
    }
    let mut pairs: Vec<(&String, &String)> = alert.labels.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Plain-text message sent to Slack (`{"text": ...}`).
#[must_use]
pub fn slack_text(alert: &Alert) -> String {
    let mut text = format!(
        "[{:?}] {}\n{}\nLabels: {}",
        alert.severity,
        alert.title,
        alert.detail,
        format_labels(alert),
    );
    if let Some(explanation) = alert.explanation.as_deref().filter(|e| !e.is_empty()) {
        text.push_str("\nWhy: ");
        text.push_str(explanation);
    }
    text
}

/// One notification target. Returns whether the alert was delivered.
pub trait Notifier: Send + Sync {
    /// Stable name for logs.
    fn name(&self) -> &'static str;
    /// Deliver `alert`; any failure yields `false` after a warning log.
    async fn notify(&self, alert: &Alert) -> bool;
}

/// Generic JSON webhook with an optional `Bearer` credential.
#[derive(Debug, Clone)]
pub struct WebhookNotifier {
    client: reqwest::Client,
    url: String,
    bearer: Option<String>,
}

impl WebhookNotifier {
    #[must_use]
    pub fn new(url: String, bearer: Option<String>) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
            bearer,
        }
    }
}

impl Notifier for WebhookNotifier {
    fn name(&self) -> &'static str {
        "webhook"
    }

    async fn notify(&self, alert: &Alert) -> bool {
        let mut request = self
            .client
            .post(&self.url)
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .json(&webhook_payload(alert));
        if let Some(bearer) = self.bearer.as_deref() {
            request = request.bearer_auth(bearer);
        }
        match request.send().await {
            Ok(response) if response.status().is_success() => true,
            Ok(response) => {
                tracing::warn!(
                    alert_id = %alert.id,
                    status = %response.status(),
                    "webhook notification rejected"
                );
                false
            }
            Err(err) => {
                tracing::warn!(alert_id = %alert.id, "webhook notification failed: {err}");
                false
            }
        }
    }
}

/// Slack Incoming Webhook (`{"text": ...}`).
#[derive(Debug, Clone)]
pub struct SlackNotifier {
    client: reqwest::Client,
    url: String,
}

impl SlackNotifier {
    #[must_use]
    pub fn new(url: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            url,
        }
    }
}

impl Notifier for SlackNotifier {
    fn name(&self) -> &'static str {
        "slack"
    }

    async fn notify(&self, alert: &Alert) -> bool {
        let body = serde_json::json!({ "text": slack_text(alert) });
        match self
            .client
            .post(&self.url)
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .json(&body)
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => true,
            Ok(response) => {
                tracing::warn!(
                    alert_id = %alert.id,
                    status = %response.status(),
                    "slack notification rejected"
                );
                false
            }
            Err(err) => {
                tracing::warn!(alert_id = %alert.id, "slack notification failed: {err}");
                false
            }
        }
    }
}

/// Runtime notification target.
#[derive(Debug, Clone)]
pub enum NotifierKind {
    Webhook(WebhookNotifier),
    Slack(SlackNotifier),
}

impl Notifier for NotifierKind {
    fn name(&self) -> &'static str {
        match self {
            Self::Webhook(inner) => inner.name(),
            Self::Slack(inner) => inner.name(),
        }
    }

    async fn notify(&self, alert: &Alert) -> bool {
        match self {
            Self::Webhook(inner) => inner.notify(alert).await,
            Self::Slack(inner) => inner.notify(alert).await,
        }
    }
}

/// Notification targets plus the severity gate, from `NOTIFY_*` env.
#[derive(Debug, Clone, Default)]
pub struct NotifyConfig {
    /// Configured targets; empty means notifications are disabled.
    pub targets: Vec<NotifierKind>,
    /// Alerts below this severity are never sent.
    pub min_severity: MinSeverity,
}

impl NotifyConfig {
    fn clean_env(name: &str) -> Option<String> {
        std::env::var(name)
            .ok()
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    }

    /// Read `NOTIFY_WEBHOOK_URL` (+ optional `NOTIFY_WEBHOOK_BEARER`),
    /// `NOTIFY_SLACK_WEBHOOK_URL`, and `NOTIFY_MIN_SEVERITY`. Credentials are
    /// never logged.
    #[must_use]
    pub fn from_env() -> Self {
        let mut targets = Vec::new();
        if let Some(url) = Self::clean_env("NOTIFY_WEBHOOK_URL") {
            tracing::info!(%url, "webhook notifications enabled");
            targets.push(NotifierKind::Webhook(WebhookNotifier::new(
                url,
                Self::clean_env("NOTIFY_WEBHOOK_BEARER"),
            )));
        }
        if let Some(url) = Self::clean_env("NOTIFY_SLACK_WEBHOOK_URL") {
            tracing::info!(%url, "slack notifications enabled");
            targets.push(NotifierKind::Slack(SlackNotifier::new(url)));
        }
        let min_severity = Self::clean_env("NOTIFY_MIN_SEVERITY")
            .map(|value| MinSeverity::parse(&value))
            .unwrap_or_default();
        if targets.is_empty() {
            tracing::info!("NOTIFY_* unset; outbound notifications disabled");
        }
        Self {
            targets,
            min_severity,
        }
    }

    /// Send `alert` to every target when this is its first upsert and its
    /// severity passes the gate. Failures bump the notify-failures counter.
    pub async fn notify_if_new(
        &self,
        alert: &Alert,
        occurrences: u64,
        metrics: &crate::metrics::Metrics,
    ) {
        if occurrences != 1 || !self.min_severity.allows(alert.severity) {
            return;
        }
        for target in &self.targets {
            if target.notify(alert).await {
                tracing::info!(
                    target = target.name(),
                    alert_id = %alert.id,
                    "notification sent"
                );
            } else {
                metrics.notify_failed();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn alert(severity: Severity) -> Alert {
        Alert {
            id: "scan:10.0.1.4".to_owned(),
            severity,
            title: "Port scan of node-1".to_owned(),
            detail: "20+ ports probed in 60s".to_owned(),
            first_seen_unix_ms: 0,
            last_seen_unix_ms: 0,
            labels: HashMap::from([("node".to_owned(), "node-1".to_owned())]),
            explanation: Some("Likely a scan.".to_owned()),
        }
    }

    #[test]
    fn severity_gate_parses_and_filters() {
        assert_eq!(MinSeverity::parse("info"), MinSeverity::Info);
        assert_eq!(MinSeverity::parse("warn"), MinSeverity::Warning);
        assert_eq!(MinSeverity::parse("CRITICAL"), MinSeverity::Critical);
        assert_eq!(MinSeverity::parse("bogus"), MinSeverity::Info);
        assert_eq!(MinSeverity::parse(""), MinSeverity::Info);
        assert!(MinSeverity::Info.allows(Severity::Info));
        assert!(!MinSeverity::Warning.allows(Severity::Info));
        assert!(MinSeverity::Warning.allows(Severity::Warning));
        assert!(MinSeverity::Warning.allows(Severity::Critical));
        assert!(!MinSeverity::Critical.allows(Severity::Warning));
        assert!(MinSeverity::Critical.allows(Severity::Critical));
    }

    #[test]
    fn webhook_payload_names_source_and_alert() {
        let body = webhook_payload(&alert(Severity::Warning));
        assert_eq!(body["source"], "mist");
        assert_eq!(body["alert"]["id"], "scan:10.0.1.4");
        assert_eq!(body["alert"]["severity"], "warning");
    }

    #[test]
    fn slack_text_says_what_and_why() {
        let text = slack_text(&alert(Severity::Critical));
        assert!(text.contains("[Critical] Port scan of node-1"));
        assert!(text.contains("20+ ports probed in 60s"));
        assert!(text.contains("Labels: node=node-1"));
        assert!(text.contains("Why: Likely a scan."));
        let mut bare = alert(Severity::Info);
        bare.explanation = None;
        bare.labels.clear();
        let text = slack_text(&bare);
        assert!(!text.contains("Why:"));
        assert!(text.contains("Labels: -"));
    }

    #[derive(Clone)]
    struct StubState {
        hits: Arc<AtomicUsize>,
    }

    async fn stub_server() -> (String, StubState) {
        use axum::extract::State;
        use axum::http::HeaderMap;
        async fn webhook(
            State(state): State<StubState>,
            headers: HeaderMap,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> axum::http::StatusCode {
            assert_eq!(
                headers.get("authorization").and_then(|v| v.to_str().ok()),
                Some("Bearer hook-secret")
            );
            assert_eq!(body["source"], "mist");
            assert_eq!(body["alert"]["title"], "Port scan of node-1");
            state.hits.fetch_add(1, Ordering::Relaxed);
            axum::http::StatusCode::OK
        }
        async fn slack(
            State(state): State<StubState>,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> axum::http::StatusCode {
            let text = body["text"].as_str().unwrap_or_default();
            assert!(text.contains("Port scan of node-1"));
            assert!(text.contains("Why: Likely a scan."));
            state.hits.fetch_add(1, Ordering::Relaxed);
            axum::http::StatusCode::OK
        }
        async fn fail() -> axum::http::StatusCode {
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        }
        let state = StubState {
            hits: Arc::new(AtomicUsize::new(0)),
        };
        let app = axum::Router::new()
            .route("/hook", axum::routing::post(webhook))
            .route("/slack", axum::routing::post(slack))
            .route("/fail", axum::routing::post(fail))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub");
        let addr = listener.local_addr().expect("stub addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve stub");
        });
        (format!("http://{addr}"), state)
    }

    #[tokio::test]
    async fn notifiers_deliver_to_stubs() {
        let (base, state) = stub_server().await;
        let webhook = WebhookNotifier::new(format!("{base}/hook"), Some("hook-secret".to_owned()));
        assert_eq!(webhook.name(), "webhook");
        assert!(webhook.notify(&alert(Severity::Warning)).await);
        let slack = SlackNotifier::new(format!("{base}/slack"));
        assert_eq!(slack.name(), "slack");
        assert!(slack.notify(&alert(Severity::Critical)).await);
        assert_eq!(state.hits.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn notifier_reports_failure_open() {
        let (base, _) = stub_server().await;
        let webhook = WebhookNotifier::new(format!("{base}/fail"), None);
        assert!(!webhook.notify(&alert(Severity::Info)).await);
    }

    #[tokio::test]
    async fn config_notifies_once_and_above_gate() {
        let (base, state) = stub_server().await;
        let config = NotifyConfig {
            targets: vec![NotifierKind::Webhook(WebhookNotifier::new(
                format!("{base}/hook"),
                Some("hook-secret".to_owned()),
            ))],
            min_severity: MinSeverity::Warning,
        };
        let metrics = crate::metrics::Metrics::default();
        // Below gate: silent.
        config
            .notify_if_new(&alert(Severity::Info), 1, &metrics)
            .await;
        // Re-fire: silent.
        config
            .notify_if_new(&alert(Severity::Warning), 2, &metrics)
            .await;
        assert_eq!(state.hits.load(Ordering::Relaxed), 0);
        // First fire above gate: delivered.
        config
            .notify_if_new(&alert(Severity::Critical), 1, &metrics)
            .await;
        assert_eq!(state.hits.load(Ordering::Relaxed), 1);
    }
}
