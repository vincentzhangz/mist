//! Alert webhook: mist-api POSTs analyzer findings; the operator mirrors
//! them as `AnomalyAlert` custom resources, deduplicated by alert id.

use std::{collections::BTreeMap, sync::Arc};

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::post,
};
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use mist_types::Alert;

use crate::crd::{AlertSeverity, AlertState, AnomalyAlert, AnomalyAlertSpec, AnomalyAlertStatus};

/// Analyzer label keys carrying workload identity.
pub const LABEL_NAMESPACE: &str = "namespace";
pub const LABEL_POD: &str = "pod";

#[derive(Clone)]
pub struct WebhookState {
    pub client: kube::Client,
    pub namespace: String,
}

#[derive(Debug, thiserror::Error)]
pub enum WebhookError {
    #[error("kubernetes error: {0}")]
    Kube(#[from] kube::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

impl IntoResponse for WebhookError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self {
            Self::Kube(_) | Self::Serde(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (
            status,
            Json(serde_json::json!({ "error": self.to_string() })),
        )
            .into_response()
    }
}

pub fn router(state: WebhookState) -> Router {
    Router::new()
        .route("/alerts", post(receive_alert))
        .with_state(Arc::new(state))
}

async fn receive_alert(
    State(state): State<Arc<WebhookState>>,
    Json(alert): Json<Alert>,
) -> Result<StatusCode, WebhookError> {
    let api: Api<AnomalyAlert> = Api::namespaced(state.client.clone(), &state.namespace);
    let name = alert_cr_name(&alert.id);
    // The API server ignores `.status` on create/replace (status subresource),
    // so it is always written with a dedicated status patch below.
    if let Some(existing) = api.get_opt(&name).await? {
        let mut merged = existing.clone();
        merged.spec = alert_spec(&alert);
        api.replace(&name, &PostParams::default(), &merged).await?;
        let status = merge_status(existing.status.as_ref(), &alert);
        api.patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "status": status })),
        )
        .await?;
    } else {
        let reported = AnomalyAlert {
            metadata: ObjectMeta {
                name: Some(name.clone()),
                labels: Some(alert_labels(&alert)),
                ..Default::default()
            },
            spec: alert_spec(&alert),
            status: None,
        };
        api.create(&PostParams::default(), &reported).await?;
        let status = fresh_status(&alert);
        api.patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "status": status })),
        )
        .await?;
    }
    Ok(StatusCode::ACCEPTED)
}

/// Build the CR spec from an analyzer alert.
fn alert_spec(alert: &Alert) -> AnomalyAlertSpec {
    AnomalyAlertSpec {
        alert_id: alert.id.clone(),
        severity: match alert.severity {
            mist_types::Severity::Info => AlertSeverity::Info,
            mist_types::Severity::Warning => AlertSeverity::Warning,
            mist_types::Severity::Critical => AlertSeverity::Critical,
        },
        title: alert.title.clone(),
        detail: alert.detail.clone(),
        explanation: alert.explanation.clone(),
        workload_namespace: alert.labels.get(LABEL_NAMESPACE).cloned(),
        workload_name: alert.labels.get(LABEL_POD).cloned(),
        attributes: alert
            .labels
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect(),
    }
}

fn fresh_status(alert: &Alert) -> AnomalyAlertStatus {
    AnomalyAlertStatus {
        state: AlertState::Firing,
        first_seen_unix_ms: ms(alert.first_seen_unix_ms),
        last_seen_unix_ms: ms(alert.last_seen_unix_ms),
        occurrences: 1,
    }
}

/// Fold a re-reported alert into existing status: widen the window, bump the
/// count, and re-fire (a resolved alert that re-fires is firing again).
fn merge_status(existing: Option<&AnomalyAlertStatus>, alert: &Alert) -> AnomalyAlertStatus {
    match existing {
        Some(status) => AnomalyAlertStatus {
            state: AlertState::Firing,
            first_seen_unix_ms: status.first_seen_unix_ms.min(ms(alert.first_seen_unix_ms)),
            last_seen_unix_ms: status.last_seen_unix_ms.max(ms(alert.last_seen_unix_ms)),
            occurrences: status.occurrences.saturating_add(1),
        },
        None => fresh_status(alert),
    }
}

/// u64 millis saturate into the CRD's int64 millis (overflow only past the
/// year 292 million).
fn ms(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// CR labels carrying severity + workload identity.
fn alert_labels(alert: &Alert) -> BTreeMap<String, String> {
    let severity = match alert.severity {
        mist_types::Severity::Info => "info",
        mist_types::Severity::Warning => "warning",
        mist_types::Severity::Critical => "critical",
    };
    let mut labels = BTreeMap::from([("mist.io/severity".to_owned(), severity.to_owned())]);
    if let Some(namespace) = alert.labels.get(LABEL_NAMESPACE) {
        labels.insert(
            "mist.io/namespace".to_owned(),
            sanitize_label_value(namespace),
        );
    }
    if let Some(pod) = alert.labels.get(LABEL_POD) {
        labels.insert("mist.io/pod".to_owned(), sanitize_label_value(pod));
    }
    labels
}

/// Valid CR name for an alert id: lowercase alphanumerics collapsed with
/// single dashes (DNS subdomain, at most 200 chars, never empty).
pub fn alert_cr_name(id: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = true; // trim leading dashes
    for ch in id.chars().flat_map(char::to_lowercase) {
        if out.len() >= 200 {
            break;
        }
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        out.push_str("alert");
    }
    out
}

/// Sanitize to the label-value alphabet (`[A-Za-z0-9-_.]`, at most 63 chars,
/// alphanumeric ends; empty stays empty, which is a valid label value).
fn sanitize_label_value(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if out.len() >= 63 {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches(|char| matches!(char, '-' | '_' | '.'))
        .to_owned()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use mist_types::Severity;

    use super::*;

    fn alert() -> Alert {
        Alert {
            id: "scan:10.0.1.4".to_owned(),
            severity: Severity::Warning,
            title: "Port scan detected".to_owned(),
            detail: "many ports probed".to_owned(),
            first_seen_unix_ms: 1_700_000_000_000,
            last_seen_unix_ms: 1_700_000_060_000,
            labels: HashMap::from([
                (LABEL_NAMESPACE.to_owned(), "prod".to_owned()),
                (LABEL_POD.to_owned(), "api-0".to_owned()),
            ]),
            explanation: None,
        }
    }

    #[test]
    fn names_are_dns_safe_and_stable() {
        assert_eq!(alert_cr_name("scan:10.0.1.4"), "scan-10-0-1-4");
        assert_eq!(alert_cr_name("  Weird__ID!! "), "weird-id");
        assert_eq!(alert_cr_name("!!!"), "alert");
        assert_eq!(alert_cr_name(""), "alert");
        let long = "a".repeat(300);
        assert_eq!(alert_cr_name(&long).len(), 200);
    }

    #[test]
    fn label_values_stay_valid() {
        assert_eq!(sanitize_label_value("prod"), "prod");
        assert_eq!(sanitize_label_value("api-0.xyz_1"), "api-0.xyz_1");
        assert_eq!(sanitize_label_value("-bad-"), "bad");
        assert_eq!(sanitize_label_value("has space"), "has-space");
        assert_eq!(sanitize_label_value(""), "");
        assert_eq!(sanitize_label_value("x".repeat(100).as_str()).len(), 63);
    }

    #[test]
    fn payload_without_explanation_still_accepted() {
        // Older analyzers omit `explanation` (or send null); the webhook
        // must keep accepting those payloads.
        for body in [
            r#"{
                "id": "scan:10.0.1.4",
                "severity": "warning",
                "title": "Port scan detected",
                "detail": "many ports probed",
                "first_seen_unix_ms": 1700000000000,
                "last_seen_unix_ms": 1700000060000,
                "labels": {"namespace": "prod", "pod": "api-0"}
            }"#,
            r#"{
                "id": "scan:10.0.1.4",
                "severity": "warning",
                "title": "Port scan detected",
                "detail": "many ports probed",
                "first_seen_unix_ms": 1700000000000,
                "last_seen_unix_ms": 1700000060000,
                "labels": {"namespace": "prod", "pod": "api-0"},
                "explanation": null
            }"#,
        ] {
            let alert: Alert = serde_json::from_str(body).expect("compat payload must parse");
            assert_eq!(alert.explanation, None);
            assert_eq!(alert_spec(&alert).explanation, None);
        }
    }

    #[test]
    fn spec_carries_explanation_when_present() {
        let alert = Alert {
            explanation: Some("likely backup traffic".to_owned()),
            ..alert()
        };
        assert_eq!(
            alert_spec(&alert).explanation.as_deref(),
            Some("likely backup traffic")
        );
    }

    #[test]
    fn spec_carries_alert_fields() {
        let spec = alert_spec(&alert());
        assert_eq!(spec.alert_id, "scan:10.0.1.4");
        assert_eq!(spec.severity, AlertSeverity::Warning);
        assert_eq!(spec.workload_namespace.as_deref(), Some("prod"));
        assert_eq!(spec.workload_name.as_deref(), Some("api-0"));
        assert_eq!(spec.attributes.len(), 2);
        let labels = alert_labels(&alert());
        assert_eq!(labels["mist.io/severity"], "warning");
        assert_eq!(labels["mist.io/namespace"], "prod");
        assert_eq!(labels["mist.io/pod"], "api-0");
    }

    #[test]
    fn status_merges_windows_and_counts() {
        let fresh = fresh_status(&alert());
        assert_eq!(fresh.state, AlertState::Firing);
        assert_eq!(fresh.occurrences, 1);
        let again = Alert {
            first_seen_unix_ms: 1_700_000_030_000,
            last_seen_unix_ms: 1_700_000_120_000,
            ..alert()
        };
        let merged = merge_status(Some(&fresh), &again);
        assert_eq!(merged.first_seen_unix_ms, 1_700_000_000_000);
        assert_eq!(merged.last_seen_unix_ms, 1_700_000_120_000);
        assert_eq!(merged.occurrences, 2);
        assert_eq!(merge_status(None, &alert()), fresh);
    }
}
