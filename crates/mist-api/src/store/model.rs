//! Storage domain types: filters, pages, views, and their mappings.

use mist_types::{Alert, FlowRecord, Severity, TrafficDirection};
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
    pub(crate) fn parse(value: &str) -> Option<Self> {
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
    /// Upper bound, inclusive: only rows with `last_seen_ms <= before_ms`.
    /// Inclusive so millisecond ties at the page edge repeat (deduped by
    /// row key) instead of being skipped.
    pub before_ms: Option<u64>,
    pub limit: i64,
}

/// One page of `GET /api/flows`: newest-first rows plus the cursor for
/// the next (older) page, or `None` when this page came up short.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FlowsPage {
    pub flows: Vec<FlowRecord>,
    pub next_cursor: Option<u64>,
}

/// Filter for `GET /api/alerts`. `severity` is the lowercase stored form
/// (`info`/`warning`/`critical`); the handler normalizes the query param.
/// `before_ms` is the inclusive upper bound, mirroring [`FlowFilter`]:
/// rows with `last_seen_ms <= before_ms`, so millisecond ties at the page
/// edge repeat (deduped by id) instead of being skipped.
#[derive(Debug, Clone)]
pub struct AlertFilter {
    pub state: Option<String>,
    pub severity: Option<String>,
    pub before_ms: Option<u64>,
    pub limit: i64,
}

/// One page of `GET /api/alerts`, mirroring [`FlowsPage`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AlertsPage {
    pub alerts: Vec<AlertView>,
    pub next_cursor: Option<u64>,
}

pub(crate) fn direction_str(direction: TrafficDirection) -> &'static str {
    match direction {
        TrafficDirection::Ingress => "ingress",
        TrafficDirection::Egress => "egress",
    }
}

pub(crate) fn severity_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Critical => "critical",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_helpers::*;

    #[test]
    fn silence_window_is_half_open() {
        let rule = test_silence();
        let alert = test_alert("scan:10.0.1.4");
        assert!(!silence_matches(&rule, &alert, 999));
        assert!(silence_matches(&rule, &alert, 1_000));
        assert!(silence_matches(&rule, &alert, 1_999));
        assert!(!silence_matches(&rule, &alert, 2_000));
    }
    #[test]
    fn silence_matchers_all_must_hit() {
        let mut alert = test_alert("scan:10.0.1.4");
        alert.title = "Port scan of node-1".to_owned();
        alert.labels.insert("node".to_owned(), "node-1".to_owned());
        let mut rule = test_silence();
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
}
