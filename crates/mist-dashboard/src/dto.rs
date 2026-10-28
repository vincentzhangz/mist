//! Local serde DTOs for the mist HTTP/WS API.
//!
//! FE/BE boundary duplication is intentional: this crate must NOT depend on
//! `mist-types`. These shapes mirror the API contract documented for
//! `/api/auth/login`, `/api/flows`, `/api/alerts*`, and `/api/ws`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// Five-tuple identifying a flow.
///
/// `protocol` is the IP protocol number (`IPPROTO_*`, e.g. 6 = TCP) exactly
/// as the API serializes it. Use [`protocol_name`] for display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowKey {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: u8,
}

/// Human-readable name for an IP protocol number.
#[must_use]
pub fn protocol_name(protocol: u8) -> String {
    match protocol {
        1 => "icmp".to_owned(),
        6 => "tcp".to_owned(),
        17 => "udp".to_owned(),
        other => format!("ip-{other}"),
    }
}

/// A Kubernetes pod reference (`namespace/name`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodRef {
    pub namespace: String,
    pub name: String,
}

/// Packet direction relative to the observed node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Ingress,
    Egress,
}

/// One flow record as returned by `GET /api/flows`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRecord {
    pub key: FlowKey,
    pub direction: Direction,
    pub bytes: u64,
    pub packets: u64,
    pub start_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub node: String,
    pub src_pod: Option<PodRef>,
    pub dst_pod: Option<PodRef>,
}

impl FlowRecord {
    /// Stable row key for keyed list rendering.
    #[must_use]
    pub fn row_key(&self) -> String {
        format!(
            "{}-{}-{}-{}-{}-{:?}",
            self.node,
            self.key.src_ip,
            self.key.src_port,
            self.key.dst_ip,
            self.key.dst_port,
            self.direction,
        )
    }
}

/// Alert severity as returned by the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// Alert lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AlertState {
    Firing,
    Resolved,
}

/// One alert as returned by `GET /api/alerts` and `GET /api/alerts/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertView {
    pub id: String,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub first_seen_unix_ms: u64,
    pub last_seen_unix_ms: u64,
    pub labels: BTreeMap<String, String>,
    /// Missing on older API payloads; absent means "no explanation".
    #[serde(default)]
    pub explanation: Option<String>,
    pub state: AlertState,
    pub occurrences: u64,
}

/// Body sent to `POST /api/auth/login`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Success body of `POST /api/auth/login`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResponse {
    pub token: String,
    pub email: String,
}

/// Error body returned with non-2xx statuses (e.g. 401 from login).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

/// A message received over `GET /api/ws`.
///
/// The wire format is a JSON object with a `type` discriminator:
/// `{"type":"flows","flows":[...]}` or `{"type":"alert","alert":{...}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WsEvent {
    /// A batch of live flow records.
    #[serde(rename = "flows")]
    Flows { flows: Vec<FlowRecord> },
    /// A single new/updated alert.
    #[serde(rename = "alert")]
    Alert { alert: AlertView },
}

/// Parse one websocket text frame.
///
/// Returns `Ok(None)` for frames whose `type` is unknown so that future
/// server-side message kinds do not break the dashboard.
///
/// # Errors
///
/// Returns `Err` when `text` is not valid JSON or is JSON of an unexpected
/// shape for a known event type.
pub fn parse_ws_event(text: &str) -> Result<Option<WsEvent>, String> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("invalid ws frame: {e}"))?;
    let kind = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("");
    match kind {
        "flows" | "alert" => serde_json::from_value::<WsEvent>(value)
            .map(Some)
            .map_err(|e| format!("invalid ws event: {e}")),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLOW_JSON: &str = r#"{
        "key": {"src_ip":"10.0.0.1","src_port":54321,"dst_ip":"10.0.0.2","dst_port":443,"protocol":6},
        "direction":"egress",
        "bytes": 1024,
        "packets": 8,
        "start_unix_ms": 1700000000000,
        "last_seen_unix_ms": 1700000060000,
        "node": "node-1",
        "src_pod": {"namespace":"default","name":"web-0"},
        "dst_pod": null
    }"#;

    const ALERT_JSON: &str = r#"{
        "id": "default/web-0/high-egress",
        "severity": "warning",
        "title": "High egress rate",
        "detail": "egress exceeds threshold",
        "first_seen_unix_ms": 1700000000000,
        "last_seen_unix_ms": 1700000060000,
        "labels": {"node":"node-1","namespace":"default"},
        "explanation": "Likely backup traffic.",
        "state": "firing",
        "occurrences": 3
    }"#;

    #[test]
    fn flow_record_roundtrip() {
        let flow: FlowRecord = serde_json::from_str(FLOW_JSON).expect("fixture must parse");
        assert_eq!(flow.direction, Direction::Egress);
        assert_eq!(flow.key.src_port, 54321);
        assert_eq!(flow.bytes, 1024);
        assert_eq!(flow.packets, 8);
        assert_eq!(
            flow.src_pod,
            Some(PodRef {
                namespace: "default".to_owned(),
                name: "web-0".to_owned(),
            })
        );
        assert_eq!(flow.dst_pod, None);
        let back = serde_json::to_value(&flow).expect("must serialize");
        let again: FlowRecord = serde_json::from_value(back).expect("must roundtrip");
        assert_eq!(flow, again);
        assert_ne!(flow.row_key(), "");
    }

    #[test]
    fn flow_list_roundtrip() {
        let flows: Vec<FlowRecord> =
            serde_json::from_str(&format!("[{FLOW_JSON}]")).expect("fixture list must parse");
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].node, "node-1");
    }

    #[test]
    fn alert_view_roundtrip() {
        let alert: AlertView = serde_json::from_str(ALERT_JSON).expect("fixture must parse");
        assert_eq!(alert.severity, Severity::Warning);
        assert_eq!(alert.state, AlertState::Firing);
        assert_eq!(alert.occurrences, 3);
        assert_eq!(alert.explanation.as_deref(), Some("Likely backup traffic."));
        assert_eq!(alert.labels.get("node").map(String::as_str), Some("node-1"));
        // ids contain `/` and must survive serde untouched
        assert_eq!(alert.id, "default/web-0/high-egress");
        let back = serde_json::to_value(&alert).expect("must serialize");
        let again: AlertView = serde_json::from_value(back).expect("must roundtrip");
        assert_eq!(alert, again);
    }

    #[test]
    fn alert_without_explanation() {
        let json = ALERT_JSON.replace(
            r#""explanation": "Likely backup traffic.","#,
            r#""explanation": null,"#,
        );
        let alert: AlertView = serde_json::from_str(&json).expect("null explanation must parse");
        assert_eq!(alert.explanation, None);
    }

    #[test]
    fn alert_with_missing_explanation_key() {
        // Older API payloads omit the key entirely; it must default to None
        // so the detail panel simply renders no explanation section.
        let json = ALERT_JSON.replace(r#""explanation": "Likely backup traffic.","#, "");
        let alert: AlertView = serde_json::from_str(&json).expect("missing explanation must parse");
        assert_eq!(alert.explanation, None);
    }

    #[test]
    fn login_shapes() {
        let req = LoginRequest {
            email: "admin@example.com".to_owned(),
            password: "secret".to_owned(),
        };
        assert_eq!(
            serde_json::to_value(&req).expect("must serialize"),
            serde_json::json!({"email": "admin@example.com", "password": "secret"})
        );
        let resp: LoginResponse =
            serde_json::from_str(r#"{"token":"jwt.here","email":"admin@example.com"}"#)
                .expect("login response must parse");
        assert_eq!(resp.token, "jwt.here");
        let err: ErrorBody = serde_json::from_str(r#"{"error":"invalid credentials"}"#)
            .expect("error body must parse");
        assert_eq!(err.error, "invalid credentials");
    }

    #[test]
    fn ws_flows_event() {
        let text = format!(r#"{{"type":"flows","flows":[{FLOW_JSON}]}}"#);
        let event = parse_ws_event(&text)
            .expect("must parse")
            .expect("must be Some");
        match event {
            WsEvent::Flows { flows } => {
                assert_eq!(flows.len(), 1);
                assert_eq!(flows[0].key.protocol, 6);
                assert_eq!(protocol_name(6), "tcp");
                assert_eq!(protocol_name(17), "udp");
                assert_eq!(protocol_name(2), "ip-2");
            }
            WsEvent::Alert { .. } => panic!("expected flows event"),
        }
    }

    #[test]
    fn ws_alert_event() {
        let text = format!(r#"{{"type":"alert","alert":{ALERT_JSON}}}"#);
        let event = parse_ws_event(&text)
            .expect("must parse")
            .expect("must be Some");
        match event {
            WsEvent::Alert { alert } => {
                assert_eq!(alert.id, "default/web-0/high-egress");
            }
            WsEvent::Flows { .. } => panic!("expected alert event"),
        }
    }

    #[test]
    fn ws_unknown_type_is_ignored() {
        assert_eq!(
            parse_ws_event(r#"{"type":"stats","n":1}"#).expect("must not fail"),
            None
        );
        assert_eq!(
            parse_ws_event(r#"{"no_type":true}"#).expect("must not fail"),
            None
        );
    }

    #[test]
    fn ws_invalid_json_fails() {
        assert!(parse_ws_event("not json").is_err());
        assert!(parse_ws_event(r#"{"type":"flows"}"#).is_err());
    }

    #[test]
    fn ws_event_serializes_with_tag() {
        let flow: FlowRecord = serde_json::from_str(FLOW_JSON).expect("fixture must parse");
        let value =
            serde_json::to_value(&WsEvent::Flows { flows: vec![flow] }).expect("must serialize");
        assert_eq!(
            value.get("type").and_then(serde_json::Value::as_str),
            Some("flows")
        );
    }
}
