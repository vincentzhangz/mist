//! OpenAI-compatible LLM explainer for fired alerts.
//!
//! Disabled by default: without LLM config the analyzer keeps the
//! [`NoopExplainer`](crate::analyzer::NoopExplainer) stub (`explainer=none`).
//! Any `OpenAI`-compatible chat-completions endpoint works — a cloud
//! provider or a keyless in-cluster server (`Ollama`, `vLLM`) via `LLM_BASE_URL`.
//!
//! The explainer is fail-open: timeouts, non-2xx statuses, and malformed
//! payloads all yield `None`, and the store keeps any prior explanation.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::time::Duration;

use mist_types::{Alert, FlowRecord, TrafficDirection};

use crate::analyzer::{Explainer, NoopExplainer};

/// Default chat-completions root; `LLM_BASE_URL` overrides (e.g. Ollama).
pub const DEFAULT_BASE_URL: &str = "https://api.openai.com/v1";
/// Default model name; `LLM_MODEL` overrides.
pub const DEFAULT_MODEL: &str = "gpt-4o-mini";
/// Top flows (by bytes) included in the prompt.
const MAX_FLOWS_IN_PROMPT: usize = 8;
/// Prompt cap in chars, to bound cost on wide batches.
const MAX_PROMPT_CHARS: usize = 4_000;
/// Stored explanation cap in chars, to bound store rows.
const MAX_EXPLANATION_CHARS: usize = 2_000;
/// Per-request LLM timeout; the analyzer must never stall on the model.
const REQUEST_TIMEOUT_SECS: u64 = 15;
/// Completion cap; explanations should be two to three sentences.
const MAX_TOKENS: u32 = 300;

const SYSTEM_PROMPT: &str = "You are a Kubernetes network security analyst. \
    Explain the alert in two to three sentences of plain text (no markdown): \
    what the traffic pattern means and one concrete next step for the operator.";

/// LLM connection settings. The key is optional so keyless local servers work.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
}

impl LlmConfig {
    /// Build config from explicit parts. Returns `None` (disabled) unless an
    /// API key or an explicit base URL is provided; empty strings are ignored.
    #[must_use]
    pub fn from_parts(
        base_url: Option<String>,
        model: Option<String>,
        api_key: Option<String>,
    ) -> Option<Self> {
        fn clean(value: Option<String>) -> Option<String> {
            value.map(|v| v.trim().to_owned()).filter(|v| !v.is_empty())
        }
        let base_url = clean(base_url);
        let api_key = clean(api_key);
        if base_url.is_none() && api_key.is_none() {
            return None;
        }
        Some(Self {
            base_url: base_url.unwrap_or_else(|| DEFAULT_BASE_URL.to_owned()),
            model: clean(model).unwrap_or_else(|| DEFAULT_MODEL.to_owned()),
            api_key,
        })
    }

    /// Read `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` from the environment.
    #[must_use]
    pub fn from_env() -> Option<Self> {
        Self::from_parts(
            std::env::var("LLM_BASE_URL").ok(),
            std::env::var("LLM_MODEL").ok(),
            std::env::var("LLM_API_KEY").ok(),
        )
    }
}

/// Chat-completions endpoint for a base URL. A base already pointing at
/// `/chat/completions` is used as-is; otherwise the path is appended.
#[must_use]
pub fn completions_endpoint(base_url: &str) -> String {
    let trimmed = base_url.trim_end_matches('/');
    if trimmed.ends_with("/chat/completions") {
        trimmed.to_owned()
    } else {
        format!("{trimmed}/chat/completions")
    }
}

/// Human-readable protocol name for the prompt (mirrors the dashboard).
#[must_use]
pub fn protocol_name(protocol: u8) -> String {
    match protocol {
        1 => "icmp".to_owned(),
        6 => "tcp".to_owned(),
        17 => "udp".to_owned(),
        other => format!("ip-{other}"),
    }
}

fn pod_label(pod: Option<&mist_types::PodRef>) -> String {
    pod.map_or_else(|| "-".to_owned(), |p| format!("{}/{}", p.namespace, p.name))
}

fn truncate_chars(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    text.chars().take(max).collect()
}

/// `key=value` label block for the prompt, or `-` when the alert has none.
fn format_labels(labels: &HashMap<String, String>) -> String {
    if labels.is_empty() {
        return "-".to_owned();
    }
    let mut pairs: Vec<(&String, &String)> = labels.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    pairs
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// One prompt line per flow, top `MAX_FLOWS_IN_PROMPT` by bytes.
fn format_flows(flows: &[FlowRecord]) -> String {
    if flows.is_empty() {
        return "-".to_owned();
    }
    let mut top: Vec<&FlowRecord> = flows.iter().collect();
    top.sort_by_key(|flow| Reverse(flow.bytes));
    top.truncate(MAX_FLOWS_IN_PROMPT);
    top.iter()
        .map(|flow| {
            let direction = match flow.direction {
                TrafficDirection::Ingress => "ingress",
                TrafficDirection::Egress => "egress",
            };
            format!(
                "{}:{} -> {}:{} {} {direction} bytes={} packets={} node={} src={} dst={}",
                flow.key.src_ip,
                flow.key.src_port,
                flow.key.dst_ip,
                flow.key.dst_port,
                protocol_name(flow.key.protocol),
                flow.bytes,
                flow.packets,
                flow.node,
                pod_label(flow.src_pod.as_ref()),
                pod_label(flow.dst_pod.as_ref()),
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// User prompt for one alert plus its batch context, capped in length.
#[must_use]
pub fn build_user_prompt(alert: &Alert, flows: &[FlowRecord]) -> String {
    let prompt = format!(
        "Alert [{}] {} ({:?}): {}\nLabels: {}\nFlows (top by bytes):\n{}",
        alert.id,
        alert.title,
        alert.severity,
        alert.detail,
        format_labels(&alert.labels),
        format_flows(flows),
    );
    truncate_chars(&prompt, MAX_PROMPT_CHARS)
}

/// Chat-completions request body for the configured model.
#[must_use]
pub fn request_body(config: &LlmConfig, alert: &Alert, flows: &[FlowRecord]) -> serde_json::Value {
    serde_json::json!({
        "model": config.model,
        "temperature": 0.2,
        "max_tokens": MAX_TOKENS,
        "messages": [
            { "role": "system", "content": SYSTEM_PROMPT },
            { "role": "user", "content": build_user_prompt(alert, flows) },
        ],
    })
}

/// Extract the assistant text from a chat-completions response. Anything
/// unexpected (error payloads, missing fields, blank content) yields `None`.
#[must_use]
pub fn parse_explanation(body: &serde_json::Value) -> Option<String> {
    let content = body
        .get("choices")?
        .get(0)?
        .get("message")?
        .get("content")?
        .as_str()?;
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(truncate_chars(trimmed, MAX_EXPLANATION_CHARS))
}

/// [`Explainer`] backed by an OpenAI-compatible chat-completions endpoint.
/// Every failure mode returns `None` (fail-open) after a warning log.
#[derive(Debug, Clone)]
pub struct LlmExplainer {
    client: reqwest::Client,
    config: LlmConfig,
}

impl LlmExplainer {
    #[must_use]
    pub fn new(config: LlmConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
        }
    }
}

impl Explainer for LlmExplainer {
    fn name(&self) -> &'static str {
        "llm"
    }

    async fn explanation_for(&self, alert: &Alert, flows: &[FlowRecord]) -> Option<String> {
        let mut request = self
            .client
            .post(completions_endpoint(&self.config.base_url))
            .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
            .json(&request_body(&self.config, alert, flows));
        if let Some(key) = self.config.api_key.as_deref() {
            request = request.bearer_auth(key);
        }
        let response = match request.send().await {
            Ok(response) => response,
            Err(err) => {
                tracing::warn!(alert_id = %alert.id, "LLM request failed: {err}");
                return None;
            }
        };
        let status = response.status();
        if !status.is_success() {
            tracing::warn!(alert_id = %alert.id, %status, "LLM request rejected");
            return None;
        }
        match response.json::<serde_json::Value>().await {
            Ok(body) => parse_explanation(&body).or_else(|| {
                tracing::warn!(alert_id = %alert.id, "LLM response had no usable content");
                None
            }),
            Err(err) => {
                tracing::warn!(alert_id = %alert.id, "LLM response was not JSON: {err}");
                None
            }
        }
    }
}

/// Runtime explainer selection: LLM when configured, stub otherwise.
/// Exists because `run_analyzer` takes one concrete `impl Explainer`.
#[derive(Debug, Clone)]
pub enum ExplainerKind {
    Stub(NoopExplainer),
    Llm(LlmExplainer),
}

impl Explainer for ExplainerKind {
    fn name(&self) -> &'static str {
        match self {
            Self::Stub(inner) => inner.name(),
            Self::Llm(inner) => inner.name(),
        }
    }

    async fn explanation_for(&self, alert: &Alert, flows: &[FlowRecord]) -> Option<String> {
        match self {
            Self::Stub(inner) => inner.explanation_for(alert, flows).await,
            Self::Llm(inner) => inner.explanation_for(alert, flows).await,
        }
    }
}

/// Select the explainer from `LLM_*` env. The API key is never logged.
#[must_use]
pub fn explainer_from_env() -> ExplainerKind {
    if let Some(config) = LlmConfig::from_env() {
        tracing::info!(
            base_url = %config.base_url,
            model = %config.model,
            "LLM explainer enabled"
        );
        ExplainerKind::Llm(LlmExplainer::new(config))
    } else {
        tracing::info!("LLM env unset; alert explanations disabled");
        ExplainerKind::Stub(NoopExplainer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mist_types::{FlowKey, Severity};

    fn alert() -> Alert {
        Alert {
            id: "scan:10.0.1.4".to_owned(),
            severity: Severity::Warning,
            title: "Port scan of node-1".to_owned(),
            detail: "20+ ports probed in 60s".to_owned(),
            first_seen_unix_ms: 0,
            last_seen_unix_ms: 0,
            labels: HashMap::from([("node".to_owned(), "node-1".to_owned())]),
            explanation: None,
        }
    }

    fn flow(bytes: u64) -> FlowRecord {
        use std::net::{IpAddr, Ipv4Addr};
        FlowRecord {
            key: FlowKey {
                src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                src_port: 54321,
                dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                dst_port: 443,
                protocol: 6,
            },
            direction: TrafficDirection::Egress,
            bytes,
            packets: 8,
            start_unix_ms: 0,
            last_seen_unix_ms: 0,
            node: "node-1".to_owned(),
            src_pod: Some(mist_types::PodRef {
                namespace: "default".to_owned(),
                name: "web-0".to_owned(),
                labels: std::collections::HashMap::new(),
            }),
            dst_pod: None,
        }
    }

    #[test]
    fn config_requires_key_or_explicit_base_url() {
        assert_eq!(LlmConfig::from_parts(None, None, None), None);
        assert_eq!(
            LlmConfig::from_parts(Some(String::new()), None, Some("  ".to_owned())),
            None
        );
        let keyed =
            LlmConfig::from_parts(None, None, Some("sk-x".to_owned())).expect("key enables");
        assert_eq!(keyed.base_url, DEFAULT_BASE_URL);
        assert_eq!(keyed.model, DEFAULT_MODEL);
        assert_eq!(keyed.api_key.as_deref(), Some("sk-x"));
        // Keyless local server: explicit base URL alone enables.
        let local = LlmConfig::from_parts(
            Some("http://ollama:11434/v1".to_owned()),
            Some("llama3".to_owned()),
            None,
        )
        .expect("base url enables");
        assert_eq!(local.base_url, "http://ollama:11434/v1");
        assert_eq!(local.model, "llama3");
        assert_eq!(local.api_key, None);
    }

    #[test]
    fn endpoint_appends_path_once() {
        assert_eq!(
            completions_endpoint("https://api.openai.com/v1"),
            "https://api.openai.com/v1/chat/completions"
        );
        assert_eq!(
            completions_endpoint("http://ollama:11434/v1/"),
            "http://ollama:11434/v1/chat/completions"
        );
        assert_eq!(
            completions_endpoint("http://x/v1/chat/completions"),
            "http://x/v1/chat/completions"
        );
    }

    #[test]
    fn prompt_contains_alert_and_top_flows() {
        let flows = vec![flow(100), flow(9_000)];
        let prompt = build_user_prompt(&alert(), &flows);
        assert!(prompt.contains("Port scan of node-1"));
        assert!(prompt.contains("node=node-1"));
        assert!(prompt.contains("bytes=9000"));
        assert!(prompt.contains("default/web-0"));
        assert!(prompt.len() <= MAX_PROMPT_CHARS);
        let empty = build_user_prompt(&alert(), &[]);
        assert!(empty.contains("Flows (top by bytes):\n-"));
    }

    #[test]
    fn request_body_pins_model_and_temperature() {
        let config = LlmConfig {
            base_url: "http://x".to_owned(),
            model: "stub-model".to_owned(),
            api_key: None,
        };
        let body = request_body(&config, &alert(), &[flow(1)]);
        assert_eq!(body["model"], "stub-model");
        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["messages"][0]["role"], "system");
        assert!(
            body["messages"][1]["content"]
                .as_str()
                .unwrap_or_default()
                .contains("Port scan")
        );
    }

    #[test]
    fn response_parsing_accepts_only_usable_content() {
        let ok = serde_json::json!({
            "choices": [{ "message": { "role": "assistant", "content": "  Likely a scan.  " } }]
        });
        assert_eq!(parse_explanation(&ok).as_deref(), Some("Likely a scan."));
        let error = serde_json::json!({ "error": { "message": "bad key" } });
        assert_eq!(parse_explanation(&error), None);
        let blank = serde_json::json!({ "choices": [{ "message": { "content": "   " } }] });
        assert_eq!(parse_explanation(&blank), None);
        assert_eq!(parse_explanation(&serde_json::json!({})), None);
    }

    #[test]
    fn long_explanation_is_capped_on_char_boundary() {
        let long = "é".repeat(MAX_EXPLANATION_CHARS + 10);
        let body = serde_json::json!({ "choices": [{ "message": { "content": long } }] });
        let parsed = parse_explanation(&body).expect("must parse");
        assert_eq!(parsed.chars().count(), MAX_EXPLANATION_CHARS);
    }

    async fn stub_server() -> String {
        use axum::http::HeaderMap;
        async fn ok(
            headers: HeaderMap,
            axum::Json(body): axum::Json<serde_json::Value>,
        ) -> axum::Json<serde_json::Value> {
            assert_eq!(
                headers.get("authorization").and_then(|v| v.to_str().ok()),
                Some("Bearer test-key")
            );
            assert_eq!(body["model"], "stub-model");
            axum::Json(serde_json::json!({
                "choices": [{ "message": { "role": "assistant", "content": "Stub says scan." } }]
            }))
        }
        async fn fail() -> axum::http::StatusCode {
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        }
        let app = axum::Router::new()
            .route("/ok/chat/completions", axum::routing::post(ok))
            .route("/fail/chat/completions", axum::routing::post(fail));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub");
        let addr = listener.local_addr().expect("stub addr");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve stub");
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn explainer_roundtrip_against_stub() {
        let base = stub_server().await;
        let explainer = LlmExplainer::new(LlmConfig {
            base_url: format!("{base}/ok"),
            model: "stub-model".to_owned(),
            api_key: Some("test-key".to_owned()),
        });
        assert_eq!(explainer.name(), "llm");
        let out = explainer
            .explanation_for(&alert(), &[flow(10)])
            .await
            .expect("stub answers");
        assert_eq!(out, "Stub says scan.");
    }

    #[tokio::test]
    async fn explainer_fails_open_on_server_error() {
        let base = stub_server().await;
        let explainer = LlmExplainer::new(LlmConfig {
            base_url: format!("{base}/fail"),
            model: "stub-model".to_owned(),
            api_key: None,
        });
        assert_eq!(explainer.explanation_for(&alert(), &[]).await, None);
    }
}
