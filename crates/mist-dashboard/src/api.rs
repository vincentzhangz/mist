//! REST + websocket helpers for the mist API (same-origin relative URLs).
//!
//! [`ApiError`] is a plain message-carrying error for UI display; the pure
//! URL/parsing helpers below are unit-tested on the host.

use std::fmt::{Display, Formatter, Result as FmtResult};

use gloo_net::http::Request;

use crate::dto::{AlertView, ErrorBody, FlowRecord, LoginRequest, LoginResponse};

/// Error from an API call, carrying a human-readable message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// Transport-level failure (DNS, connection refused, CORS, ...).
    Network(String),
    /// Non-2xx status with the server-provided (or fallback) message.
    Status(u16, String),
    /// The response body did not match the expected shape.
    Decode(String),
}

impl Display for ApiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            Self::Network(msg) => write!(f, "network error: {msg}"),
            Self::Status(code, msg) => write!(f, "request failed ({code}): {msg}"),
            Self::Decode(msg) => write!(f, "bad response: {msg}"),
        }
    }
}

fn auth_value(token: &str) -> String {
    format!("Bearer {token}")
}

/// Extract an error message from a non-2xx response, falling back to the
/// status code when the body is not a JSON error object.
fn status_error(status: u16, text: &str) -> ApiError {
    let message = serde_json::from_str::<ErrorBody>(text)
        .map_or_else(|_| format!("unexpected status {status}"), |b| b.error);
    ApiError::Status(status, message)
}

fn parse_or_status<T>(status: u16, text: &str) -> Result<T, ApiError>
where
    T: serde::de::DeserializeOwned,
{
    if (200..300).contains(&status) {
        serde_json::from_str::<T>(text)
            .map_err(|e| ApiError::Decode(format!("invalid response: {e}")))
    } else {
        Err(status_error(status, text))
    }
}

async fn get_authed(path: &str, token: &str) -> Result<String, ApiError> {
    let response = Request::get(path)
        .header("Authorization", &auth_value(token))
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    let status = response.status();
    let text = response
        .text()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    if (200..300).contains(&status) {
        Ok(text)
    } else {
        Err(status_error(status, &text))
    }
}

/// Log in with email + password.
///
/// # Errors
///
/// Returns [`ApiError`] when the request fails, the credentials are rejected
/// (401 with the server message), or the response shape is unexpected.
pub async fn login(email: &str, password: &str) -> Result<LoginResponse, ApiError> {
    let body = LoginRequest {
        email: email.to_owned(),
        password: password.to_owned(),
    };
    let request = Request::post("/api/auth/login")
        .json(&body)
        .map_err(|e| ApiError::Network(e.to_string()))?;
    let response = request
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    parse_or_status(
        response.status(),
        &response
            .text()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?,
    )
}

/// Fetch the current flow snapshot.
///
/// # Errors
///
/// Returns [`ApiError`] when the request fails or the response is unexpected.
pub async fn fetch_flows(token: &str, limit: usize) -> Result<Vec<FlowRecord>, ApiError> {
    let path = format!("/api/flows?limit={limit}");
    let text = get_authed(&path, token).await?;
    serde_json::from_str::<Vec<FlowRecord>>(&text)
        .map_err(|e| ApiError::Decode(format!("invalid flows response: {e}")))
}

/// Query string for the alerts list endpoint.
#[must_use]
pub fn alerts_query(state: Option<&str>, severity: Option<&str>, limit: usize) -> String {
    let mut query = format!("/api/alerts?limit={limit}");
    if let Some(state) = state.filter(|s| !s.is_empty() && *s != "all") {
        query.push_str("&state=");
        query.push_str(state);
    }
    if let Some(severity) = severity.filter(|s| !s.is_empty() && *s != "all") {
        query.push_str("&severity=");
        query.push_str(severity);
    }
    query
}

/// Fetch alerts with optional server-side filters.
///
/// # Errors
///
/// Returns [`ApiError`] when the request fails or the response is unexpected.
pub async fn fetch_alerts(
    token: &str,
    state: Option<&str>,
    severity: Option<&str>,
    limit: usize,
) -> Result<Vec<AlertView>, ApiError> {
    let text = get_authed(&alerts_query(state, severity, limit), token).await?;
    serde_json::from_str::<Vec<AlertView>>(&text)
        .map_err(|e| ApiError::Decode(format!("invalid alerts response: {e}")))
}

/// Path for a single alert. The id may contain `/`, so it is percent-encoded.
///
/// # Panics
///
/// Never panics; encoding a string cannot fail.
#[must_use]
pub fn alert_path(id: &str) -> String {
    format!("/api/alerts/{}", urlencoding::encode(id))
}

/// Fetch one alert by id.
///
/// # Errors
///
/// Returns [`ApiError`] when the request fails or the response is unexpected.
pub async fn fetch_alert(token: &str, id: &str) -> Result<AlertView, ApiError> {
    let text = get_authed(&alert_path(id), token).await?;
    serde_json::from_str::<AlertView>(&text)
        .map_err(|e| ApiError::Decode(format!("invalid alert response: {e}")))
}

/// Mark one alert resolved.
///
/// # Errors
///
/// Returns [`ApiError`] when the request fails or the response is unexpected.
pub async fn resolve_alert(token: &str, id: &str) -> Result<AlertView, ApiError> {
    let path = format!("{}/resolve", alert_path(id));
    let response = Request::post(&path)
        .header("Authorization", &auth_value(token))
        .send()
        .await
        .map_err(|e| ApiError::Network(e.to_string()))?;
    parse_or_status(
        response.status(),
        &response
            .text()
            .await
            .map_err(|e| ApiError::Network(e.to_string()))?,
    )
}

/// Build the websocket URL for the current page (`ws:`/`wss:` + same host).
///
/// Returns `None` outside the browser (e.g. during host-side checks).
#[must_use]
pub fn ws_url(token: &str) -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        let window = web_sys::window()?;
        let location = window.location();
        let scheme = location
            .protocol()
            .ok()
            .map(|protocol| if protocol == "https:" { "wss" } else { "ws" })?;
        let host = location.host().ok()?;
        Some(format!(
            "{scheme}://{host}/api/ws?token={}",
            urlencoding::encode(token)
        ))
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = token;
        None
    }
}

// --- localStorage -----------------------------------------------------------

#[cfg(target_arch = "wasm32")]
const TOKEN_KEY: &str = "mist.token";
#[cfg(target_arch = "wasm32")]
const EMAIL_KEY: &str = "mist.email";

#[cfg(target_arch = "wasm32")]
fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

/// Read the stored JWT, if any.
#[must_use]
pub fn read_token() -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        storage()?.get_item(TOKEN_KEY).ok().flatten()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

/// Read the stored login email, if any.
#[must_use]
pub fn read_email() -> Option<String> {
    #[cfg(target_arch = "wasm32")]
    {
        storage()?.get_item(EMAIL_KEY).ok().flatten()
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        None
    }
}

/// Persist the session after login.
pub fn write_session(token: &str, email: &str) {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(storage) = storage() {
            let _ = storage.set_item(TOKEN_KEY, token);
            let _ = storage.set_item(EMAIL_KEY, email);
        }
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = (token, email);
    }
}

/// Drop the stored session on logout.
pub fn clear_session() {
    #[cfg(target_arch = "wasm32")]
    {
        if let Some(storage) = storage() {
            let _ = storage.remove_item(TOKEN_KEY);
            let _ = storage.remove_item(EMAIL_KEY);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alert_path_encodes_slashes() {
        // ids contain `/` and MUST be percent-encoded in the URL path.
        assert_eq!(
            alert_path("default/web-0/high-egress"),
            "/api/alerts/default%2Fweb-0%2Fhigh-egress"
        );
        assert_eq!(alert_path("simple"), "/api/alerts/simple");
    }

    #[test]
    fn resolve_path_appends_resolve() {
        let path = format!("{}/resolve", alert_path("ns/name/rule"));
        assert_eq!(path, "/api/alerts/ns%2Fname%2Frule/resolve");
    }

    #[test]
    fn alerts_query_shapes() {
        assert_eq!(alerts_query(None, None, 200), "/api/alerts?limit=200");
        assert_eq!(
            alerts_query(Some("firing"), Some("critical"), 50),
            "/api/alerts?limit=50&state=firing&severity=critical"
        );
        assert_eq!(
            alerts_query(Some("all"), Some("all"), 10),
            "/api/alerts?limit=10"
        );
    }

    #[test]
    fn api_error_display() {
        assert_eq!(
            ApiError::Status(401, "invalid credentials".to_owned()).to_string(),
            "request failed (401): invalid credentials"
        );
        assert!(
            ApiError::Network("x".to_owned())
                .to_string()
                .contains("network")
        );
    }

    #[test]
    fn ws_url_none_off_wasm() {
        assert_eq!(ws_url("token"), None);
    }
}
