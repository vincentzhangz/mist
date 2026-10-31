//! Shared dashboard state: auth session, live flows/alerts, WS status.

use leptos::prelude::*;

use crate::api::{clear_session, read_email, read_token, write_session};
use crate::dto::{AlertView, FlowRecord};

/// Connection state of the `/api/ws` stream, shown in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WsStatus {
    /// First connect attempt is in flight.
    Connecting,
    /// Receiving live events.
    Live,
    /// The stream dropped; backing off before retrying.
    Reconnecting,
}

impl WsStatus {
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Connecting => "connecting",
            Self::Live => "live",
            Self::Reconnecting => "reconnecting",
        }
    }

    #[must_use]
    pub fn css_class(self) -> &'static str {
        match self {
            Self::Connecting => "ws-connecting",
            Self::Live => "ws-live",
            Self::Reconnecting => "ws-reconnecting",
        }
    }
}

/// Signals shared across all views, provided once at the app root.
#[derive(Clone, Copy)]
pub struct AppState {
    /// JWT from `/api/auth/login`; `None` means logged out.
    pub token: RwSignal<Option<String>>,
    /// Email shown in the header.
    pub email: RwSignal<Option<String>>,
    /// Newest-first flow rows, capped by the flows view.
    pub flows: RwSignal<Vec<FlowRecord>>,
    /// Alert list as last fetched / patched by WS events.
    pub alerts: RwSignal<Vec<AlertView>>,
    /// Current websocket connection state.
    pub ws_status: RwSignal<WsStatus>,
}

impl AppState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            token: RwSignal::new(read_token()),
            email: RwSignal::new(read_email()),
            flows: RwSignal::new(Vec::new()),
            alerts: RwSignal::new(Vec::new()),
            ws_status: RwSignal::new(WsStatus::Connecting),
        }
    }

    /// Store a fresh login both in `localStorage` and in signals.
    pub fn set_session(&self, token: String, email: String) {
        write_session(&token, &email);
        self.token.set(Some(token));
        self.email.set(Some(email));
        self.flows.set(Vec::new());
        self.alerts.set(Vec::new());
    }

    /// Drop the session when the server reports it unauthorized, so the
    /// route guard bounces to `/login` instead of stranding the user on
    /// views that can never load again (e.g. an expired overnight token).
    pub fn logout_if_unauthorized(&self, err: &crate::api::ApiError) {
        if err.is_unauthorized() {
            self.logout();
        }
    }

    /// Clear the session (logout).
    pub fn logout(&self) {
        clear_session();
        self.token.set(None);
        self.email.set(None);
        self.flows.set(Vec::new());
        self.alerts.set(Vec::new());
        self.ws_status.set(WsStatus::Connecting);
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Format epoch milliseconds as `HH:MM:SS` (UTC) for table cells.
#[must_use]
pub fn format_time_ms(ms: u64) -> String {
    let secs = ms / 1_000;
    let hours = (secs / 3_600) % 24;
    let minutes = (secs / 60) % 60;
    let seconds = secs % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}")
}

/// Short `namespace/name` label for a pod, or `—` when unattributed.
#[must_use]
pub fn pod_label(pod: Option<&crate::dto::PodRef>) -> String {
    pod.map_or_else(|| "—".to_owned(), |p| format!("{}/{}", p.namespace, p.name))
}

/// Format a byte count as `B`/`KB`/`MB`/`GB` with one decimal for units above bytes.
#[must_use]
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1_024;
    const MB: u64 = 1_024 * KB;
    const GB: u64 = 1_024 * MB;
    if bytes >= GB {
        format!("{}.{} GB", bytes / GB, (bytes % GB) * 10 / GB)
    } else if bytes >= MB {
        format!("{}.{} MB", bytes / MB, (bytes % MB) * 10 / MB)
    } else if bytes >= KB {
        format!("{}.{} KB", bytes / KB, (bytes % KB) * 10 / KB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_formats_as_hh_mm_ss() {
        // 1700000000s = 2023-11-14T22:13:20Z
        assert_eq!(format_time_ms(1_700_000_000_000), "22:13:20");
        assert_eq!(format_time_ms(0), "00:00:00");
    }

    #[test]
    fn bytes_format_units() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(999), "999 B");
        assert_eq!(format_bytes(1_024), "1.0 KB");
        assert_eq!(format_bytes(1_536), "1.5 KB");
        assert_eq!(format_bytes(1_048_576), "1.0 MB");
        assert_eq!(format_bytes(1_073_741_824), "1.0 GB");
        assert_eq!(format_bytes(2_684_354_560), "2.5 GB");
    }

    #[test]
    fn ws_status_labels() {
        assert_eq!(WsStatus::Live.label(), "live");
        assert_eq!(WsStatus::Reconnecting.label(), "reconnecting");
        assert_eq!(WsStatus::Connecting.label(), "connecting");
    }
}
