//! App shell: route guard, header (nav + WS status + logout), WS loop.

use futures::StreamExt;
use leptos::prelude::*;
use leptos_router::components::{A, Outlet, Redirect};

use crate::api::ws_url;
use crate::dto::{AlertView, WsEvent, parse_ws_event};
use crate::state::{AppState, WsStatus};

/// Maximum flow rows kept in memory (initial load + live prepend).
const MAX_FLOWS: usize = 200;
/// Maximum alerts kept in memory when patched by WS events.
const MAX_ALERTS: usize = 500;

/// Merge a WS batch at the front, newest first, capped at [`MAX_FLOWS`].
fn prepend_flows(
    flows: &RwSignal<Vec<crate::dto::FlowRecord>>,
    mut batch: Vec<crate::dto::FlowRecord>,
) {
    flows.update(|current| {
        batch.append(current);
        batch.truncate(MAX_FLOWS);
        *current = batch;
    });
}

/// Upsert one alert from a WS event, newest first, capped at [`MAX_ALERTS`].
fn upsert_alert(alerts: &RwSignal<Vec<AlertView>>, alert: AlertView) {
    alerts.update(|current| {
        current.retain(|a| a.id != alert.id);
        current.insert(0, alert);
        current.truncate(MAX_ALERTS);
    });
}

/// Run one websocket connection until it closes. Returns when the stream ends
/// or the session token changed (caller should stop reconnecting then).
async fn run_ws(url: &str, state: &AppState, token: &str) {
    let Ok(socket) = gloo_net::websocket::futures::WebSocket::open(url) else {
        return;
    };
    state.ws_status.set(WsStatus::Live);
    let (_sink, mut stream) = socket.split();
    while let Some(message) = stream.next().await {
        if state.token.get_untracked().as_deref() != Some(token) {
            break;
        }
        let text = match message {
            Ok(gloo_net::websocket::Message::Text(text)) => text,
            Ok(gloo_net::websocket::Message::Bytes(_)) | Err(_) => break,
        };
        match parse_ws_event(&text) {
            Ok(Some(WsEvent::Flows { flows })) => {
                prepend_flows(&state.flows, flows);
            }
            Ok(Some(WsEvent::Alert { alert })) => {
                upsert_alert(&state.alerts, alert);
            }
            Ok(None) | Err(_) => {}
        }
    }
}

/// Connect with exponential backoff until the session token changes.
async fn ws_loop(state: AppState, token: String) {
    let mut backoff_ms: u32 = 1_000;
    loop {
        if state.token.get_untracked().as_deref() != Some(token.as_str()) {
            break;
        }
        state.ws_status.set(WsStatus::Connecting);
        if let Some(url) = ws_url(&token) {
            run_ws(&url, &state, &token).await;
        }
        if state.token.get_untracked().as_deref() != Some(token.as_str()) {
            break;
        }
        state.ws_status.set(WsStatus::Reconnecting);
        gloo_timers::future::TimeoutFuture::new(backoff_ms).await;
        backoff_ms = backoff_ms.saturating_mul(2).min(30_000);
    }
}

/// Authenticated shell: header + `<Outlet/>` for the tab views.
///
/// Redirects to `/login` without a token and owns the websocket loop.
#[component]
pub fn Shell() -> impl IntoView {
    let state = expect_context::<AppState>();
    let ws_started = RwSignal::new(false);

    // Start the WS loop once a session exists.
    Effect::new(move || {
        if state.token.get().is_some() && !ws_started.get_untracked() {
            ws_started.set(true);
            if let Some(token) = state.token.get_untracked() {
                leptos::task::spawn_local(ws_loop(state, token));
            }
        }
        if state.token.get_untracked().is_none() {
            ws_started.set(false);
        }
    });

    view! {
        <Show
            when=move || state.token.get().is_some()
            fallback=|| {
                view! { <Redirect path="/login" /> }
            }
        >
            <div class="app">
                <header class="topbar">
                    <span class="brand">"mist"</span>
                    <nav>
                        <A href="/">"Flows"</A>
                        <A href="/alerts">"Alerts"</A>
                    </nav>
                    <span class="spacer" />
                    <span class=move || {
                        format!("ws-status {}", state.ws_status.get().css_class())
                    }>
                        <span class="dot" />
                        {move || state.ws_status.get().label()}
                    </span>
                    <span class="user">{move || state.email.get().unwrap_or_default()}</span>
                    <button
                        class="logout"
                        on:click=move |_| {
                            state.logout();
                        }
                    >
                        "Logout"
                    </button>
                </header>
                <main>
                    <Outlet />
                </main>
            </div>
        </Show>
    }
}
