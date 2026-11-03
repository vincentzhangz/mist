//! Authenticated websocket event stream.

use axum::{
    extract::{Query, State, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Json},
};
use serde::Deserialize;
use tokio::sync::broadcast;

use crate::{analyzer::AlertEvent, auth, state::AppState};

#[derive(Debug, Default, Deserialize)]
pub(crate) struct WsQuery {
    token: Option<String>,
}

pub(crate) async fn ws_handler(
    State(state): State<AppState>,
    Query(query): Query<WsQuery>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let authorized = query
        .token
        .as_deref()
        .and_then(|token| auth::verify_token(token, &state.inner.jwt_secret))
        .is_some();
    if !authorized {
        // Reject before upgrading: no socket is opened for bad tokens.
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "missing or invalid token" })),
        )
            .into_response();
    }
    ws.on_upgrade(move |socket| drive_socket(socket, state.inner.events_tx.subscribe()))
        .into_response()
}

async fn drive_socket(
    socket: axum::extract::ws::WebSocket,
    mut events: broadcast::Receiver<AlertEvent>,
) {
    use axum::extract::ws::Message;
    use futures::{SinkExt as _, StreamExt as _};
    let (mut sender, mut receiver) = socket.split();
    // Forward broadcast events until either side closes. A lagged receiver
    // skips missed events rather than stalling the broadcast.
    let forward = async move {
        loop {
            match events.recv().await {
                Ok(event) => {
                    let text = match serde_json::to_string(&event) {
                        Ok(text) => text,
                        Err(error) => {
                            tracing::warn!(?error, "event serialization failed");
                            continue;
                        }
                    };
                    if sender.send(Message::Text(text.into())).await.is_err() {
                        break;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    tracing::debug!(skipped, "websocket receiver lagged");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    };
    // Drain client messages (pings/pongs/closes) so the connection stays alive.
    let drain = async move {
        while let Some(message) = receiver.next().await {
            match message {
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(_) => {}
            }
        }
    };
    tokio::select! {
        () = forward => {},
        () = drain => {},
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::store::{AlertView, model::AlertLifecycle};

    async fn serve_addr(state: AppState) -> std::net::SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, crate::routes::router(state))
                .await
                .unwrap();
        });
        addr
    }
    fn ws_url(addr: &std::net::SocketAddr, state: &AppState) -> String {
        let token = auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
        format!("ws://{addr}/api/ws?token={token}")
    }
    #[tokio::test]
    async fn websocket_rejects_missing_and_bad_tokens() {
        let (state, _rx) = crate::test_helpers::test_state();
        let addr = serve_addr(state).await;
        let bad = format!("ws://{addr}/api/ws?token=bogus");
        for url in [format!("ws://{addr}/api/ws"), bad] {
            assert!(
                tokio_tungstenite::connect_async(url).await.is_err(),
                "handshake without a valid token must fail"
            );
        }
    }
    #[tokio::test]
    async fn websocket_streams_broadcast_events() {
        use futures::SinkExt as _;

        let (state, _rx) = crate::test_helpers::test_state();
        let addr = serve_addr(state.clone()).await;

        let (mut socket, _) = tokio_tungstenite::connect_async(ws_url(&addr, &state))
            .await
            .unwrap();
        // The server drains client messages; a ping followed by a clean close
        // exercises upgrade, liveness, and teardown.
        socket
            .send(tokio_tungstenite::tungstenite::Message::Ping(
                vec![1, 2, 3].into(),
            ))
            .await
            .unwrap();
        socket.close(None).await.unwrap();
    }
    #[tokio::test]
    async fn websocket_receives_published_alert() {
        use futures::StreamExt as _;

        let (state, _rx) = crate::test_helpers::test_state();
        let events_tx = state.inner.events_tx.clone();
        let addr = serve_addr(state.clone()).await;

        let (mut socket, _) = tokio_tungstenite::connect_async(ws_url(&addr, &state))
            .await
            .unwrap();
        let view = AlertView {
            alert: mist_types::Alert {
                id: "x".to_owned(),
                severity: mist_types::Severity::Info,
                title: "t".to_owned(),
                detail: "d".to_owned(),
                first_seen_unix_ms: 1,
                last_seen_unix_ms: 2,
                labels: HashMap::default(),
                explanation: None,
            },
            state: AlertLifecycle::Firing,
            acked_by: None,
            ack_note: None,
            silenced: false,
            occurrences: 1,
        };
        events_tx
            .send(AlertEvent::Alert {
                alert: Box::new(view),
            })
            .unwrap();
        let message = tokio::time::timeout(std::time::Duration::from_secs(5), socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        let text = message.into_text().unwrap();
        let event: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(event["type"], "alert");
        assert_eq!(event["alert"]["id"], "x");
    }
}
