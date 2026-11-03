//! Authentication middleware: JWT for REST, token for ingest.

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Json},
};

use crate::{auth, state::AppState};

/// Bearer token from the `Authorization` header, if syntactically present.
fn bearer_token(req: &Request<Body>) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

/// Rejects unauthenticated `/api/*` requests with 401.
///
/// Public without a token: `/healthz`, `/metrics`, `POST /api/auth/login`,
/// and `/api/ws` (the token travels in `?token=` instead, checked in
/// [`crate::ws::ws_handler`]). `/api/ingest` requires one of the provisioned
/// `INGEST_TOKEN`/`INGEST_TOKENS` as `Bearer` when any is configured, and
/// stays open otherwise.
/// Everything else under `/api/` requires `Authorization: Bearer <jwt>`.
pub(crate) async fn require_auth(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> impl IntoResponse {
    let unauthorized = || {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({ "error": "unauthorized" })),
        )
            .into_response()
    };
    let path = req.uri().path().to_owned();
    if !path.starts_with("/api/") || path == "/api/auth/login" || path == "/api/ws" {
        return next.run(req).await;
    }
    if path == "/api/ingest" {
        let tokens = &state.inner.ingest_tokens;
        let token_ok = bearer_token(&req).is_some_and(|got| tokens.iter().any(|t| t == got));
        if tokens.is_empty() || token_ok {
            return next.run(req).await;
        }
        return unauthorized();
    }
    let Some(email) =
        bearer_token(&req).and_then(|token| auth::verify_token(token, &state.inner.jwt_secret))
    else {
        return unauthorized();
    };
    req.extensions_mut().insert(AuthedEmail(email));
    next.run(req).await
}

/// Email from the verified JWT, inserted by [`require_auth`].
#[derive(Clone, Debug)]
pub(crate) struct AuthedEmail(pub(crate) String);

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt as _;

    use super::*;

    #[tokio::test]
    async fn protected_routes_require_token() {
        let (state, _rx) = crate::test_helpers::test_state();
        let token = auth::create_token("tester@example.com", &state.inner.jwt_secret).unwrap();
        let bearer = format!("Bearer {token}");

        // No token and a bogus token both fail.
        for header in [None, Some(String::from("Bearer bogus"))] {
            let mut builder = Request::get("/api/alerts");
            if let Some(header) = header {
                builder = builder.header("authorization", header);
            }
            let response = crate::routes::router(state.clone())
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        let response = crate::routes::router(state.clone())
            .oneshot(
                Request::get("/api/alerts")
                    .header("authorization", bearer)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
}
