use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::config::ApiKeyConfig;
use crate::state::AppState;

#[derive(Clone)]
pub struct AuthenticatedKey(pub ApiKeyConfig);

pub async fn require_api_key(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let header = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());

    let Some(token) = header.and_then(|value| value.strip_prefix("Bearer ")) else {
        return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response();
    };

    let digest = Sha256::digest(token.as_bytes());
    let digest_hex = digest.iter().map(|b| format!("{b:02x}")).collect::<String>();

    let matched = state
        .config
        .keys
        .iter()
        .find(|key| key.key_hash.as_bytes().ct_eq(digest_hex.as_bytes()).into());

    match matched {
        Some(key) => {
            tracing::debug!(key = %key.name, "authenticated request");
            request.extensions_mut().insert(AuthenticatedKey(key.clone()));
            next.run(request).await
        }
        None => (StatusCode::UNAUTHORIZED, "invalid api key").into_response(),
    }
}
