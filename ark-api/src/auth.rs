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

fn bearer_token(request: &Request) -> Option<&str> {
    request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn matching_key<'a>(keys: &'a [ApiKeyConfig], token: &str) -> Option<&'a ApiKeyConfig> {
    let digest = Sha256::digest(token.as_bytes());
    let digest_hex = digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    keys.iter()
        .find(|key| key.key_hash.as_bytes().ct_eq(digest_hex.as_bytes()).into())
}

pub async fn require_api_key(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(token) = bearer_token(&request) else {
        return (StatusCode::UNAUTHORIZED, "missing bearer token").into_response();
    };
    let matched = matching_key(&state.config.keys, token);

    match matched {
        Some(key) => {
            tracing::debug!(key = %key.name, "authenticated request");
            request
                .extensions_mut()
                .insert(AuthenticatedKey(key.clone()));
            next.run(request).await
        }
        None => (StatusCode::UNAUTHORIZED, "invalid api key").into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> ApiKeyConfig {
        ApiKeyConfig {
            name: "internal".to_string(),
            key_hash: format!("{:x}", Sha256::digest(b"correct-secret")),
            allowed_categories: None,
            default_categories: None,
            gates: None,
        }
    }

    #[test]
    fn accepts_valid_and_rejects_invalid_key() {
        let keys = vec![key()];
        assert!(matching_key(&keys, "correct-secret").is_some());
        assert!(matching_key(&keys, "wrong-secret").is_none());
    }

    #[test]
    fn rejects_missing_or_malformed_bearer_header() {
        let missing = Request::new(axum::body::Body::empty());
        assert!(bearer_token(&missing).is_none());

        let malformed = Request::builder()
            .header(axum::http::header::AUTHORIZATION, "Basic abc")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(bearer_token(&malformed).is_none());
    }
}
