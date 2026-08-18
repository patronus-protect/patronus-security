use std::convert::Infallible;
use std::time::Duration;

use axum::extract::{Multipart, Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use futures::StreamExt;
use patronus_ark::QueuedSecurityEvent;
use serde_json::json;
use tokio_stream::wrappers::BroadcastStream;

use crate::auth::AuthenticatedKey;
use crate::dto::{CompletionDto, QueuedScanResultDto};
use crate::state::AppState;

/// Multipart field `text` and/or one or more `files` are accepted. Each file
/// is scanned as its own request (its content is decoded as UTF-8 text);
/// `text`, when present, is scanned as an additional request. The response
/// lists every accepted request id — the client follows each one's event
/// stream independently.
pub async fn submit_scan(
    State(state): State<AppState>,
    Extension(AuthenticatedKey(key)): Extension<AuthenticatedKey>,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let categories = match &key.allowed_categories {
        Some(allowed) => allowed.clone(),
        None => state.config.categories.clone(),
    };
    let gates = state.config.gates_for(&key);

    let mut jobs = Vec::new();

    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("invalid multipart body: {err}") })),
                )
                    .into_response();
            }
        };

        let field_name = field.name().unwrap_or_default().to_string();
        let file_name = field.file_name().map(|name| name.to_string());
        let bytes = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": format!("failed to read field '{field_name}': {err}") })),
                )
                    .into_response();
            }
        };

        let text = match String::from_utf8(bytes.to_vec()) {
            Ok(text) => text,
            Err(_) => {
                return (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(json!({
                        "error": format!(
                            "field '{field_name}' is not valid UTF-8 text; only text-decodable files are supported"
                        )
                    })),
                )
                    .into_response();
            }
        };

        if text.trim().is_empty() {
            continue;
        }

        let source = file_name.unwrap_or(field_name);
        let request_id =
            state
                .gateway
                .enqueue_categories(categories.clone(), text, Some(gates.clone()));
        state.register(request_id.clone());
        jobs.push(json!({ "request_id": request_id, "source": source }));
    }

    if jobs.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "no non-empty 'text' field or files provided" })),
        )
            .into_response();
    }

    (StatusCode::ACCEPTED, Json(json!({ "jobs": jobs }))).into_response()
}

pub async fn scan_events(
    State(state): State<AppState>,
    Path(request_id): Path<String>,
) -> axum::response::Response {
    let Some((buffered, receiver)) = state.subscribe(&request_id) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "unknown or already-finished request_id" })),
        )
            .into_response();
    };

    let replay = futures::stream::iter(
        buffered
            .into_iter()
            .map(|event| Ok::<Event, Infallible>(to_sse_event(event))),
    );
    let live = BroadcastStream::new(receiver).filter_map(|item| {
        futures::future::ready(match item {
            Ok(event) => Some(Ok::<Event, Infallible>(to_sse_event(event))),
            Err(_lagged) => None,
        })
    });
    let stream = replay.chain(live);

    Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

fn to_sse_event(event: QueuedSecurityEvent) -> Event {
    match event {
        QueuedSecurityEvent::Progress(progress) => Event::default()
            .event("progress")
            .json_data(progress)
            .unwrap_or_else(|_| Event::default().event("progress")),
        QueuedSecurityEvent::Provisional(result) => Event::default()
            .event("provisional")
            .json_data(QueuedScanResultDto::from(result))
            .unwrap_or_else(|_| Event::default().event("provisional")),
        QueuedSecurityEvent::Result(result) => Event::default()
            .event("result")
            .json_data(QueuedScanResultDto::from(result))
            .unwrap_or_else(|_| Event::default().event("result")),
        QueuedSecurityEvent::Finished {
            request_id,
            completion,
        } => Event::default()
            .event("finished")
            .json_data(json!({
                "request_id": request_id,
                "completion": CompletionDto::from(completion),
            }))
            .unwrap_or_else(|_| Event::default().event("finished")),
    }
}
