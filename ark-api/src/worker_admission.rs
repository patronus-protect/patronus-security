//! Admission fencing prevents a timed-out POST from starting after recovery.
use std::sync::{Arc, Mutex};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::state::AppState;

pub struct Admission {
    pub instance_id: String,
    pub epoch: u64,
    pub active_submissions: usize,
}

impl Default for Admission {
    fn default() -> Self {
        Self {
            instance_id: Uuid::new_v4().to_string(),
            epoch: 0,
            active_submissions: 0,
        }
    }
}

impl Admission {
    pub fn recover(&mut self, active_jobs: usize) -> bool {
        if self.active_submissions != 0 || active_jobs != 0 {
            return false;
        }
        self.epoch = self
            .epoch
            .checked_add(1)
            .expect("admission epoch exhausted");
        true
    }

    fn enter(&mut self, instance: Option<&str>, epoch: Option<&str>) -> bool {
        match (instance, epoch) {
            (None, None) => {}
            (Some(instance), Some(epoch))
                if instance == self.instance_id && epoch.parse::<u64>() == Ok(self.epoch) => {}
            _ => return false,
        }
        self.active_submissions += 1;
        true
    }
}

struct SubmissionGuard(Arc<Mutex<Admission>>);

impl Drop for SubmissionGuard {
    fn drop(&mut self) {
        self.0
            .lock()
            .expect("admission mutex poisoned")
            .active_submissions -= 1;
    }
}

pub async fn track_submission(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    {
        let mut admission = state.admission.lock().expect("admission mutex poisoned");
        let instance = request.headers().get("x-ark-worker-instance");
        let epoch = request.headers().get("x-ark-worker-epoch");
        if instance.is_some_and(|value| value.to_str().is_err())
            || epoch.is_some_and(|value| value.to_str().is_err())
            || !admission.enter(
                instance.and_then(|value| value.to_str().ok()),
                epoch.and_then(|value| value.to_str().ok()),
            )
        {
            return (StatusCode::CONFLICT, "stale worker admission").into_response();
        }
    }
    // Lives through body parsing, enqueueing, and registration; cancellation
    // releases this count, while registered jobs remain active until Finished.
    let _guard = SubmissionGuard(Arc::clone(&state.admission));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_and_instance_fence_delayed_submissions() {
        let mut admission = Admission::default();
        let instance = admission.instance_id.clone();
        admission.epoch = 1;
        assert!(!admission.enter(Some(&instance), Some("0")));
        assert!(!admission.enter(Some("previous-process"), Some("1")));
        assert!(!admission.enter(Some(&instance), None));
        assert_eq!(admission.active_submissions, 0);
        assert!(admission.enter(Some(&instance), Some("1")));
        assert_eq!(admission.active_submissions, 1);
    }

    #[test]
    fn direct_worker_clients_are_counted_and_guard_cancellation_releases_them() {
        let admission = Arc::new(Mutex::new(Admission::default()));
        assert!(admission.lock().unwrap().enter(None, None));
        let guard = SubmissionGuard(admission.clone());
        assert_eq!(admission.lock().unwrap().active_submissions, 1);
        drop(guard);
        assert_eq!(admission.lock().unwrap().active_submissions, 0);
    }
    #[test]
    fn idle_fence_waits_for_submission_registration_and_every_finished_event() {
        let mut admission = Admission::default();
        assert!(admission.enter(None, None));
        // A body is still being read: no request channel exists yet.
        assert!(!admission.recover(0));
        assert_eq!(admission.epoch, 0);
        admission.active_submissions -= 1;
        // POST completed, but its inference remains active after an SSE loss.
        assert!(!admission.recover(1));
        assert_eq!(admission.epoch, 0);
        assert!(admission.recover(0));
        assert_eq!(admission.epoch, 1);
    }
    #[tokio::test]
    async fn worker_recovery_endpoint_rejects_active_jobs_and_fences_http_posts() {
        use axum::body::{to_bytes, Body};
        use axum::routing::{get, post};
        use axum::Router;
        use patronus_ark::{ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel};
        use sha2::{Digest, Sha256};
        use tower::ServiceExt;

        let categories = vec![SecurityCategory::Injection];
        let config = crate::config::Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            max_upload_bytes: 1024,
            keys: vec![crate::config::ApiKeyConfig {
                name: "worker".into(),
                key_hash: format!("{:x}", Sha256::digest(b"service-token")),
                allowed_categories: None,
                default_categories: None,
                gates: None,
            }],
            categories: categories.clone(),
            max_level: SecurityLevel::L1,
            model_dir: None,
            download_files: false,
            cache_dir: None,
            default_gates: ScanGateMatrix::default(),
            dynamic_pii: None,
            onnx_runtime: Default::default(),
        };
        let state = AppState::new(
            config,
            SecurityGateway::with_max_level(categories, SecurityLevel::L1, None, false),
        );
        let instance = state.admission.lock().unwrap().instance_id.clone();
        let app = Router::new()
            .route(
                "/v1/scan",
                post(|| async { StatusCode::ACCEPTED }).layer(
                    axum::middleware::from_fn_with_state(state.clone(), track_submission),
                ),
            )
            .route(
                "/internal/status",
                get(crate::routes::health::worker_status),
            )
            .route(
                "/internal/recover",
                post(crate::routes::health::recover_worker),
            )
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                crate::auth::require_api_key,
            ))
            .with_state(state.clone());
        let request = |path: &str, method: &str| {
            Request::builder()
                .uri(path)
                .method(method)
                .header("Authorization", "Bearer service-token")
                .body(Body::empty())
                .unwrap()
        };
        let unauthorized = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/internal/recover")
                    .method("POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        let recovered = app
            .clone()
            .oneshot(request("/internal/recover", "POST"))
            .await
            .unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(recovered.into_body(), 4096).await.unwrap()).unwrap();
        assert_eq!(body["epoch"], 1);
        let stale = Request::builder()
            .uri("/v1/scan")
            .method("POST")
            .header("Authorization", "Bearer service-token")
            .header("x-ark-worker-instance", &instance)
            .header("x-ark-worker-epoch", "0")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(stale).await.unwrap().status(),
            StatusCode::CONFLICT
        );
        assert_eq!(
            app.clone()
                .oneshot(request("/v1/scan", "POST"))
                .await
                .unwrap()
                .status(),
            StatusCode::ACCEPTED
        );
        state.register("unfinished-inference".into());
        let busy = app
            .clone()
            .oneshot(request("/internal/status", "GET"))
            .await
            .unwrap();
        assert_eq!(busy.status(), StatusCode::OK);
        assert_eq!(
            app.oneshot(request("/internal/recover", "POST"))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        assert_eq!(state.admission.lock().unwrap().epoch, 1);
    }
}
