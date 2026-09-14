// SPDX-License-Identifier: GPL-3.0-only
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use axum::{
    extract::{Multipart, Path, State},
    http::{header, HeaderMap, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{
    config::CoordinatorConfig, cube::orchestrator::CubeOrchestrator,
    request_config::RequestScanConfig, store::JobStore,
};

#[derive(Clone)]
pub struct AppState {
    config: Arc<CoordinatorConfig>,
    orchestrator: Arc<CubeOrchestrator>,
    store: JobStore,
    admission: Arc<Semaphore>,
    admission_capacity: usize,
    active: Arc<ActiveScans>,
}

#[derive(Default)]
struct ActiveScans {
    count: AtomicUsize,
    idle: tokio::sync::Notify,
}

struct ActiveGuard(Arc<ActiveScans>);

enum ParentPermit {
    Upload { _permit: Arc<OwnedSemaphorePermit> },
    Reserved { _permit: OwnedSemaphorePermit },
}

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        if self.0.count.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.0.idle.notify_waiters();
        }
    }
}

impl AppState {
    pub async fn connect(config: CoordinatorConfig) -> Result<Self, Box<dyn std::error::Error>> {
        config.validate()?;
        let redis_url = std::fs::read_to_string(&config.gateway.redis_url_file)
            .map_err(|_| "cannot read Redis URL file")?;
        let cube_token = std::fs::read_to_string(&config.gateway.cube_token_file)
            .map_err(|_| "cannot read Cube token file")?;
        let redis_url = redis_url.trim();
        let cube_token = cube_token.trim();
        if redis_url.is_empty() || cube_token.is_empty() {
            return Err("coordinator secret file is empty".into());
        }
        let active_ttl_secs = config
            .gateway
            .parent_deadline_ms
            .div_ceil(1_000)
            .saturating_add(60)
            .max(config.gateway.retention_secs);
        let store = JobStore::connect(
            redis_url,
            config.gateway.redis_prefix.clone(),
            config.gateway.retention_secs,
            active_ttl_secs,
        )
        .await
        .map_err(|_| "cannot connect to Redis job store")?;
        let orchestrator = CubeOrchestrator::new(
            config.gateway.cubes.clone(),
            cube_token.to_owned(),
            config.gateway.chunk_bytes,
            config.gateway.chunks_per_batch,
            Duration::from_millis(config.gateway.parent_deadline_ms),
        )?;
        let admission_capacity = config
            .gateway
            .cubes
            .iter()
            .try_fold(config.gateway.max_waiting_requests, |total, cube| {
                total.checked_add(cube.max_in_flight)
            })
            .ok_or("coordinator admission capacity overflow")?;
        Ok(Self {
            admission: Arc::new(Semaphore::new(admission_capacity)),
            admission_capacity,
            config: Arc::new(config),
            orchestrator: Arc::new(orchestrator),
            store,
            active: Arc::new(ActiveScans::default()),
        })
    }

    pub async fn wait_for_idle(&self) {
        loop {
            let idle = self.active.idle.notified();
            if self.active.count.load(Ordering::Acquire) == 0 {
                return;
            }
            idle.await;
        }
    }

    fn begin_scan(&self) -> ActiveGuard {
        self.active.count.fetch_add(1, Ordering::AcqRel);
        ActiveGuard(Arc::clone(&self.active))
    }
}

pub fn router(state: AppState) -> Router {
    let limit = state
        .config
        .server
        .max_upload_mb
        .saturating_mul(1024 * 1024);
    Router::new()
        .route("/healthz", get(|| async { StatusCode::OK }))
        .route("/readyz", get(ready))
        .route(
            "/v1/scan",
            post(submit_scan).layer(middleware::from_fn_with_state(state.clone(), admit_scan)),
        )
        .route("/v1/scan/:job_id", get(get_scan))
        .layer(axum::extract::DefaultBodyLimit::max(limit))
        .with_state(state)
}

async fn ready(State(state): State<AppState>) -> StatusCode {
    if state.store.ready().await && state.orchestrator.ready().await {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn admit_scan(
    State(state): State<AppState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    if !authenticated(&state, request.headers()) {
        return api_error(StatusCode::UNAUTHORIZED, "invalid api key");
    }
    if !state.store.ready().await {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "job store unavailable");
    }
    let Ok(permit) = state.admission.clone().try_acquire_owned() else {
        return api_error(StatusCode::TOO_MANY_REQUESTS, "worker queue full");
    };
    request.extensions_mut().insert(Arc::new(permit));
    next.run(request).await
}

async fn submit_scan(
    State(state): State<AppState>,
    Extension(permit): Extension<Arc<OwnedSemaphorePermit>>,
    mut multipart: Multipart,
) -> Response {
    let mut inputs = Vec::new();
    let mut request_config = None;
    loop {
        let field = match multipart.next_field().await {
            Ok(Some(field)) => field,
            Ok(None) => break,
            Err(_) => return api_error(StatusCode::BAD_REQUEST, "invalid multipart body"),
        };
        let name = field.name().unwrap_or_default().to_owned();
        let filename = field.file_name().map(str::to_owned);
        let bytes = match field.bytes().await {
            Ok(bytes) => bytes,
            Err(_) => return api_error(StatusCode::BAD_REQUEST, "invalid multipart field"),
        };
        if name == "config" && filename.is_none() {
            if request_config.is_some() {
                return api_error(StatusCode::BAD_REQUEST, "duplicate config field");
            }
            let value = match serde_json::from_slice::<Value>(&bytes) {
                Ok(value) => value,
                Err(error) => {
                    return api_error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("invalid config JSON: {error}"),
                    )
                }
            };
            let parsed = match serde_json::from_value::<RequestScanConfig>(value.clone()) {
                Ok(parsed) => parsed,
                Err(error) => {
                    return api_error(
                        StatusCode::UNPROCESSABLE_ENTITY,
                        format!("invalid config JSON: {error}"),
                    )
                }
            };
            if let Err(error) = parsed.validate() {
                return api_error(StatusCode::UNPROCESSABLE_ENTITY, error);
            }
            request_config = Some(value);
            continue;
        }
        let text = match String::from_utf8(bytes.to_vec()) {
            Ok(text) => text,
            Err(_) => return api_error(StatusCode::UNPROCESSABLE_ENTITY, "input is not UTF-8"),
        };
        if !text.trim().is_empty() {
            if inputs.len() == state.admission_capacity {
                return api_error(StatusCode::TOO_MANY_REQUESTS, "worker queue full");
            }
            inputs.push((filename.unwrap_or(name), Arc::<str>::from(text)));
        }
    }
    if inputs.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "no non-empty text or file input");
    }
    let permits = match reserve_parent_permits(Arc::clone(&state.admission), permit, inputs.len()) {
        Ok(permits) => permits,
        Err(()) => return api_error(StatusCode::TOO_MANY_REQUESTS, "worker queue full"),
    };

    let jobs = inputs
        .iter()
        .map(|(source, _)| initial_job(new_job_id(), source))
        .collect::<Vec<_>>();
    if state.store.save_many(&jobs).await.is_err() {
        return api_error(StatusCode::SERVICE_UNAVAILABLE, "job store unavailable");
    }

    let response_jobs = jobs
        .iter()
        .map(|job| {
            let id = job["job_id"].as_str().expect("initial job has an id");
            json!({
                "job_id": id,
                "source": job["source"],
                "status_url": format!("/v1/scan/{id}"),
            })
        })
        .collect::<Vec<_>>();
    for (((source, text), job), task_permit) in inputs.into_iter().zip(jobs).zip(permits) {
        let task_state = state.clone();
        let task_config = request_config.clone();
        let id = job["job_id"]
            .as_str()
            .expect("initial job has an id")
            .to_owned();
        let guard = task_state.begin_scan();
        tokio::spawn(async move {
            let _permit = task_permit;
            let _active = guard;
            let scan = {
                let state = task_state.clone();
                let id = id.clone();
                tokio::spawn(async move {
                    state
                        .orchestrator
                        .scan(&id, &source, text, task_config)
                        .await
                })
                .await
            };
            let completed = match scan {
                Ok(outcome) => {
                    tracing::info!(job_id = %id, metrics = %outcome.metrics, "coordinator scan finished");
                    outcome.job
                }
                Err(_) => failed_job(job),
            };
            if task_state.store.save(&completed).await.is_err() {
                tracing::error!(job_id = %id, "failed to persist terminal coordinator job");
            }
        });
    }
    (StatusCode::ACCEPTED, Json(json!({"jobs": response_jobs}))).into_response()
}

fn reserve_parent_permits(
    admission: Arc<Semaphore>,
    upload_permit: Arc<OwnedSemaphorePermit>,
    parent_count: usize,
) -> Result<Vec<ParentPermit>, ()> {
    debug_assert!(parent_count > 0);
    let additional_count = u32::try_from(parent_count - 1).map_err(|_| ())?;
    let mut additional = admission
        .try_acquire_many_owned(additional_count)
        .map_err(|_| ())?;
    let mut permits = Vec::with_capacity(parent_count);
    permits.push(ParentPermit::Upload {
        _permit: upload_permit,
    });
    for _ in 1..parent_count {
        permits.push(ParentPermit::Reserved {
            _permit: additional
                .split(1)
                .expect("bulk reservation contains one permit per parent"),
        });
    }
    Ok(permits)
}

async fn get_scan(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    if !authenticated(&state, &headers) {
        return api_error(StatusCode::UNAUTHORIZED, "invalid api key");
    }
    if !valid_job_id(&job_id) {
        return api_error(StatusCode::NOT_FOUND, "unknown or expired job_id");
    }
    match state.store.load(&job_id).await {
        Ok(Some(job)) => Json(job).into_response(),
        Ok(None) => api_error(StatusCode::NOT_FOUND, "unknown or expired job_id"),
        Err(_) => api_error(StatusCode::SERVICE_UNAVAILABLE, "job store unavailable"),
    }
}

fn authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
    else {
        return false;
    };
    let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
    state.config.auth.keys.iter().any(|key| {
        bool::from(
            key.key_hash
                .to_ascii_lowercase()
                .as_bytes()
                .ct_eq(digest.as_bytes()),
        )
    })
}

fn new_job_id() -> String {
    format!("job_{}", uuid::Uuid::new_v4().simple())
}

fn valid_job_id(id: &str) -> bool {
    id.starts_with("job_")
        && id.len() <= 128
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn initial_job(id: String, source: &str) -> Value {
    json!({
        "job_id": id,
        "source": source,
        "status": "running",
        "worker": "coordinator",
        "worker_request_id": id,
        "progress": {},
        "categories": {},
        "timings": {
            "queue_wait_ms": 0.0,
            "worker_submit_ms": 0.0,
            "worker_ms": null,
            "total_ms": null,
            "l2_ms": null,
            "l2_cache_hit": null
        }
    })
}

fn failed_job(mut job: Value) -> Value {
    job["status"] = json!("failed");
    job["completion"] = json!({"state":"failed","failures":[{
        "stage":"coordinator",
        "kind":"internal_error",
        "message":"Coordinator scan task failed",
        "retryable":true
    }]});
    job["decision"] = json!("review");
    job
}

fn api_error(status: StatusCode, message: impl Into<String>) -> Response {
    (status, Json(json!({"error": message.into()}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body, Bytes},
        http::Request,
    };
    use std::{
        collections::HashMap,
        sync::{
            atomic::{AtomicBool, AtomicUsize},
            Mutex,
        },
    };
    use tower::ServiceExt;

    async fn redis_fixture() -> (JobStore, Arc<AtomicUsize>) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let writes = Arc::new(AtomicUsize::new(0));
        let recorded = writes.clone();
        let values = Arc::new(Mutex::new(HashMap::<Vec<u8>, Vec<u8>>::new()));
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let recorded = recorded.clone();
                let values = values.clone();
                tokio::spawn(async move {
                    let mut io = BufReader::new(stream);
                    let mut transaction = None::<Vec<Vec<Vec<u8>>>>;
                    loop {
                        let mut line = String::new();
                        if io.read_line(&mut line).await.unwrap_or(0) == 0 {
                            break;
                        }
                        let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
                        let mut args = Vec::new();
                        for _ in 0..count {
                            line.clear();
                            io.read_line(&mut line).await.unwrap();
                            let len: usize =
                                line.trim().strip_prefix('$').unwrap().parse().unwrap();
                            let mut value = vec![0; len + 2];
                            io.read_exact(&mut value).await.unwrap();
                            value.truncate(len);
                            args.push(value);
                        }
                        let response = match args[0].as_slice() {
                            b"CLIENT" => "+OK\r\n".to_owned(),
                            b"PING" => "+PONG\r\n".to_owned(),
                            b"MULTI" => {
                                transaction = Some(Vec::new());
                                "+OK\r\n".to_owned()
                            }
                            b"SET" if transaction.is_some() => {
                                transaction.as_mut().unwrap().push(args);
                                "+QUEUED\r\n".to_owned()
                            }
                            b"EXEC" => {
                                let commands = transaction.take().unwrap();
                                let mut response = format!("*{}\r\n", commands.len());
                                for command in commands {
                                    values
                                        .lock()
                                        .unwrap()
                                        .insert(command[1].clone(), command[2].clone());
                                    recorded.fetch_add(1, Ordering::SeqCst);
                                    response.push_str("+OK\r\n");
                                }
                                response
                            }
                            b"GET" => match values.lock().unwrap().get(&args[1]).cloned() {
                                Some(value) => {
                                    let mut response = format!("${}\r\n", value.len()).into_bytes();
                                    response.extend_from_slice(&value);
                                    response.extend_from_slice(b"\r\n");
                                    String::from_utf8(response).unwrap()
                                }
                                None => "$-1\r\n".to_owned(),
                            },
                            command => {
                                panic!(
                                    "unexpected Redis command: {}",
                                    String::from_utf8_lossy(command)
                                )
                            }
                        };
                        if io.get_mut().write_all(response.as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let store = JobStore::connect(&format!("redis://{address}/"), "test:".into(), 900, 1200)
            .await
            .unwrap();
        (store, writes)
    }

    async fn service_fixture(
        capacity: usize,
    ) -> (
        AppState,
        Arc<AtomicUsize>,
        Arc<AtomicUsize>,
        Arc<AtomicBool>,
    ) {
        use crate::config::{
            CoordinatorApiKey, CoordinatorAuthConfig, Cube, GatewayConfig, ServerConfig,
        };

        let cube_posts = Arc::new(AtomicUsize::new(0));
        let posted = cube_posts.clone();
        let cube_release = Arc::new(AtomicBool::new(false));
        let released = cube_release.clone();
        let cube_app = Router::new()
            .route("/readyz", get(|| async { StatusCode::OK }))
            .route(
                "/v1/scan",
                post(move |body: Bytes| {
                    let request = posted.fetch_add(1, Ordering::SeqCst);
                    async move {
                        let body = String::from_utf8(body.to_vec()).unwrap();
                        let jobs = (0..body.matches("filename=").count())
                            .map(|index| {
                                let id = format!("job_cube_{request}_{index}");
                                json!({
                                    "job_id": id,
                                    "source": format!("chunk-{index}.txt"),
                                    "status_url": format!("/v1/scan/{id}")
                                })
                            })
                            .collect::<Vec<_>>();
                        (StatusCode::ACCEPTED, Json(json!({"jobs": jobs})))
                    }
                }),
            )
            .route(
                "/v1/scan/:job_id",
                get(move |Path(job_id): Path<String>| {
                    let complete = released.load(Ordering::SeqCst);
                    async move {
                        if !complete {
                            return Json(json!({"job_id": job_id, "status": "running"}));
                        }
                        Json(json!({
                            "job_id": job_id,
                            "source": "chunk.txt",
                            "status": "completed",
                            "worker": "cube-worker",
                            "worker_request_id": "cube-request",
                            "progress": {},
                            "categories": {
                                "threat": {
                                    "accepted": false,
                                    "class_name": "safe",
                                    "confidence": 0.99
                                }
                            },
                            "completion": {"state": "complete"},
                            "decision": "allow",
                            "timings": {
                                "queue_wait_ms": 0.0,
                                "worker_submit_ms": 0.0,
                                "worker_ms": 1.0,
                                "total_ms": 1.0,
                                "l2_ms": 0.0,
                                "l2_cache_hit": false
                            }
                        }))
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cube_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, cube_app).await.unwrap() });
        let cube = Cube {
            name: "cube".into(),
            url: cube_url,
            max_in_flight: 3,
        };
        let (store, redis_writes) = redis_fixture().await;
        let config = CoordinatorConfig {
            server: ServerConfig {
                bind: "127.0.0.1:0".parse().unwrap(),
                max_upload_mb: 1,
            },
            auth: CoordinatorAuthConfig {
                keys: vec![CoordinatorApiKey {
                    key_hash: format!("{:x}", Sha256::digest(b"test-key")),
                }],
            },
            gateway: GatewayConfig {
                redis_url_file: "unused".into(),
                cube_token_file: "unused".into(),
                cubes: vec![cube.clone()],
                redis_prefix: "test:".into(),
                retention_secs: 900,
                max_waiting_requests: 0,
                chunk_bytes: 4096,
                chunks_per_batch: 4,
                parent_deadline_ms: 1000,
            },
        };
        let state = AppState {
            config: Arc::new(config),
            orchestrator: Arc::new(
                CubeOrchestrator::new(
                    vec![cube],
                    "cube-key".into(),
                    4096,
                    4,
                    Duration::from_secs(1),
                )
                .unwrap(),
            ),
            store,
            admission: Arc::new(Semaphore::new(capacity)),
            admission_capacity: capacity,
            active: Arc::new(ActiveScans::default()),
        };
        (state, redis_writes, cube_posts, cube_release)
    }

    fn multipart_request(config: Option<&str>, inputs: usize) -> Request<Body> {
        let boundary = "test-boundary";
        let mut body = String::new();
        if let Some(config) = config {
            body.push_str(&format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"config\"\r\n\r\n{config}\r\n"
            ));
        }
        for index in 0..inputs {
            body.push_str(&format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"input-{index}\"\r\n\r\ntext-{index}\r\n"
            ));
        }
        body.push_str(&format!("--{boundary}--\r\n"));
        Request::builder()
            .method("POST")
            .uri("/v1/scan")
            .header(header::AUTHORIZATION, "Bearer test-key")
            .header(
                header::CONTENT_TYPE,
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(Body::from(body))
            .unwrap()
    }

    #[test]
    fn initial_job_matches_entrypoint_shape() {
        let job = initial_job("job_123".into(), "input.txt");
        assert_eq!(job["job_id"], "job_123");
        assert_eq!(job["source"], "input.txt");
        assert_eq!(job["status"], "running");
        assert!(job["progress"].is_object());
        assert!(job["categories"].is_object());
        assert!(job.get("completion").is_none());
        assert!(job.get("decision").is_none());
    }

    #[test]
    fn job_ids_are_bounded_before_redis_lookup() {
        assert!(valid_job_id("job_0123-abcd"));
        assert!(!valid_job_id("request_0123"));
        assert!(!valid_job_id("job_../../other"));
    }

    #[test]
    fn admission_reserves_and_releases_one_per_parent_atomically() {
        let admission = Arc::new(Semaphore::new(3));
        let upload = Arc::new(admission.clone().try_acquire_owned().unwrap());
        let mut permits = reserve_parent_permits(admission.clone(), upload, 3).unwrap();
        assert_eq!(admission.available_permits(), 0);

        permits.pop();
        assert_eq!(admission.available_permits(), 1);
        drop(permits);
        assert_eq!(admission.available_permits(), 3);

        let upload = Arc::new(admission.clone().try_acquire_owned().unwrap());
        assert!(reserve_parent_permits(admission.clone(), upload, 4).is_err());
        assert_eq!(
            admission.available_permits(),
            3,
            "failed bulk reservation must not retain any parent slots"
        );
    }

    #[tokio::test]
    async fn multipart_overflow_returns_429_before_redis_or_cube_dispatch() {
        let (state, redis_writes, cube_posts, _) = service_fixture(3).await;
        let response = router(state)
            .oneshot(multipart_request(None, 4))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(redis_writes.load(Ordering::SeqCst), 0);
        assert_eq!(cube_posts.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn invalid_request_configs_return_422_without_side_effects() {
        for config in [
            r#"{"unknown":true}"#,
            r#"{"categories":["not-a-category"]}"#,
            r#"{"gates":{"policy":{"degraded_factor":1.1}}}"#,
        ] {
            let (state, redis_writes, cube_posts, _) = service_fixture(3).await;
            let response = router(state)
                .oneshot(multipart_request(Some(config), 1))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert_eq!(redis_writes.load(Ordering::SeqCst), 0);
            assert_eq!(cube_posts.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn router_authentication_has_no_side_effects_for_missing_or_wrong_bearers() {
        for authorization in [None, Some("Bearer wrong-key")] {
            let (state, redis_writes, cube_posts, _) = service_fixture(3).await;
            let admission = state.admission.clone();
            let mut request = multipart_request(None, 1);
            match authorization {
                Some(value) => {
                    request
                        .headers_mut()
                        .insert(header::AUTHORIZATION, value.parse().unwrap());
                }
                None => {
                    request.headers_mut().remove(header::AUTHORIZATION);
                }
            }
            let response = router(state).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(redis_writes.load(Ordering::SeqCst), 0);
            assert_eq!(cube_posts.load(Ordering::SeqCst), 0);
            assert_eq!(admission.available_permits(), 3);
        }

        for authorization in [None, Some("Bearer wrong-key")] {
            let (state, redis_writes, cube_posts, _) = service_fixture(3).await;
            let admission = state.admission.clone();
            let mut request = Request::builder()
                .uri("/v1/scan/job_test")
                .body(Body::empty())
                .unwrap();
            if let Some(value) = authorization {
                request
                    .headers_mut()
                    .insert(header::AUTHORIZATION, value.parse().unwrap());
            }
            let response = router(state).oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(redis_writes.load(Ordering::SeqCst), 0);
            assert_eq!(cube_posts.load(Ordering::SeqCst), 0);
            assert_eq!(admission.available_permits(), 3);
        }
    }

    #[tokio::test]
    async fn authenticated_router_persists_running_then_terminal_job() {
        let (state, redis_writes, cube_posts, cube_release) = service_fixture(3).await;
        let app = router(state.clone());

        let response = app
            .clone()
            .oneshot(multipart_request(None, 1))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        let accepted = &body["jobs"][0];
        let job_id = accepted["job_id"].as_str().unwrap();
        let status_url = accepted["status_url"].as_str().unwrap();
        assert_eq!(accepted["source"], "input-0");

        let get = |uri: &str| {
            Request::builder()
                .uri(uri)
                .header(header::AUTHORIZATION, "Bearer test-key")
                .body(Body::empty())
                .unwrap()
        };
        let running = app.clone().oneshot(get(status_url)).await.unwrap();
        assert_eq!(running.status(), StatusCode::OK);
        let running: Value =
            serde_json::from_slice(&to_bytes(running.into_body(), 1024 * 1024).await.unwrap())
                .unwrap();
        assert_eq!(running["job_id"], job_id);
        assert_eq!(running["status"], "running");
        assert_eq!(running["worker"], "coordinator");

        tokio::time::timeout(Duration::from_secs(1), async {
            while cube_posts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        cube_release.store(true, Ordering::SeqCst);

        let terminal = tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let response = app.clone().oneshot(get(status_url)).await.unwrap();
                assert_eq!(response.status(), StatusCode::OK);
                let job: Value = serde_json::from_slice(
                    &to_bytes(response.into_body(), 1024 * 1024).await.unwrap(),
                )
                .unwrap();
                if job["status"] == "completed" {
                    break job;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(terminal["job_id"], job_id);
        assert_eq!(terminal["worker_request_id"], job_id);
        assert_eq!(terminal["completion"]["state"], "complete");
        assert_eq!(terminal["decision"], "allow");
        assert_eq!(redis_writes.load(Ordering::SeqCst), 2);
        assert_eq!(cube_posts.load(Ordering::SeqCst), 1);
        state.wait_for_idle().await;
        assert_eq!(state.admission.available_permits(), 3);
    }
}
