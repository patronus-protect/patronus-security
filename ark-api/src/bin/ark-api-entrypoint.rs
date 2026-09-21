use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[path = "entrypoint/events.rs"]
mod events;
#[path = "entrypoint/sse.rs"]
mod sse;
#[path = "entrypoint/timings.rs"]
mod timings;
#[path = "entrypoint/worker_pool.rs"]
mod worker_pool;
use events::collect_events;
#[cfg(test)]
use events::{collect_events_inner, compact_result};
use timings::JobTimings;
use worker_pool::{WorkerLease, WorkerPool};

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use clap::Parser;
use futures::StreamExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const ACTIVE_TTL_SECS: u64 = 10 * 60;
const REDIS_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);

async fn redis_deadline<T>(
    operation: impl std::future::Future<Output = redis::RedisResult<T>>,
) -> redis::RedisResult<T> {
    tokio::time::timeout(REDIS_OPERATION_TIMEOUT, operation)
        .await
        .map_err(|_| {
            redis::RedisError::from(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Redis operation deadline exceeded",
            ))
        })?
}

async fn connect_redis(url: &str) -> redis::RedisResult<redis::aio::ConnectionManager> {
    let config = redis::aio::ConnectionManagerConfig::new()
        .set_connection_timeout(Duration::from_secs(1))
        .set_response_timeout(Duration::from_secs(1))
        .set_number_of_retries(2)
        .set_max_delay(100);
    redis_deadline(redis::Client::open(url)?.get_connection_manager_with_config(config)).await
}

#[derive(Parser)]
#[command(name = "ark-api-entrypoint")]
struct Args {
    #[arg(long, default_value = "/etc/ark-api/entrypoint.yaml")]
    config: PathBuf,
}

#[derive(Deserialize)]
struct RawConfig {
    server: ServerConfig,
    auth: AuthConfig,
    gateway: GatewayConfig,
}

#[derive(Deserialize)]
struct ServerConfig {
    bind: String,
}

#[derive(Deserialize)]
struct AuthConfig {
    keys: Vec<ApiKey>,
}

#[derive(Deserialize)]
struct ApiKey {
    key_hash: String,
}

#[derive(Clone, Deserialize)]
struct GatewayConfig {
    redis_url: String,
    worker_token: String,
    workers: Vec<WorkerConfig>,
    #[serde(default = "default_retention_secs")]
    retention_secs: u64,
    #[serde(default = "default_max_waiting")]
    max_waiting_requests: usize,
    // Bounds submissions; a multipart submission retains its slot until all jobs finish.
    #[serde(default = "default_max_inflight_per_worker")]
    max_inflight_per_worker: usize,
}

fn default_max_inflight_per_worker() -> usize {
    1
}

fn default_max_waiting() -> usize {
    64
}

fn default_retention_secs() -> u64 {
    90
}

#[derive(Clone, Deserialize)]
struct WorkerConfig {
    name: String,
    url: String,
}

#[derive(Clone)]
struct AppState {
    client: reqwest::Client,
    redis: redis::aio::ConnectionManager,
    worker_token: String,
    worker_pool: Arc<WorkerPool>,
    key_hashes: Vec<String>,
    retention_secs: u64,
}

#[derive(Clone)]
struct JobOwner(String);

#[derive(Clone, Serialize, Deserialize)]
struct Job {
    job_id: String,
    #[serde(default)]
    owner_key_hash: String,
    source: String,
    status: String,
    worker: String,
    worker_request_id: String,
    #[serde(default)]
    progress: HashMap<String, Value>,
    #[serde(default)]
    categories: HashMap<String, Value>,
    #[serde(default)]
    detectors: HashMap<String, Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
    #[serde(default)]
    timings: JobTimings,
}

impl Job {
    fn record_detector(&mut self, category: &str, model: &str) {
        let models = self.detectors.entry(category.to_string()).or_default();
        if !models.iter().any(|existing| existing == model) {
            models.push(model.to_string());
        }
    }
}

fn job_key(job_id: &str) -> String {
    format!("ark:job:{job_id}")
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
}

fn authenticated(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let token = bearer(headers)?;
    let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
    state
        .key_hashes
        .iter()
        .find(|hash| bool::from(hash.as_bytes().ct_eq(digest.as_bytes())))
        .map(|_| digest)
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": "invalid api key" })),
    )
        .into_response()
}

async fn save_job(state: &AppState, job: &Job) -> Result<(), redis::RedisError> {
    let ttl = if job.status == "completed" || job.status == "failed" {
        state.retention_secs
    } else {
        ACTIVE_TTL_SECS
    };
    let mut connection = state.redis.clone();
    let payload = serde_json::to_string(job).expect("job serialization must succeed");
    redis_deadline(connection.set_ex(job_key(&job.job_id), payload, ttl)).await
}

async fn load_job(state: &AppState, job_id: &str) -> Result<Option<Job>, redis::RedisError> {
    let mut connection = state.redis.clone();
    let payload: Option<String> = redis_deadline(connection.get(job_key(job_id))).await?;
    Ok(payload.and_then(|value| serde_json::from_str(&value).ok()))
}

fn final_decision(job: &Job) -> String {
    if job
        .completion
        .as_ref()
        .and_then(|value| value.get("state"))
        .and_then(Value::as_str)
        != Some("complete")
    {
        return "review".to_string();
    }
    let has_risk = job.categories.values().any(|result| {
        let class = result.get("class_name").and_then(Value::as_str);
        let accepted = result
            .get("accepted")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        accepted || !matches!(class, Some("safe") | Some("benign"))
    });
    if has_risk { "block" } else { "allow" }.to_string()
}

fn job_owned_by(job: &Job, owner: &str) -> bool {
    !job.owner_key_hash.is_empty() && job.owner_key_hash == owner
}

async fn admit_scan(
    State(state): State<Arc<AppState>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(owner) = authenticated(&state, request.headers()) else {
        return unauthorized();
    };
    let admission = match state.worker_pool.reserve() {
        Ok(admission) => admission,
        Err(error) => {
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error": error}))).into_response()
        }
    };
    request.extensions_mut().insert(admission);
    request.extensions_mut().insert(JobOwner(owner));
    next.run(request).await
}

async fn submit_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(admission): Extension<Arc<tokio::sync::OwnedSemaphorePermit>>,
    Extension(JobOwner(owner)): Extension<JobOwner>,
    body: Bytes,
) -> Response {
    let submitted = Instant::now();
    let lease = match tokio::time::timeout(
        Duration::from_secs(15),
        state.worker_pool.acquire_reserved(admission),
    )
    .await
    {
        Ok(Ok(lease)) => lease,
        Ok(Err(error)) => {
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error":error}))).into_response()
        }
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"no worker became available within 15 seconds"})),
            )
                .into_response()
        }
    };
    let worker = &lease.worker;
    let queue_wait_ms = submitted.elapsed().as_secs_f64() * 1000.0;
    let upstream_started = Instant::now();
    let mut request = state
        .client
        .post(format!("{}/v1/scan", worker.url.trim_end_matches('/')))
        .bearer_auth(&state.worker_token)
        .header("x-ark-worker-instance", &lease.instance_id)
        .header("x-ark-worker-epoch", lease.epoch.to_string())
        .body(body);
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    lease.start_dispatch();
    let response = match request.timeout(Duration::from_secs(10)).send().await {
        Ok(response) => response,
        Err(_) => {
            lease.quarantine();
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":"worker unavailable"})),
            )
                .into_response();
        }
    };
    let status = response.status();
    if !status.is_success() {
        // Multipart/body-limit rejections can be plain text, not JSON. The
        // rejected request did not occupy this worker and must not quarantine it.
        if status == StatusCode::CONFLICT || status.is_server_error() {
            lease.quarantine();
        } else {
            lease.finished();
        }
        let payload = response.json::<Value>().await.unwrap_or_else(
            |_| json!({"error":format!("worker rejected request with HTTP {}", status.as_u16())}),
        );
        return (status, Json(payload)).into_response();
    }
    let payload: Value = match response.json().await {
        Ok(payload) => payload,
        Err(_) => {
            lease.quarantine();
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":"invalid worker response"})),
            )
                .into_response();
        }
    };
    if payload
        .get("jobs")
        .and_then(Value::as_array)
        .is_none_or(|jobs| {
            jobs.is_empty()
                || jobs
                    .iter()
                    .any(|job| job.get("request_id").and_then(Value::as_str).is_none())
        })
    {
        lease.quarantine();
        return (
            StatusCode::BAD_GATEWAY,
            Json(json!({"error":"invalid worker job response"})),
        )
            .into_response();
    }
    lease.accepted(payload["jobs"].as_array().expect("validated jobs").len());
    let mut jobs = Vec::new();
    for worker_job in payload
        .get("jobs")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let Some(worker_request_id) = worker_job.get("request_id").and_then(Value::as_str) else {
            continue;
        };
        let job_id = format!("job_{}", Uuid::new_v4().simple());
        tracing::debug!(job_id, worker = %worker.name, worker_submit_ms = upstream_started.elapsed().as_secs_f64() * 1_000.0, "worker accepted scan");
        let job = Job {
            job_id: job_id.clone(),
            owner_key_hash: owner.clone(),
            source: worker_job
                .get("source")
                .and_then(Value::as_str)
                .unwrap_or("input")
                .to_string(),
            status: "running".to_string(),
            worker: worker.name.clone(),
            worker_request_id: worker_request_id.to_string(),
            progress: HashMap::new(),
            categories: HashMap::new(),
            detectors: HashMap::new(),
            completion: None,
            decision: None,
            timings: JobTimings {
                queue_wait_ms,
                worker_submit_ms: upstream_started.elapsed().as_secs_f64() * 1000.0,
                ..Default::default()
            },
        };
        if save_job(&state, &job).await.is_err() {
            lease.quarantine();
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"job store unavailable"})),
            )
                .into_response();
        }
        jobs.push(json!({
            "job_id": job_id,
            "source": job.source,
            "status_url": format!("/v1/scan/{job_id}"),
        }));
        tokio::spawn(collect_events(
            (*state).clone(),
            job,
            lease.clone(),
            worker_request_id.to_string(),
            submitted,
            upstream_started,
        ));
    }
    (StatusCode::ACCEPTED, Json(json!({"jobs": jobs}))).into_response()
}

async fn submit_scan_sync(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Extension(admission): Extension<Arc<tokio::sync::OwnedSemaphorePermit>>,
    body: Bytes,
) -> Response {
    let lease = match tokio::time::timeout(
        Duration::from_secs(15),
        state.worker_pool.acquire_reserved(admission),
    )
    .await
    {
        Ok(Ok(lease)) => lease,
        Ok(Err(error)) => {
            return (StatusCode::TOO_MANY_REQUESTS, Json(json!({"error":error}))).into_response()
        }
        Err(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"no worker became available within 15 seconds"})),
            )
                .into_response()
        }
    };
    let worker = &lease.worker;
    let mut request = state
        .client
        .post(format!("{}/v1/scan/sync", worker.url.trim_end_matches('/')))
        .bearer_auth(&state.worker_token)
        .header("x-ark-worker-instance", &lease.instance_id)
        .header("x-ark-worker-epoch", lease.epoch.to_string())
        .body(body);
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    lease.start_dispatch();
    let response = match request
        .timeout(Duration::from_secs(ACTIVE_TTL_SECS - 10))
        .send()
        .await
    {
        Ok(response) => response,
        Err(_) => {
            lease.quarantine();
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":"worker unavailable"})),
            )
                .into_response();
        }
    };
    let status = response.status();
    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let payload = match response.bytes().await {
        Ok(payload) => payload,
        Err(_) => {
            lease.quarantine();
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":"invalid worker response"})),
            )
                .into_response();
        }
    };
    if status.is_success() || (!status.is_server_error() && status != StatusCode::CONFLICT) {
        lease.finished();
    } else {
        lease.quarantine();
    }
    let mut response = Response::builder().status(status);
    if let Some(content_type) = content_type {
        response = response.header(header::CONTENT_TYPE, content_type);
    }
    response
        .body(axum::body::Body::from(payload))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn get_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    let Some(owner) = authenticated(&state, &headers) else {
        return unauthorized();
    };
    match load_job(&state, &job_id).await {
        Ok(Some(job)) if job_owned_by(&job, &owner) => {
            let mut response = serde_json::to_value(job).expect("job serialization must succeed");
            response.as_object_mut().unwrap().remove("owner_key_hash");
            Json(response).into_response()
        }
        Ok(Some(_)) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"unknown or expired job_id"})),
        )
            .into_response(),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error":"unknown or expired job_id"})),
        )
            .into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"error":"job store unavailable"})),
        )
            .into_response(),
    }
}

async fn healthz() -> StatusCode {
    StatusCode::OK
}

async fn readyz(State(state): State<Arc<AppState>>) -> StatusCode {
    let mut connection = state.redis.clone();
    match tokio::time::timeout(
        std::time::Duration::from_secs(1),
        redis::cmd("PING").query_async::<String>(&mut connection),
    )
    .await
    {
        Ok(Ok(pong)) if pong == "PONG" && state.worker_pool.ready() => StatusCode::OK,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config: RawConfig = serde_yaml::from_reader(std::fs::File::open(Args::parse().config)?)?;
    if config.gateway.workers.is_empty() {
        return Err("gateway.workers must not be empty".into());
    }
    let mut names = std::collections::HashSet::new();
    let mut urls = std::collections::HashSet::new();
    for worker in &config.gateway.workers {
        if worker.name.is_empty()
            || !names.insert(&worker.name)
            || !urls.insert(worker.url.trim_end_matches('/'))
        {
            return Err("gateway.workers must have distinct names and URLs".into());
        }
    }
    if config.gateway.max_waiting_requests > 1024 {
        return Err("gateway.max_waiting_requests must not exceed 1024".into());
    }
    if !(1..=2).contains(&config.gateway.max_inflight_per_worker) {
        return Err("gateway.max_inflight_per_worker must be between 1 and 2".into());
    }
    let bind: SocketAddr = config.server.bind.parse()?;
    let redis = connect_redis(config.gateway.redis_url.as_str()).await?;
    let state = Arc::new(AppState {
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()?,
        redis,
        worker_token: config.gateway.worker_token,
        worker_pool: WorkerPool::with_capacity(
            config.gateway.workers,
            config.gateway.max_waiting_requests,
            config.gateway.max_inflight_per_worker,
        ),
        key_hashes: config
            .auth
            .keys
            .into_iter()
            .map(|key| key.key_hash)
            .collect(),
        retention_secs: config.gateway.retention_secs,
    });
    state
        .worker_pool
        .spawn_monitor(state.client.clone(), state.worker_token.clone());
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route(
            "/v1/scan",
            post(submit_scan).layer(middleware::from_fn_with_state(state.clone(), admit_scan)),
        )
        .route(
            "/v1/scan/sync",
            post(submit_scan_sync).layer(middleware::from_fn_with_state(state.clone(), admit_scan)),
        )
        .route("/v1/scan/:job_id", get(get_scan))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn recording_store() -> (
        redis::aio::ConnectionManager,
        Arc<std::sync::Mutex<Vec<Job>>>,
        tokio::task::JoinHandle<()>,
    ) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let writes = Arc::new(std::sync::Mutex::new(Vec::new()));
        let recorded = writes.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            loop {
                let mut line = String::new();
                if stream.read_line(&mut line).await.unwrap() == 0 {
                    break;
                }
                let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
                let mut args = Vec::new();
                for _ in 0..count {
                    line.clear();
                    stream.read_line(&mut line).await.unwrap();
                    let len: usize = line.trim().strip_prefix('$').unwrap().parse().unwrap();
                    let mut value = vec![0; len + 2];
                    stream.read_exact(&mut value).await.unwrap();
                    value.truncate(len);
                    args.push(value);
                }
                match args[0].as_slice() {
                    b"CLIENT" => {}
                    b"SETEX" => recorded
                        .lock()
                        .unwrap()
                        .push(serde_json::from_slice(&args[3]).unwrap()),
                    command => panic!("collector must never reload its job: {command:?}"),
                }
                stream.get_mut().write_all(b"+OK\r\n").await.unwrap();
            }
        });
        let redis = connect_redis(&format!("redis://{address}/")).await.unwrap();
        (redis, writes, server)
    }

    #[tokio::test]
    async fn collector_coalesces_progress_without_reads_and_persists_terminal_states() {
        let (redis, writes, store) = recording_store().await;
        let frames = (0..100)
            .map(|step| {
                format!("event: progress\ndata: {{\"category\":\"injection\",\"step\":{step}}}\n\n")
            })
            .collect::<String>();
        let complete = format!(
            "{frames}event: finished\ndata: {{\"completion\":{{\"state\":\"complete\"}}}}\n\n"
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/v1/scan/complete/events",
                get(move || {
                    let complete = complete.clone();
                    async move { complete }
                }),
            )
            .route(
                "/v1/scan/interrupted/events",
                get(|| async {
                    "event: progress\ndata: {\"category\":\"injection\",\"step\":7}\n\n"
                }),
            );
        let worker_server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let state = AppState {
            client: reqwest::Client::new(),
            redis,
            worker_token: String::new(),
            worker_pool: WorkerPool::healthy_test_pool(),
            key_hashes: Vec::new(),
            retention_secs: 90,
        };
        let worker = WorkerConfig {
            name: "test".into(),
            url: format!("http://{address}"),
        };
        let mut job = completed_job(HashMap::new());
        job.status = "running".into();
        assert!(
            collect_events_inner(
                &state,
                &mut job,
                &worker,
                "complete",
                Instant::now(),
                Instant::now()
            )
            .await
        );
        {
            let writes = writes.lock().unwrap();
            assert_eq!(
                writes.len(),
                1,
                "progress burst should be covered by the terminal snapshot"
            );
            assert_eq!(writes[0].status, "completed");
            assert_eq!(writes[0].progress["injection"]["step"], 99);
        }
        // An interrupted stream must persist failure from the local job as well.
        let mut lease = state.worker_pool.acquire().await.unwrap();
        Arc::get_mut(&mut lease).unwrap().worker.url = worker.url;
        lease.start_dispatch();
        collect_events(
            state,
            job,
            lease,
            "interrupted".into(),
            Instant::now(),
            Instant::now(),
        )
        .await;
        let writes = writes.lock().unwrap();
        let failed = writes.last().unwrap();
        assert_eq!(failed.status, "failed");
        assert_eq!(failed.decision.as_deref(), Some("review"));
        assert_eq!(failed.progress["injection"]["step"], 7);
        worker_server.abort();
        store.abort();
    }

    #[tokio::test]
    async fn admission_rejects_before_body_read_and_releases_failed_or_cancelled_uploads() {
        use axum::body::Body;
        use tower::ServiceExt;
        let (redis, _, store) = recording_store().await;
        let pool = WorkerPool::healthy_test_pool();
        let state = Arc::new(AppState {
            client: reqwest::Client::new(),
            redis,
            worker_token: String::new(),
            worker_pool: pool.clone(),
            key_hashes: vec![format!("{:x}", Sha256::digest(b"test-key"))],
            retention_secs: 90,
        });
        let app = Router::new()
            .route(
                "/v1/scan",
                post(submit_scan).layer(middleware::from_fn_with_state(state.clone(), admit_scan)),
            )
            .with_state(state);
        let unread_body = || {
            Body::from_stream(futures::stream::poll_fn(
                |_| -> std::task::Poll<Option<Result<Bytes, std::io::Error>>> {
                    panic!("rejected body must not be polled")
                },
            ))
        };
        let request = |body, authenticated| {
            let mut request = Request::builder().uri("/v1/scan").method("POST");
            if authenticated {
                request = request.header(header::AUTHORIZATION, "Bearer test-key");
            }
            request.body(body).unwrap()
        };
        assert_eq!(
            app.clone()
                .oneshot(request(unread_body(), false))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
        let reserved = pool.reserve().unwrap();
        assert_eq!(
            app.clone()
                .oneshot(request(unread_body(), true))
                .await
                .unwrap()
                .status(),
            StatusCode::TOO_MANY_REQUESTS
        );
        drop(reserved);
        let broken = Body::from_stream(futures::stream::once(async {
            Err::<Bytes, _>(std::io::Error::other("upload failed"))
        }));
        assert_eq!(
            app.clone()
                .oneshot(request(broken, true))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
        drop(pool.reserve().expect("body failure must release admission"));
        let (polled, started) = tokio::sync::oneshot::channel();
        let mut polled = Some(polled);
        let pending = Body::from_stream(futures::stream::poll_fn(
            move |_| -> std::task::Poll<Option<Result<Bytes, std::io::Error>>> {
                if let Some(polled) = polled.take() {
                    let _ = polled.send(());
                }
                std::task::Poll::Pending
            },
        ));
        let upload = tokio::spawn(app.oneshot(request(pending, true)));
        started.await.unwrap();
        assert!(
            pool.reserve().is_err(),
            "upload must hold admission before it gets a worker"
        );
        upload.abort();
        let _ = upload.await;
        drop(
            pool.reserve()
                .expect("cancelled upload must release admission"),
        );
        store.abort();
    }

    #[tokio::test]
    async fn redis_disconnect_changes_readiness_and_recovers_job_storage() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        // Minimal RESP peer: terminate the first PING, then serve the reconnect.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut payload = Vec::new();
            for connection_index in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                loop {
                    let mut line = String::new();
                    if stream.read_line(&mut line).await.unwrap() == 0 {
                        break;
                    }
                    let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
                    let mut args = Vec::new();
                    for _ in 0..count {
                        line.clear();
                        stream.read_line(&mut line).await.unwrap();
                        let len: usize = line.trim().strip_prefix('$').unwrap().parse().unwrap();
                        let mut value = vec![0; len + 2];
                        stream.read_exact(&mut value).await.unwrap();
                        value.truncate(len);
                        args.push(value);
                    }
                    let response = match args[0].as_slice() {
                        b"CLIENT" => b"+OK\r\n".to_vec(),
                        b"PING" if connection_index == 0 => break,
                        b"PING" => b"+PONG\r\n".to_vec(),
                        b"SETEX" => {
                            payload = args[3].clone();
                            b"+OK\r\n".to_vec()
                        }
                        b"GET" => format!(
                            "${}\r\n{}\r\n",
                            payload.len(),
                            String::from_utf8_lossy(&payload)
                        )
                        .into_bytes(),
                        command => panic!("unexpected Redis command: {command:?}"),
                    };
                    stream.get_mut().write_all(&response).await.unwrap();
                }
            }
        });
        let client = redis::Client::open(format!("redis://{address}/")).unwrap();
        let state = Arc::new(AppState {
            client: reqwest::Client::new(),
            redis: client.get_connection_manager().await.unwrap(),
            worker_token: String::new(),
            worker_pool: WorkerPool::healthy_test_pool(),
            key_hashes: Vec::new(),
            retention_secs: 90,
        });
        assert_eq!(
            readyz(State(Arc::clone(&state))).await,
            StatusCode::SERVICE_UNAVAILABLE
        );
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while readyz(State(Arc::clone(&state))).await != StatusCode::OK {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("Redis connection must recover");
        let job = completed_job(HashMap::new());
        save_job(&state, &job).await.unwrap();
        let restored = load_job(&state, &job.job_id).await.unwrap().unwrap();
        assert_eq!(
            serde_json::to_value(&restored).unwrap(),
            serde_json::to_value(&job).unwrap()
        );
        server.abort();
    }

    #[tokio::test]
    async fn connected_but_silent_redis_bounds_reads_writes_and_initial_connect() {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
        use tokio::net::TcpListener;

        // Complete the Redis handshake, then keep TCP open without answering
        // actual commands. A healthy socket must not imply a healthy store.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut peers = tokio::task::JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                peers.spawn(async move {
                    let mut stream = BufReader::new(stream);
                    loop {
                        let mut line = String::new();
                        if stream.read_line(&mut line).await.unwrap() == 0 {
                            break;
                        }
                        let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
                        let mut args = Vec::new();
                        for _ in 0..count {
                            line.clear();
                            stream.read_line(&mut line).await.unwrap();
                            let len: usize =
                                line.trim().strip_prefix('$').unwrap().parse().unwrap();
                            let mut value = vec![0; len + 2];
                            stream.read_exact(&mut value).await.unwrap();
                            value.truncate(len);
                            args.push(value);
                        }
                        if args[0].as_slice() == b"CLIENT" {
                            stream.get_mut().write_all(b"+OK\r\n").await.unwrap();
                        }
                    }
                });
            }
        });
        let redis = connect_redis(&format!("redis://{address}/")).await.unwrap();
        let state = Arc::new(AppState {
            client: reqwest::Client::new(),
            redis,
            worker_token: String::new(),
            worker_pool: WorkerPool::healthy_test_pool(),
            key_hashes: Vec::new(),
            retention_secs: 90,
        });
        let job = completed_job(HashMap::new());
        let began = Instant::now();
        let (saved, loaded, readiness) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                save_job(&state, &job),
                load_job(&state, &job.job_id),
                readyz(State(state.clone()))
            )
        })
        .await
        .expect("silent Redis must not retain HTTP or collector tasks");
        assert!(saved.unwrap_err().is_timeout());
        assert!(loaded.err().expect("read must fail").is_timeout());
        assert_eq!(readiness, StatusCode::SERVICE_UNAVAILABLE);
        assert!(began.elapsed() < Duration::from_secs(3));
        server.abort();
        let _ = server.await;

        // A peer can also accept TCP but never complete the CLIENT handshake.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut streams = Vec::new();
            loop {
                streams.push(listener.accept().await.unwrap().0);
            }
        });
        let connected = tokio::time::timeout(
            Duration::from_secs(3),
            connect_redis(&format!("redis://{address}/")),
        )
        .await
        .expect("initial Redis handshake/retries must have a deadline");
        assert!(connected.is_err());
        server.abort();
    }

    fn completed_job(categories: HashMap<String, Value>) -> Job {
        Job {
            job_id: "job_test".to_string(),
            owner_key_hash: "owner-hash".to_string(),
            source: "text".to_string(),
            status: "completed".to_string(),
            worker: "ark-api-1".to_string(),
            worker_request_id: "rq-test".to_string(),
            progress: HashMap::new(),
            categories,
            detectors: HashMap::new(),
            completion: Some(json!({"state": "complete"})),
            decision: None,
            timings: JobTimings::default(),
        }
    }

    #[test]
    fn job_access_requires_its_creating_key() {
        let mut job = completed_job(HashMap::new());
        assert!(job_owned_by(&job, "owner-hash"));
        assert!(!job_owned_by(&job, "other-hash"));
        job.owner_key_hash.clear();
        assert!(!job_owned_by(&job, ""));
    }

    #[test]
    fn job_response_lists_all_reported_detector_models() {
        let mut job = completed_job(HashMap::new());
        job.record_detector("dlp", "native:dlp");
        job.record_detector("dlp", "native:secret_transfer");
        let response = serde_json::to_value(job).unwrap();
        assert_eq!(
            response["detectors"]["dlp"],
            json!(["native:dlp", "native:secret_transfer"])
        );
    }

    #[test]
    fn completed_job_response_contains_layer_decision_evidence() {
        let result = compact_result(&json!({
            "category": "threat",
            "class_name": "malicious",
            "confidence": 0.98,
            "level": "L3",
            "model": "unified-multitask-model-augmented-v3",
            "decision": {"recommendation": {"accepted": true}},
            "layers": [
                {"details": {"decision_evidence": {
                    "stage": "l3",
                    "decisive_chunks": [{"chunk_id": 3, "span": {"start": 120, "end": 180}}]
                }}},
                {"details": {"decision_evidence": null}}
            ]
        }));
        let mut categories = HashMap::new();
        categories.insert("threat".to_string(), result);
        let job = completed_job(categories);

        let response = serde_json::to_value(job).unwrap();

        assert_eq!(
            response["categories"]["threat"]["decision_evidence"]["decisive_chunks"][0]["chunk_id"],
            3
        );
    }

    #[test]
    fn compact_result_accepts_top_level_decision_evidence() {
        let result = compact_result(&json!({
            "category": "pii",
            "decision_evidence": {"contributors": [{"chunk_id": 3}]}
        }));

        assert_eq!(
            result["decision_evidence"]["contributors"][0]["chunk_id"],
            3
        );
    }

    #[test]
    fn compact_result_preserves_dynamic_pii_evidence_spans() {
        let result = compact_result(&json!({
            "category": "dynamic-pii",
            "class_name": "entities",
            "confidence": 0.98,
            "evidence_spans": [{
                "label": "person",
                "text": "Thomas Müller",
                "score": 0.98,
                "start_byte": 0,
                "end_byte": 14,
                "start_char": 0,
                "end_char": 13
            }]
        }));

        assert_eq!(result["evidence_spans"][0]["label"], "person");
        assert_eq!(result["evidence_spans"][0]["text"], "Thomas Müller");
        assert_eq!(result["evidence_spans"][0]["start_byte"], 0);
        assert_eq!(result["evidence_spans"][0]["end_byte"], 14);
    }

    #[test]
    fn compact_result_exposes_l2_decision_candidate_chunk_evidence() {
        let result = compact_result(&json!({
            "category": "injection",
            "decision": {
                "decision_candidate": {
                    "chunk_evidence": {
                        "stage": "union",
                        "decisive_chunks": [{
                            "chunk_id": 3,
                            "span": {"start": 3870, "end": 4002}
                        }]
                    }
                }
            }
        }));

        assert_eq!(
            result["decision_evidence"]["decisive_chunks"][0]["chunk_id"],
            3
        );
    }

    #[test]
    fn compact_result_derives_evidence_from_raw_l2_chunk_outputs() {
        let result = compact_result(&json!({
            "category": "injection",
            "class_name": "attack",
            "layers": [{"details": {"l2_chunk_outputs": [
                {"class_name": "benign", "confidence": 0.99, "span": {"start": 0, "end": 100}},
                {"class_name": "attack", "confidence": 0.997, "span": {"start": 100, "end": 200}}
            ]}}]
        }));

        assert_eq!(result["decision_evidence"]["stage"], "l2");
        assert_eq!(
            result["decision_evidence"]["decisive_chunks"][0]["chunk_id"],
            1
        );
    }

    #[test]
    fn final_decision_is_allow_block_or_review() {
        let mut safe_categories = HashMap::new();
        safe_categories.insert(
            "injection".to_string(),
            json!({"class_name": "benign", "accepted": false}),
        );
        assert_eq!(final_decision(&completed_job(safe_categories)), "allow");

        let mut risky_categories = HashMap::new();
        risky_categories.insert(
            "threat".to_string(),
            json!({"class_name": "malicious", "accepted": true}),
        );
        assert_eq!(final_decision(&completed_job(risky_categories)), "block");

        let mut running = completed_job(HashMap::new());
        running.completion = None;
        assert_eq!(final_decision(&running), "review");
    }
}
