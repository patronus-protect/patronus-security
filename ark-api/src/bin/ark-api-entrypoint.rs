use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Parser;
use futures::StreamExt;
use redis::AsyncCommands;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;

const ACTIVE_TTL_SECS: u64 = 10 * 60;

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
    workers: Vec<WorkerConfig>,
    worker_cursor: Arc<AtomicUsize>,
    key_hashes: Vec<String>,
    retention_secs: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Job {
    job_id: String,
    source: String,
    status: String,
    worker: String,
    worker_request_id: String,
    #[serde(default)]
    progress: HashMap<String, Value>,
    #[serde(default)]
    categories: HashMap<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    completion: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision: Option<String>,
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

fn authenticated(state: &AppState, headers: &HeaderMap) -> bool {
    let Some(token) = bearer(headers) else {
        return false;
    };
    let digest = format!("{:x}", Sha256::digest(token.as_bytes()));
    state
        .key_hashes
        .iter()
        .any(|hash| hash.as_bytes().ct_eq(digest.as_bytes()).into())
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
    connection.set_ex(job_key(&job.job_id), payload, ttl).await
}

async fn load_job(state: &AppState, job_id: &str) -> Result<Option<Job>, redis::RedisError> {
    let mut connection = state.redis.clone();
    let payload: Option<String> = connection.get(job_key(job_id)).await?;
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

async fn collect_events(state: AppState, job_id: String, worker: WorkerConfig, request_id: String) {
    let started = Instant::now();
    let url = format!(
        "{}/v1/scan/{request_id}/events",
        worker.url.trim_end_matches('/')
    );
    let response = match state
        .client
        .get(url)
        .bearer_auth(&state.worker_token)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => response,
        Ok(response) => {
            tracing::warn!(job_id, status = %response.status(), "worker event stream rejected");
            return;
        }
        Err(error) => {
            tracing::warn!(job_id, %error, "worker event stream failed");
            return;
        }
    };

    tracing::info!(job_id, worker = %worker.name, worker_events_connected_ms = started.elapsed().as_secs_f64() * 1_000.0, "worker event stream connected");

    let mut pending = String::new();
    let mut stream = response.bytes_stream();
    let mut event_count = 0usize;
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else { break };
        pending.push_str(&String::from_utf8_lossy(&chunk));
        while let Some(index) = pending.find("\n\n") {
            let frame = pending[..index].to_string();
            pending.drain(..index + 2);
            let event = frame.lines().find_map(|line| line.strip_prefix("event: "));
            let data = frame
                .lines()
                .find_map(|line| line.strip_prefix("data: "))
                .and_then(|data| serde_json::from_str::<Value>(data).ok());
            let (Some(event), Some(data)) = (event, data) else {
                continue;
            };
            event_count += 1;
            let Ok(Some(mut job)) = load_job(&state, &job_id).await else {
                return;
            };
            match event {
                "progress" => {
                    if let Some(category) = data.get("category").and_then(Value::as_str) {
                        job.progress.insert(category.to_string(), data);
                    }
                }
                "result" => {
                    if let Some(category) = data.get("category").and_then(Value::as_str) {
                        tracing::info!(
                            job_id,
                            worker = %worker.name,
                            category,
                            level = data.get("level").and_then(|value| value.as_str()).unwrap_or("unknown"),
                            model = data.get("model").and_then(|value| value.as_str()).unwrap_or("unknown"),
                            reported_duration_ms = data.get("duration_ms").and_then(|value| value.as_f64()).unwrap_or_default(),
                            event_elapsed_ms = started.elapsed().as_secs_f64() * 1_000.0,
                            "worker result received"
                        );
                        let replace = job
                            .categories
                            .get(category)
                            .is_none_or(|previous| level_rank(&data) >= level_rank(previous));
                        if replace {
                            job.categories
                                .insert(category.to_string(), compact_result(&data));
                        }
                    }
                }
                "finished" => {
                    job.completion = data.get("completion").cloned();
                    job.status = if data.pointer("/completion/state").and_then(Value::as_str)
                        == Some("failed")
                    {
                        "failed".to_string()
                    } else {
                        "completed".to_string()
                    };
                    job.decision = Some(final_decision(&job));
                }
                _ => {}
            }
            if save_job(&state, &job).await.is_err() {
                return;
            }
            if event == "finished" {
                tracing::info!(job_id, worker = %worker.name, worker_events_finished_ms = started.elapsed().as_secs_f64() * 1_000.0, event_count, "worker event stream finished");
                return;
            }
        }
    }
}

fn level_rank(result: &Value) -> u8 {
    match result.get("level").and_then(Value::as_str) {
        Some("L3") => 3,
        Some("L2") => 2,
        _ => 1,
    }
}

fn compact_result(result: &Value) -> Value {
    let decision_evidence = result
        .get("decision_evidence")
        .filter(|evidence| !evidence.is_null())
        .cloned()
        .or_else(|| {
            result
                .pointer("/decision/decision_evidence")
                .filter(|evidence| !evidence.is_null())
                .cloned()
        })
        .or_else(|| {
            result
                .pointer("/decision/decision_candidate/chunk_evidence")
                .filter(|evidence| !evidence.is_null())
                .cloned()
        })
        .or_else(|| {
            result
                .get("layers")
                .and_then(Value::as_array)
                .and_then(|layers| {
                    layers.iter().rev().find_map(|layer| {
                        layer
                            .pointer("/details/decision_evidence")
                            .filter(|evidence| !evidence.is_null())
                            .cloned()
                    })
                })
        })
        .or_else(|| l2_chunk_evidence(result));
    json!({
        "category": result.get("category"),
        "class_name": result.get("class_name"),
        "confidence": result.get("confidence"),
        "level": result.get("level"),
        "model": result.get("model"),
        "accepted": result.pointer("/decision/recommendation/accepted").and_then(Value::as_bool).unwrap_or(false),
        "final_result": result.pointer("/decision/final_result"),
        "decision_evidence": decision_evidence,
        "evidence_spans": result.get("evidence_spans").cloned().unwrap_or_else(|| json!([])),
    })
}

fn l2_chunk_evidence(result: &Value) -> Option<Value> {
    let class_name = result.get("class_name")?.as_str()?;
    if matches!(class_name, "benign" | "safe") {
        return None;
    }
    let chunks = result
        .get("layers")?
        .as_array()?
        .iter()
        .rev()
        .find_map(|layer| layer.pointer("/details/l2_chunk_outputs")?.as_array())?;
    let contributors = chunks
        .iter()
        .enumerate()
        .filter(|(_, chunk)| chunk.get("class_name").and_then(Value::as_str) == Some(class_name))
        .map(|(chunk_id, chunk)| {
            json!({
                "chunk_id": chunk_id,
                "span": chunk.get("span"),
                "source": "l2",
                "class_name": class_name,
                "confidence": chunk.get("confidence"),
            })
        })
        .collect::<Vec<_>>();
    let decisive_chunk = contributors.iter().max_by(|left, right| {
        left.get("confidence")
            .and_then(Value::as_f64)
            .partial_cmp(&right.get("confidence").and_then(Value::as_f64))
            .unwrap_or(std::cmp::Ordering::Equal)
    })?;
    Some(json!({
        "stage": "l2",
        "contributors": contributors,
        "decisive_chunks": [decisive_chunk],
    }))
}

async fn submit_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if !authenticated(&state, &headers) {
        return unauthorized();
    }
    let worker = state.workers
        [state.worker_cursor.fetch_add(1, Ordering::Relaxed) % state.workers.len()]
    .clone();
    let upstream_started = Instant::now();
    let mut request = state
        .client
        .post(format!("{}/v1/scan", worker.url.trim_end_matches('/')))
        .bearer_auth(&state.worker_token)
        .body(body);
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        request = request.header(header::CONTENT_TYPE, content_type);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":"worker unavailable"})),
            )
                .into_response()
        }
    };
    let status = response.status();
    let payload: Value = match response.json().await {
        Ok(payload) => payload,
        Err(_) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(json!({"error":"invalid worker response"})),
            )
                .into_response()
        }
    };
    if !status.is_success() {
        return (status, Json(payload)).into_response();
    }
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
        tracing::info!(job_id, worker = %worker.name, worker_submit_ms = upstream_started.elapsed().as_secs_f64() * 1_000.0, "worker accepted scan");
        let job = Job {
            job_id: job_id.clone(),
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
            completion: None,
            decision: None,
        };
        if save_job(&state, &job).await.is_err() {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"job store unavailable"})),
            )
                .into_response();
        }
        tokio::spawn(collect_events(
            (*state).clone(),
            job_id.clone(),
            worker.clone(),
            worker_request_id.to_string(),
        ));
        jobs.push(json!({
            "job_id": job_id,
            "source": job.source,
            "status_url": format!("/v1/scan/{job_id}"),
        }));
    }
    (StatusCode::ACCEPTED, Json(json!({"jobs": jobs}))).into_response()
}

async fn get_scan(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(job_id): Path<String>,
) -> Response {
    if !authenticated(&state, &headers) {
        return unauthorized();
    }
    match load_job(&state, &job_id).await {
        Ok(Some(job)) => Json(job).into_response(),
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
        Ok(Ok(pong)) if pong == "PONG" => StatusCode::OK,
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
    let bind: SocketAddr = config.server.bind.parse()?;
    let redis = redis::Client::open(config.gateway.redis_url.as_str())?
        .get_connection_manager()
        .await?;
    let state = Arc::new(AppState {
        client: reqwest::Client::new(),
        redis,
        worker_token: config.gateway.worker_token,
        workers: config.gateway.workers,
        worker_cursor: Arc::new(AtomicUsize::new(0)),
        key_hashes: config
            .auth
            .keys
            .into_iter()
            .map(|key| key.key_hash)
            .collect(),
        retention_secs: config.gateway.retention_secs,
    });
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/scan", post(submit_scan))
        .route("/v1/scan/:job_id", get(get_scan))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            workers: Vec::new(),
            worker_cursor: Arc::new(AtomicUsize::new(0)),
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

    fn completed_job(categories: HashMap<String, Value>) -> Job {
        Job {
            job_id: "job_test".to_string(),
            source: "text".to_string(),
            status: "completed".to_string(),
            worker: "ark-api-1".to_string(),
            worker_request_id: "rq-test".to_string(),
            progress: HashMap::new(),
            categories,
            completion: Some(json!({"state": "complete"})),
            decision: None,
        }
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
