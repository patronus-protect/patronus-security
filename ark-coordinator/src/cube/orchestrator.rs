use crate::{
    config::Cube,
    cube::{
        batching::{batch, split_text},
        dispatcher::{CubeDispatchError, CubeTransport},
        ledger::TextLedger,
        slots::CubePool,
    },
    fair_queue::FairQueue,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinSet;

pub struct CubeScanOutcome {
    pub job: Value,
    pub metrics: Value,
}
pub struct CubeOrchestrator {
    pool: Arc<CubePool>,
    transport: CubeTransport,
    queue: Arc<FairQueue>,
    chunk_bytes: usize,
    chunks_per_batch: usize,
    deadline: Duration,
}
impl CubeOrchestrator {
    pub fn new(
        cubes: Vec<Cube>,
        cube_token: String,
        chunk_bytes: usize,
        chunks_per_batch: usize,
        parent_deadline: Duration,
    ) -> Result<Self, reqwest::Error> {
        let pool = CubePool::new(cubes);
        let transport = CubeTransport::new(cube_token)?;
        let health_pool = Arc::downgrade(&pool);
        let health_transport = transport.clone();
        tokio::spawn(async move {
            while let Some(pool) = health_pool.upgrade() {
                let names = pool.members();
                let checks = names.into_iter().map(|cube| {
                    let pool = pool.clone();
                    let transport = health_transport.clone();
                    async move {
                        pool.health(&cube.name, transport.healthy(&cube.url).await);
                    }
                });
                futures::future::join_all(checks).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
        Ok(Self {
            queue: Arc::new(FairQueue::new(pool.capacity())),
            pool,
            transport,
            chunk_bytes,
            chunks_per_batch,
            deadline: parent_deadline,
        })
    }
    pub async fn ready(&self) -> bool {
        let checks = self.pool.members().into_iter().map(|cube| async move {
            self.pool
                .health(&cube.name, self.transport.healthy(&cube.url).await);
        });
        futures::future::join_all(checks).await;
        self.pool.ready()
    }
    pub async fn scan(
        &self,
        request_id: &str,
        source: &str,
        text: Arc<str>,
        request_config: Option<Value>,
    ) -> CubeScanOutcome {
        let started = std::time::Instant::now();
        let deadline = tokio::time::Instant::now() + self.deadline;
        let requested_categories = request_config.as_ref().and_then(|config| {
            config
                .get("categories")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect::<BTreeSet<_>>()
                })
        });
        let request_config = Arc::new(request_config);
        let bytes = text.len();
        let chunks = split_text(request_id, text, self.chunk_bytes);
        let expected = chunks.len();
        let mut ledger = TextLedger::default();
        let mut errors = Vec::new();
        let Some(handle) = self.queue.register() else {
            return CubeScanOutcome {
                job: ledger.finish(
                    request_id,
                    source,
                    expected,
                    0.0,
                    vec!["coordinator_capacity".into()],
                    requested_categories.as_ref(),
                ),
                metrics: json!({"input_bytes":bytes}),
            };
        };
        let handle = Arc::new(handle);
        handle.prepare(bytes, 1);
        let mut pending = JoinSet::new();
        let mut offset = 0;
        let mut batches = 0;
        while offset < expected || !pending.is_empty() {
            // FairQueue bounds each request's pending tickets by global capacity.
            // Refill after completion also makes adaptive batching react to new parents.
            while offset < expected && pending.len() < self.pool.capacity() {
                let size = self.queue.batch_size(self.chunks_per_batch);
                let batch = batch(request_id, &chunks, offset, size.min(expected - offset));
                offset += batch.chunks.len();
                batches += 1;
                let pool = self.pool.clone();
                let transport = self.transport.clone();
                let handle = handle.clone();
                let config = request_config.clone();
                let batch_ready = std::time::Instant::now();
                pending.spawn(async move {
                    let work = batch.work_bytes() as f64;
                    let mut excluded = BTreeSet::new();
                    let mut busy_delay = Duration::from_millis(1);
                    loop {
                        let Ok(permit) =
                            tokio::time::timeout_at(deadline, handle.acquire(work)).await
                        else {
                            return (batch, Err("parent_deadline_before_dispatch".to_owned()));
                        };
                        if tokio::time::Instant::now() >= deadline {
                            return (batch, Err("parent_deadline_before_dispatch".to_owned()));
                        }
                        let Some(lease) = pool.try_acquire(work, &excluded) else {
                            // No attempt or Cube permit is held while all candidates
                            // are occupied. Re-enter the fair queue after each pause.
                            drop(permit);
                            excluded.clear();
                            if tokio::time::timeout_at(deadline, tokio::time::sleep(busy_delay))
                                .await
                                .is_err()
                            {
                                return (batch, Err("parent_deadline_before_dispatch".to_owned()));
                            }
                            busy_delay =
                                busy_delay.saturating_mul(2).min(Duration::from_millis(25));
                            continue;
                        };
                        let queue_wait_ms = batch_ready.elapsed().as_secs_f64() * 1000.0;
                        let result = transport
                            .execute(&lease.cube.url, &batch, config.as_ref().as_ref(), deadline)
                            .await;
                        if matches!(result, Err(CubeDispatchError::WorkerBusy)) {
                            excluded.insert(lease.cube.name.clone());
                            drop(lease);
                            drop(permit);
                            continue;
                        }
                        let result = result
                            .map(|mut response| {
                                lease.observe_completion();
                                // Apportion batch transport work once across its jobs.
                                let count = response.jobs.len() as f64;
                                for job in &mut response.jobs {
                                    job["timings"]["queue_wait_ms"] = json!(queue_wait_ms / count);
                                    job["timings"]["worker_submit_ms"] =
                                        json!(response.submit_ms / count);
                                }
                                response.jobs
                            })
                            .map_err(|error| match error {
                                CubeDispatchError::Failed(error) => error,
                                CubeDispatchError::WorkerBusy => {
                                    unreachable!("busy was handled before accepting work")
                                }
                            });
                        // All other errors are terminal: a POST may have been accepted.
                        handle.complete(work, 0, 1);
                        drop(lease);
                        drop(permit);
                        return (batch, result);
                    }
                });
            }
            match tokio::time::timeout_at(deadline, pending.join_next()).await {
                Ok(Some(Ok((batch, Ok(jobs))))) => {
                    for (chunk, job) in batch.chunks.into_iter().zip(jobs) {
                        if let Err(error) = ledger.insert(chunk, job) {
                            errors.push(error.into());
                        }
                    }
                }
                Ok(Some(Ok((_, Err(error))))) => errors.push(error),
                Ok(Some(Err(_))) => errors.push("batch_task_failed".into()),
                Ok(None) => break,
                Err(_) => {
                    errors.push("parent_deadline".into());
                    break;
                }
            }
        }
        // JoinSet owns all batch tasks. Abort and drain before returning a
        // terminal parent, so no local poll, slot lease or FairQueue permit can
        // outlive this scan. Dropping the final handle removes pending tickets.
        pending.abort_all();
        while pending.join_next().await.is_some() {}
        #[cfg(test)]
        assert_eq!(
            Arc::strong_count(&handle),
            1,
            "all local dispatch/retry task owners must be drained before scan returns"
        );
        drop(handle);
        let elapsed = started.elapsed().as_secs_f64() * 1000.0;
        CubeScanOutcome {
            job: ledger.finish(
                request_id,
                source,
                expected,
                elapsed,
                errors,
                requested_categories.as_ref(),
            ),
            metrics: json!({"input_bytes":bytes,"chunks":expected,"batches":batches,"total_ms":elapsed}),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{Body, Bytes},
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::{get, post},
        Json, Router,
    };
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Mutex,
    };
    struct Mock {
        posts: AtomicUsize,
        payloads: Mutex<Vec<String>>,
        polls: AtomicUsize,
        release: AtomicBool,
        reject: AtomicBool,
        busy: AtomicBool,
        disconnect: AtomicBool,
        submit_gate: Mutex<Option<Arc<SubmitGate>>>,
        submit_reply: Mutex<Option<(StatusCode, &'static str)>>,
        poll_status: AtomicUsize,
        invalid_poll_json: AtomicBool,
    }
    struct SubmitGate {
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
        processed: tokio::sync::Semaphore,
    }
    async fn submit(State(state): State<Arc<Mock>>, headers: HeaderMap, body: Bytes) -> Response {
        assert_eq!(headers.get("x-ark-dispatch-mode").unwrap(), "no-queue");
        let gate = state.submit_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            // A remote service may keep processing received bytes even if the
            // HTTP client disconnects. Keep this gated mock work independent.
            return tokio::spawn(async move {
                gate.entered.add_permits(1);
                gate.release.acquire().await.unwrap().forget();
                let response = submit_response(&state, body);
                gate.processed.add_permits(1);
                response
            })
            .await
            .unwrap();
        }
        submit_response(&state, body)
    }
    fn submit_response(state: &Mock, body: Bytes) -> Response {
        let count = state.posts.fetch_add(1, Ordering::SeqCst);
        let text = String::from_utf8(body.to_vec()).unwrap();
        let boundary = text.lines().next().unwrap();
        state
            .payloads
            .lock()
            .unwrap()
            .push(text.replace(boundary, "--BOUNDARY"));
        if state.disconnect.load(Ordering::SeqCst) {
            return Response::builder()
                .status(StatusCode::ACCEPTED)
                .header("content-type", "application/json")
                .body(Body::from_stream(futures::stream::once(async {
                    Err::<Bytes, _>(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "ambiguous POST response",
                    ))
                })))
                .unwrap();
        }
        if state.busy.load(Ordering::SeqCst) {
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(json!({"error":"worker_busy"})),
            )
                .into_response();
        }
        if let Some((status, body)) = *state.submit_reply.lock().unwrap() {
            return (status, [("content-type", "application/json")], body).into_response();
        }
        if state.reject.load(Ordering::SeqCst) {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({"error":"busy"})),
            )
                .into_response();
        }
        let jobs:Vec<Value>=(0..text.matches("filename=").count()).map(|n|json!({"job_id":format!("job_{count}_{n}"),"source":format!("chunk-{n}.txt"),"status_url":format!("/v1/scan/job_{count}_{n}")})).collect();
        (StatusCode::ACCEPTED, Json(json!({"jobs":jobs}))).into_response()
    }
    async fn poll(State(state): State<Arc<Mock>>, Path(id): Path<String>) -> Response {
        state.polls.fetch_add(1, Ordering::SeqCst);
        let status = state.poll_status.load(Ordering::SeqCst);
        if status != 0 {
            return (
                StatusCode::from_u16(status as u16).unwrap(),
                Json(json!({"error":"poll failure"})),
            )
                .into_response();
        }
        if state.invalid_poll_json.load(Ordering::SeqCst) {
            return (StatusCode::OK, "not-json").into_response();
        }
        if !state.release.load(Ordering::SeqCst) {
            return Json(json!({"job_id":id,"status":"running"})).into_response();
        }
        Json(
            json!({"job_id":id,"source":"file","status":"completed","worker":"local-worker","worker_request_id":"req","progress":{},"categories":{"threat":{"accepted":false,"class_name":"safe","confidence":0.99}},"completion":{"state":"complete"},"decision":"allow","timings":{"total_ms":1.0,"worker_ms":1.0,"l2_ms":1.0}}),
        )
        .into_response()
    }
    async fn mock(name: String) -> (Cube, Arc<Mock>, tokio::task::JoinHandle<()>) {
        let state = Arc::new(Mock {
            posts: AtomicUsize::new(0),
            payloads: Mutex::new(Vec::new()),
            polls: AtomicUsize::new(0),
            release: AtomicBool::new(false),
            reject: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            disconnect: AtomicBool::new(false),
            submit_gate: Mutex::new(None),
            submit_reply: Mutex::new(None),
            poll_status: AtomicUsize::new(0),
            invalid_poll_json: AtomicBool::new(false),
        });
        let router = Router::new()
            .route("/readyz", get(|| async { StatusCode::OK }))
            .route("/v1/scan", post(submit))
            .route("/v1/scan/:id", get(poll))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        (
            Cube {
                name,
                url: format!("http://{addr}"),
                max_in_flight: 3,
            },
            state,
            server,
        )
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn twelve_cubes_have_three_slots_and_free_cube_gets_next_batch() {
        let mut cubes = vec![];
        let mut mocks = vec![];
        let mut servers = vec![];
        for i in 0..12 {
            let (cube, state, server) = mock(format!("cube-{i}")).await;
            cubes.push(cube);
            mocks.push(state);
            servers.push(server);
        }
        let engine = Arc::new(
            CubeOrchestrator::new(cubes, "mock-key".into(), 4, 4, Duration::from_secs(15)).unwrap(),
        );
        assert!(engine.ready().await);
        let scan = engine.clone();
        let task = tokio::spawn(async move {
            scan.scan("parent", "text", Arc::from("abcdefgh".repeat(200)), None)
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if mocks
                    .iter()
                    .map(|s| s.posts.load(Ordering::SeqCst))
                    .sum::<usize>()
                    == 36
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(mocks.iter().all(|s| s.posts.load(Ordering::SeqCst) == 3));
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            mocks
                .iter()
                .map(|s| s.posts.load(Ordering::SeqCst))
                .sum::<usize>(),
            36
        );
        mocks[7].release.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(5), async {
            while mocks[7].posts.load(Ordering::SeqCst) == 3 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        assert!(mocks
            .iter()
            .enumerate()
            .all(|(i, s)| i == 7 || s.posts.load(Ordering::SeqCst) == 3));
        for state in &mocks {
            state.release.store(true, Ordering::SeqCst);
        }
        let result = task.await.unwrap();
        assert_eq!(result.job["status"], "completed");
        assert_eq!(result.job["decision"], "allow");
        assert_eq!(result.metrics["chunks"], 400);
        assert!(result.job["timings"]["queue_wait_ms"].as_f64().unwrap() > 0.0);
        assert!(result.job["timings"]["worker_submit_ms"].as_f64().unwrap() > 0.0);
        assert_eq!(
            mocks
                .iter()
                .map(|s| s.posts.load(Ordering::SeqCst))
                .sum::<usize>(),
            result.metrics["batches"].as_u64().unwrap() as usize
        );
        for server in servers {
            server.abort();
        }
    }
    #[tokio::test]
    async fn rejected_post_is_never_retried_and_single_chunk_is_parent_normalized() {
        let (cube, state, server) = mock("cube".into()).await;
        state.reject.store(true, Ordering::SeqCst);
        let engine = CubeOrchestrator::new(
            vec![cube],
            "mock-key".into(),
            4096,
            4,
            Duration::from_secs(3),
        )
        .unwrap();
        assert!(engine.ready().await);
        let failed = engine
            .scan("parent", "text", Arc::from("hello"), None)
            .await;
        assert_eq!(state.posts.load(Ordering::SeqCst), 1);
        assert_eq!(failed.job["decision"], "review");
        state.reject.store(false, Ordering::SeqCst);
        state.release.store(true, Ordering::SeqCst);
        let result = engine
            .scan(
                "parent-2",
                "text",
                Arc::from("hello"),
                Some(json!({"custom":"unchanged"})),
            )
            .await;
        assert_eq!(result.job["job_id"], "parent-2");
        assert_eq!(result.job["source"], "text");
        assert_eq!(result.job["worker"], "coordinator");
        assert_eq!(result.job["worker_request_id"], "parent-2");
        assert_eq!(result.job["decision"], "allow");
        assert_eq!(result.job["completion"]["state"], "complete");
        let missing_category = engine
            .scan(
                "parent-3",
                "text",
                Arc::from("hello"),
                Some(json!({"categories":["injection"]})),
            )
            .await;
        assert_eq!(missing_category.job["decision"], "review");
        assert_eq!(missing_category.job["completion"]["state"], "degraded");
        assert_eq!(state.posts.load(Ordering::SeqCst), 3);
        server.abort();
    }
    #[tokio::test]
    async fn permanent_poll_failures_release_the_cube_slot_without_waiting_for_deadline() {
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::NOT_FOUND,
        ] {
            let (cube, state, server) = mock(format!("cube-{}", status.as_u16())).await;
            state
                .poll_status
                .store(status.as_u16() as usize, Ordering::SeqCst);
            let engine = CubeOrchestrator::new(
                vec![cube],
                "mock-key".into(),
                4096,
                4,
                Duration::from_secs(3),
            )
            .unwrap();
            assert!(engine.ready().await);
            let started = std::time::Instant::now();
            let result = engine
                .scan("parent", "text", Arc::from("hello"), None)
                .await;
            assert!(started.elapsed() < Duration::from_millis(500));
            assert_eq!(result.job["decision"], "review");
            assert_eq!(state.polls.load(Ordering::SeqCst), 1);
            assert!(engine
                .pool
                .snapshot()
                .iter()
                .all(|(_, active)| *active == 0));
            server.abort();
        }

        let (cube, state, server) = mock("cube-invalid-json".into()).await;
        state.invalid_poll_json.store(true, Ordering::SeqCst);
        let engine = CubeOrchestrator::new(
            vec![cube],
            "mock-key".into(),
            4096,
            4,
            Duration::from_secs(3),
        )
        .unwrap();
        assert!(engine.ready().await);
        let result = engine
            .scan("parent", "text", Arc::from("hello"), None)
            .await;
        assert_eq!(result.job["decision"], "review");
        assert_eq!(state.polls.load(Ordering::SeqCst), 1);
        assert!(engine
            .pool
            .snapshot()
            .iter()
            .all(|(_, active)| *active == 0));
        server.abort();
    }

    #[tokio::test]
    async fn server_poll_failures_are_retried_and_can_recover() {
        let (cube, state, server) = mock("cube".into()).await;
        state.poll_status.store(
            StatusCode::SERVICE_UNAVAILABLE.as_u16() as usize,
            Ordering::SeqCst,
        );
        let engine = Arc::new(
            CubeOrchestrator::new(
                vec![cube],
                "mock-key".into(),
                4096,
                4,
                Duration::from_secs(3),
            )
            .unwrap(),
        );
        assert!(engine.ready().await);
        let scan = engine.clone();
        let task =
            tokio::spawn(
                async move { scan.scan("parent", "text", Arc::from("hello"), None).await },
            );
        tokio::time::timeout(Duration::from_secs(1), async {
            while state.polls.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        state.poll_status.store(0, Ordering::SeqCst);
        state.release.store(true, Ordering::SeqCst);
        let result = task.await.unwrap();
        assert_eq!(result.job["decision"], "allow");
        assert!(state.polls.load(Ordering::SeqCst) >= 3);
        assert!(engine
            .pool
            .snapshot()
            .iter()
            .all(|(_, active)| *active == 0));
        server.abort();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn parent_deadline_stops_all_polls_and_releases_slots_and_queue() {
        let (cube, state, server) = mock("cube".into()).await;
        let mut engine = CubeOrchestrator::new(
            vec![cube],
            "mock-key".into(),
            4,
            4,
            Duration::from_millis(150),
        )
        .unwrap();
        assert!(engine.ready().await);
        let started = std::time::Instant::now();
        let result = engine
            .scan(
                "timeout-parent",
                "text",
                Arc::from("abcdefgh".repeat(100)),
                None,
            )
            .await;
        assert!(started.elapsed() < Duration::from_millis(500));
        assert_eq!(result.job["decision"], "review");
        assert_eq!(result.job["completion"]["state"], "degraded");
        assert_eq!(state.posts.load(Ordering::SeqCst), 3);
        assert!(engine
            .pool
            .snapshot()
            .iter()
            .all(|(_, active)| *active == 0));
        assert!(state.polls.load(Ordering::SeqCst) > 0);
        // A second parent needs all three permits: leftover queue tickets or
        // leases from the timed-out request would prevent full completion.
        state.release.store(true, Ordering::SeqCst);
        engine.deadline = Duration::from_secs(2);
        let recovered = engine
            .scan("next-parent", "text", Arc::from("abcdefgh".repeat(6)), None)
            .await;
        assert_eq!(recovered.job["decision"], "allow");
        assert_eq!(recovered.job["completion"]["state"], "complete");
        assert!(engine
            .pool
            .snapshot()
            .iter()
            .all(|(_, active)| *active == 0));
        server.abort();
    }
    #[tokio::test]
    async fn busy_cube_reroutes_unaccepted_batch_to_another_cube() {
        let (busy_cube, busy, first_server) = mock("busy".into()).await;
        let (free_cube, free, second_server) = mock("free".into()).await;
        busy.busy.store(true, Ordering::SeqCst);
        free.release.store(true, Ordering::SeqCst);
        let engine = CubeOrchestrator::new(
            vec![busy_cube, free_cube],
            "mock-key".into(),
            4096,
            4,
            Duration::from_secs(2),
        )
        .unwrap();
        assert!(engine.ready().await);
        let result = engine
            .scan(
                "reroute",
                "text",
                Arc::from("hello"),
                Some(json!({"categories":["threat"]})),
            )
            .await;
        assert_eq!(result.job["completion"]["state"], "complete");
        assert_eq!(result.job["decision"], "allow");
        assert_eq!(busy.posts.load(Ordering::SeqCst), 1);
        assert_eq!(busy.polls.load(Ordering::SeqCst), 0);
        assert_eq!(free.posts.load(Ordering::SeqCst), 1);
        assert_eq!(
            *busy.payloads.lock().unwrap(),
            *free.payloads.lock().unwrap()
        );
        assert!(engine
            .pool
            .snapshot()
            .iter()
            .all(|(_, active)| *active == 0));
        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn only_exact_pre_admission_busy_response_can_retry() {
        for (status, body) in [
            (
                StatusCode::TOO_MANY_REQUESTS,
                r#"{"error":"worker queue full"}"#,
            ),
            (
                StatusCode::TOO_MANY_REQUESTS,
                r#"{"error":"worker_busy","jobs":[]}"#,
            ),
            (StatusCode::TOO_MANY_REQUESTS, r#"{"error":"worker_busy""#),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"worker_busy"}"#,
            ),
            (StatusCode::ACCEPTED, "not-json"),
            (
                StatusCode::TOO_MANY_REQUESTS,
                r#"{"error":"other","error":"worker_busy"}"#,
            ),
        ] {
            let (cube, state, server) = mock("cube".into()).await;
            *state.submit_reply.lock().unwrap() = Some((status, body));
            let engine = CubeOrchestrator::new(
                vec![cube],
                "mock-key".into(),
                4096,
                4,
                Duration::from_secs(1),
            )
            .unwrap();
            assert!(engine.ready().await);
            let result = engine
                .scan("ambiguous", "text", Arc::from("hello"), None)
                .await;
            assert_eq!(result.job["decision"], "review");
            assert_eq!(state.posts.load(Ordering::SeqCst), 1, "{status}: {body}");
            assert_eq!(state.polls.load(Ordering::SeqCst), 0);
            assert!(engine
                .pool
                .snapshot()
                .iter()
                .all(|(_, active)| *active == 0));
            server.abort();
        }
    }

    #[tokio::test]
    async fn disconnected_post_is_never_sent_to_another_cube() {
        let (first, state, first_server) = mock("ambiguous".into()).await;
        let (second, unused, second_server) = mock("free".into()).await;
        state.disconnect.store(true, Ordering::SeqCst);
        unused.release.store(true, Ordering::SeqCst);
        let engine = CubeOrchestrator::new(
            vec![first, second],
            "mock-key".into(),
            4096,
            4,
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(engine.ready().await);
        let result = engine
            .scan("disconnect", "text", Arc::from("hello"), None)
            .await;
        assert_eq!(result.job["decision"], "review");
        assert_eq!(state.posts.load(Ordering::SeqCst), 1);
        assert_eq!(unused.posts.load(Ordering::SeqCst), 0);
        assert!(engine
            .pool
            .snapshot()
            .iter()
            .all(|(_, active)| *active == 0));
        first_server.abort();
        second_server.abort();
    }

    #[tokio::test]
    async fn all_busy_releases_attempt_and_cube_permits_then_recovers() {
        let (cube, state, server) = mock("cube".into()).await;
        state.busy.store(true, Ordering::SeqCst);
        let engine = Arc::new(
            CubeOrchestrator::new(vec![cube], "mock-key".into(), 4, 4, Duration::from_secs(3))
                .unwrap(),
        );
        assert!(engine.ready().await);
        let scan = engine.clone();
        let task = tokio::spawn(async move {
            scan.scan(
                "busy-parent",
                "text",
                Arc::from("abcdefgh".repeat(12)),
                None,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while state.posts.load(Ordering::SeqCst) < 3 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        // Even while this parent retries, another request can reserve every
        // attempt and Cube slot. Busy responses do not keep either resource.
        let outsider = engine.queue.register().unwrap();
        let (permits, leases) = tokio::time::timeout(Duration::from_secs(1), async {
            let mut permits = Vec::new();
            let mut leases = Vec::new();
            for _ in 0..3 {
                permits.push(outsider.acquire(1.0).await);
                leases.push(engine.pool.acquire(1.0).await);
            }
            (permits, leases)
        })
        .await
        .unwrap();
        assert_eq!(state.polls.load(Ordering::SeqCst), 0);
        state.busy.store(false, Ordering::SeqCst);
        state.release.store(true, Ordering::SeqCst);
        drop(leases);
        drop(permits);
        drop(outsider);
        let result = task.await.unwrap();
        assert_eq!(result.job["decision"], "allow");
        assert_eq!(result.job["completion"]["state"], "complete");
        assert!(engine
            .pool
            .snapshot()
            .iter()
            .all(|(_, active)| *active == 0));
        server.abort();
    }

    #[tokio::test]
    async fn all_busy_deadline_stops_retries_without_leaking_permits() {
        let (cube, state, server) = mock("cube".into()).await;
        state.busy.store(true, Ordering::SeqCst);
        let mut engine = CubeOrchestrator::new(
            vec![cube],
            "mock-key".into(),
            4,
            4,
            Duration::from_millis(100),
        )
        .unwrap();
        assert!(engine.ready().await);
        let result = engine
            .scan(
                "busy-timeout",
                "text",
                Arc::from("abcdefgh".repeat(12)),
                None,
            )
            .await;
        assert_eq!(result.job["decision"], "review");
        assert_eq!(state.polls.load(Ordering::SeqCst), 0);
        assert!(engine
            .pool
            .snapshot()
            .iter()
            .all(|(_, active)| *active == 0));
        let posts = state.posts.load(Ordering::SeqCst);
        assert!(posts > 0 && posts < 100, "unbounded retry count: {posts}");
        state.busy.store(false, Ordering::SeqCst);
        state.release.store(true, Ordering::SeqCst);
        engine.deadline = Duration::from_secs(2);
        let recovered = engine
            .scan("recovered", "text", Arc::from("abcdefgh".repeat(6)), None)
            .await;
        assert_eq!(recovered.job["completion"]["state"], "complete");
        server.abort();
    }

    #[tokio::test]
    async fn deadline_drains_local_tasks_before_delayed_remote_posts_are_processed() {
        let (cube, state, server) = mock("cube".into()).await;
        state.busy.store(true, Ordering::SeqCst);
        let gate = Arc::new(SubmitGate {
            entered: tokio::sync::Semaphore::new(0),
            release: tokio::sync::Semaphore::new(0),
            processed: tokio::sync::Semaphore::new(0),
        });
        *state.submit_gate.lock().unwrap() = Some(gate.clone());
        let engine = Arc::new(
            CubeOrchestrator::new(vec![cube], "mock-key".into(), 4, 4, Duration::from_secs(2))
                .unwrap(),
        );
        assert!(engine.ready().await);
        let scan = engine.clone();
        let task = tokio::spawn(async move {
            scan.scan(
                "delayed-busy-parent",
                "text",
                Arc::from("abcdefgh".repeat(12)),
                None,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), gate.entered.acquire_many(3))
            .await
            .unwrap()
            .unwrap()
            .forget();
        let result = task.await.unwrap();
        assert_eq!(result.job["decision"], "review");
        assert_eq!(state.posts.load(Ordering::SeqCst), 0);
        assert!(engine
            .pool
            .snapshot()
            .iter()
            .all(|(_, active)| *active == 0));

        // scan() also asserts its last RequestHandle has no task owners left.
        // Every attempt permit must be reusable before the remote handlers run.
        let outsider = engine.queue.register().unwrap();
        let permits = tokio::time::timeout(Duration::from_secs(1), async {
            let mut permits = Vec::new();
            for _ in 0..3 {
                permits.push(outsider.acquire(1.0).await);
            }
            permits
        })
        .await
        .unwrap();
        // Bytes already sent cannot be recalled by canceling a local future.
        // The server can count these POSTs after scan() without any task leak.
        gate.release.add_permits(3);
        tokio::time::timeout(Duration::from_secs(1), gate.processed.acquire_many(3))
            .await
            .unwrap()
            .unwrap()
            .forget();
        assert_eq!(state.posts.load(Ordering::SeqCst), 3);
        assert_eq!(state.polls.load(Ordering::SeqCst), 0);
        drop(permits);
        drop(outsider);
        server.abort();
    }
}
