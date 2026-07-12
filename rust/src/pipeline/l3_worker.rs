use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::ml::ntdb_executor::ByteSpan;
use crate::ml::onnx::LazyOnnxTextClassifier;
use crate::{
    EvaluationResult, LayerResult, QueuedSecurityScanResult, RequestId, ScanExecution,
    SecurityScanResult,
};

use super::decision_cache::DecisionCache;
use super::long_text::{aggregate_chunk_outputs, chunk_text_bytes};
use super::{degraded_error_result, degraded_timeout_result, l3_metadata_layer, PipelineStrategy};

type L3ModelHandle = Arc<Mutex<LazyOnnxTextClassifier>>;

pub(crate) struct RequestRegistry {
    pub state: Mutex<RequestRegistryState>,
    pub available: Condvar,
}

pub(crate) struct RequestRegistryState {
    pub requests: HashMap<RequestId, RequestState>,
    pub ready: VecDeque<QueuedSecurityScanResult>,
}

impl Default for RequestRegistry {
    fn default() -> Self {
        Self {
            state: Mutex::new(RequestRegistryState {
                requests: HashMap::new(),
                ready: VecDeque::new(),
            }),
            available: Condvar::new(),
        }
    }
}

pub(crate) struct RequestState {
    pub expected_results: usize,
    pub consumed_results: usize,
    pub pending_l3_job_ids: HashSet<u64>,
    pub finished: bool,
}

#[derive(Clone)]
pub(crate) struct L3Worker {
    state: Arc<L3WorkerState>,
}

struct L3WorkerState {
    jobs: Mutex<Vec<L3WorkerJob>>,
    available: Condvar,
    models: Mutex<HashMap<String, L3ModelHandle>>,
    chunk_cache: Arc<DecisionCache>,
    requests: Arc<RequestRegistry>,
    next_sequence: Mutex<u64>,
}

#[derive(Clone)]
struct L3WorkerJob {
    job_id: u64,
    request_id: RequestId,
    category: String,
    model: String,
    text: String,
    fallback: SecurityScanResult,
    priority: usize,
    ttl_ms: u64,
    enqueued_at: Instant,
    execution: ScanExecution,
    degraded_factor: f64,
    l3_candidate_spans: Vec<ByteSpan>,
    sequence: u64,
    #[cfg(feature = "test-util")]
    test_delay_ms: Option<u64>,
}

pub(crate) struct L3JobSpec {
    pub job_id: u64,
    pub request_id: RequestId,
    pub category: String,
    pub model: String,
    pub text: String,
    pub fallback: SecurityScanResult,
    pub priority: usize,
    pub ttl_ms: u64,
    pub execution: ScanExecution,
    pub degraded_factor: f64,
    pub l3_candidate_spans: Vec<ByteSpan>,
}

impl L3Worker {
    pub(crate) fn start(requests: Arc<RequestRegistry>) -> Self {
        let state = Arc::new(L3WorkerState {
            jobs: Mutex::new(Vec::new()),
            available: Condvar::new(),
            models: Mutex::new(HashMap::new()),
            chunk_cache: Arc::new(DecisionCache::default()),
            requests,
            next_sequence: Mutex::new(0),
        });
        let worker_state = Arc::clone(&state);
        thread::spawn(move || worker_loop(worker_state));
        Self { state }
    }

    pub(crate) fn next_job_id(&self) -> u64 {
        let mut next = self
            .state
            .next_sequence
            .lock()
            .expect("l3 sequence mutex poisoned");
        let sequence = *next;
        *next += 1;
        sequence
    }

    pub(crate) fn register_model(
        &self,
        model: impl Into<String>,
        classifier: LazyOnnxTextClassifier,
    ) {
        self.state
            .models
            .lock()
            .expect("l3 model registry mutex poisoned")
            .insert(model.into(), Arc::new(Mutex::new(classifier)));
    }

    pub(crate) fn enqueue(&self, spec: L3JobSpec) {
        let job = L3WorkerJob {
            job_id: spec.job_id,
            request_id: spec.request_id,
            category: spec.category,
            model: spec.model,
            text: spec.text,
            fallback: spec.fallback,
            priority: spec.priority,
            ttl_ms: spec.ttl_ms,
            enqueued_at: Instant::now(),
            execution: spec.execution,
            degraded_factor: spec.degraded_factor,
            l3_candidate_spans: spec.l3_candidate_spans,
            sequence: spec.job_id,
            #[cfg(feature = "test-util")]
            test_delay_ms: None,
        };
        self.state
            .jobs
            .lock()
            .expect("l3 job queue mutex poisoned")
            .push(job);
        self.state.available.notify_one();
    }

    #[cfg(feature = "test-util")]
    pub(crate) fn enqueue_test_delay(&self, spec: L3JobSpec, delay_ms: u64) {
        self.enqueue_test_delays(vec![(spec, delay_ms)]);
    }

    #[cfg(feature = "test-util")]
    pub(crate) fn enqueue_test_delays(&self, specs: Vec<(L3JobSpec, u64)>) {
        let mut jobs = self.state.jobs.lock().expect("l3 job queue mutex poisoned");
        for (spec, delay_ms) in specs {
            jobs.push(L3WorkerJob {
                job_id: spec.job_id,
                request_id: spec.request_id,
                category: spec.category,
                model: spec.model,
                text: spec.text,
                fallback: spec.fallback,
                priority: spec.priority,
                ttl_ms: spec.ttl_ms,
                enqueued_at: Instant::now(),
                execution: spec.execution,
                degraded_factor: spec.degraded_factor,
                l3_candidate_spans: spec.l3_candidate_spans,
                sequence: spec.job_id,
                test_delay_ms: Some(delay_ms),
            });
        }
        drop(jobs);
        self.state.available.notify_one();
    }
}

fn worker_loop(state: Arc<L3WorkerState>) {
    loop {
        let job = next_job(&state);
        let (job_id, request_id, result) = execute_job(&state, job);
        finish_job(&state.requests, job_id, request_id, result);
    }
}

fn next_job(state: &L3WorkerState) -> L3WorkerJob {
    let mut jobs = state.jobs.lock().expect("l3 job queue mutex poisoned");
    loop {
        if !jobs.is_empty() {
            let selected = jobs
                .iter()
                .enumerate()
                .min_by(|(_, left), (_, right)| {
                    left.priority
                        .cmp(&right.priority)
                        .then_with(|| left.sequence.cmp(&right.sequence))
                })
                .map(|(index, _)| index)
                .unwrap();
            return jobs.swap_remove(selected);
        }
        jobs = state
            .available
            .wait(jobs)
            .expect("l3 job queue mutex poisoned");
    }
}

fn execute_job(state: &L3WorkerState, job: L3WorkerJob) -> (u64, RequestId, SecurityScanResult) {
    #[cfg(feature = "test-util")]
    if job.test_delay_ms.is_some() {
        return execute_with_deadline(job, |job| Ok(test_delay_result(job)));
    }

    let elapsed_before_start_ms = elapsed_ms(job.enqueued_at);
    if elapsed_before_start_ms >= job.ttl_ms as f64 {
        let result = degraded_timeout_result(
            job.fallback.clone(),
            elapsed_before_start_ms,
            job.ttl_ms,
            job.degraded_factor,
        );
        return (job.job_id, job.request_id, result);
    }

    let model = match state
        .models
        .lock()
        .expect("l3 model registry mutex poisoned")
        .get(&job.model)
        .cloned()
    {
        Some(model) => model,
        None => {
            let elapsed_ms = elapsed_ms(job.enqueued_at);
            let result = degraded_error_result(
                job.fallback.clone(),
                elapsed_ms,
                job.ttl_ms,
                job.degraded_factor,
                format!("L3 model '{}' is not registered", job.model),
            );
            return (job.job_id, job.request_id, result);
        }
    };
    let chunk_cache = Arc::clone(&state.chunk_cache);
    execute_with_deadline(job, move |job| run_model_job(job, model, chunk_cache))
}

fn execute_with_deadline<F>(job: L3WorkerJob, run: F) -> (u64, RequestId, SecurityScanResult)
where
    F: FnOnce(L3WorkerJob) -> Result<SecurityScanResult, String> + Send + 'static,
{
    let elapsed_before_start_ms = elapsed_ms(job.enqueued_at);
    if elapsed_before_start_ms >= job.ttl_ms as f64 {
        let result = degraded_timeout_result(
            job.fallback.clone(),
            elapsed_before_start_ms,
            job.ttl_ms,
            job.degraded_factor,
        );
        return (job.job_id, job.request_id, result);
    }

    let remaining = Duration::from_millis(job.ttl_ms).saturating_sub(job.enqueued_at.elapsed());
    let (tx, rx) = mpsc::channel();
    let thread_job = job.clone();
    thread::spawn(move || {
        let _ = tx.send(run(thread_job));
    });

    let result = match rx.recv_timeout(remaining) {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => degraded_error_result(
            job.fallback.clone(),
            elapsed_ms(job.enqueued_at),
            job.ttl_ms,
            job.degraded_factor,
            error,
        ),
        Err(mpsc::RecvTimeoutError::Timeout) => degraded_timeout_result(
            job.fallback.clone(),
            elapsed_ms(job.enqueued_at),
            job.ttl_ms,
            job.degraded_factor,
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => degraded_error_result(
            job.fallback.clone(),
            elapsed_ms(job.enqueued_at),
            job.ttl_ms,
            job.degraded_factor,
            "L3 worker inference thread terminated without a result".to_string(),
        ),
    };

    (job.job_id, job.request_id, result)
}

#[cfg(feature = "test-util")]
fn test_delay_result(job: L3WorkerJob) -> SecurityScanResult {
    if let Some(delay_ms) = job.test_delay_ms {
        thread::sleep(Duration::from_millis(delay_ms));
    }
    let mut result = job.fallback;
    for layer in &mut result.layers {
        layer.matched = false;
    }
    let mut layer = l3_metadata_layer("test_l3", &job.model, 1.0, elapsed_ms(job.enqueued_at));
    layer
        .details
        .insert("category".to_string(), serde_json::json!(job.category));
    layer
        .details
        .insert("l3_worker".to_string(), serde_json::json!("rust_l3_worker"));
    layer
        .details
        .insert("priority".to_string(), serde_json::json!(job.priority));
    layer
        .details
        .insert("job_id".to_string(), serde_json::json!(job.job_id));
    result.layers.push(layer);
    result.class_name = "test_l3".to_string();
    result.confidence = 1.0;
    result.level = "L3".to_string();
    result.duration_ms = result.layers.iter().map(|layer| layer.duration_ms).sum();
    result
}

fn run_model_job(
    job: L3WorkerJob,
    model: L3ModelHandle,
    chunk_cache: Arc<DecisionCache>,
) -> Result<SecurityScanResult, String> {
    let queue_wait_ms = elapsed_ms(job.enqueued_at);
    let strategy = l3_strategy(&job);
    let policy = strategy.long_text_policy(job.execution.long_text_policy());
    let chunking = policy
        .chunking()
        .map_err(|error| format!("invalid L3 chunking policy: {error}"))?;
    let chunks = selected_l3_chunks(&job.text, &job.l3_candidate_spans, chunking);
    let mut chunk_outputs = Vec::with_capacity(chunks.len());

    for chunk in &chunks {
        chunk_outputs.push(infer_l3_chunk(
            &job,
            &model,
            &chunk_cache,
            chunk,
            queue_wait_ms,
        )?);
    }

    let mut full_text_layers = job.fallback.layers.clone();
    for layer in &mut full_text_layers {
        layer.matched = false;
    }
    let aggregate = aggregate_chunk_outputs(
        full_text_layers,
        chunk_outputs,
        chunks.len(),
        l3_safe_class(&job),
        policy.verify_non_benign_l2,
        strategy.aggregation,
    )
    .ok_or_else(|| "L3 chunk aggregation produced no result".to_string())?;

    let mut result = job.fallback;
    result.class_name = aggregate.result.class_name;
    result.confidence = aggregate.result.confidence;
    result.level = "L3".to_string();
    result.layers = aggregate.layers;
    result.duration_ms = result.layers.iter().map(|layer| layer.duration_ms).sum();
    Ok(result)
}

fn selected_l3_chunks(
    text: &str,
    candidate_spans: &[ByteSpan],
    chunking: crate::TextChunking,
) -> Vec<String> {
    if candidate_spans.is_empty() {
        return chunk_text_bytes(text, chunking);
    }

    let mut spans = candidate_spans
        .iter()
        .filter_map(|span| expanded_span(text, *span, chunking.overlap_bytes))
        .collect::<Vec<_>>();
    spans.sort_by_key(|span| span.start);
    let mut merged: Vec<ByteSpan> = Vec::new();
    for span in spans {
        if let Some(previous) = merged.last_mut() {
            if span.start <= previous.end {
                previous.end = previous.end.max(span.end);
                continue;
            }
        }
        merged.push(span);
    }

    let selected = merged
        .into_iter()
        .flat_map(|span| chunk_text_bytes(&text[span.start..span.end], chunking))
        .collect::<Vec<_>>();
    if selected.is_empty() {
        chunk_text_bytes(text, chunking)
    } else {
        selected
    }
}

fn expanded_span(text: &str, span: ByteSpan, overlap: usize) -> Option<ByteSpan> {
    if span.start >= span.end || span.start >= text.len() {
        return None;
    }
    let mut start = span.start.saturating_sub(overlap).min(text.len());
    let mut end = span.end.saturating_add(overlap).min(text.len());
    while start > 0 && !text.is_char_boundary(start) {
        start -= 1;
    }
    while end < text.len() && !text.is_char_boundary(end) {
        end += 1;
    }
    (start < end).then_some(ByteSpan { start, end })
}

fn infer_l3_chunk(
    job: &L3WorkerJob,
    model: &L3ModelHandle,
    chunk_cache: &DecisionCache,
    chunk: &str,
    queue_wait_ms: f64,
) -> Result<(EvaluationResult, Vec<LayerResult>), String> {
    let namespace = {
        let mut model = model
            .lock()
            .map_err(|err| format!("L3 model mutex poisoned: {err}"))?;
        model
            .cache_namespace(job.execution.backend())
            .map_err(|err| err.to_string())?
    };

    if let Some((result, mut layers)) = chunk_cache.get(&namespace, chunk, &job.execution) {
        decorate_l3_layers(&mut layers, job, &namespace, chunk.len(), queue_wait_ms);
        return Ok((result, layers));
    }

    let started = Instant::now();
    let (result, mut layers) = {
        let mut model = model
            .lock()
            .map_err(|err| format!("L3 model mutex poisoned: {err}"))?;
        let result = model
            .infer(chunk, job.execution.backend())
            .map_err(|err| err.to_string())?;
        let mut layer = l3_metadata_layer(
            &result.class_name,
            &job.model,
            result.confidence,
            elapsed_ms(started),
        );
        layer.details.insert(
            "model_name".to_string(),
            serde_json::json!(model.model_name()),
        );
        if let Some(model_path) = model.model_path() {
            layer.details.insert(
                "model_path".to_string(),
                serde_json::json!(model_path.display().to_string()),
            );
        }
        if let Some(precision) = model.precision() {
            layer
                .details
                .insert("precision".to_string(), serde_json::json!(precision));
        }
        if let Some(provider) = model.execution_provider() {
            layer.details.insert(
                "execution_provider".to_string(),
                serde_json::json!(provider),
            );
        }
        (result, vec![layer])
    };

    chunk_cache.insert(&namespace, chunk, &job.execution, &result, &layers);
    decorate_l3_layers(&mut layers, job, &namespace, chunk.len(), queue_wait_ms);
    Ok((result, layers))
}

fn decorate_l3_layers(
    layers: &mut [LayerResult],
    job: &L3WorkerJob,
    cache_namespace: &str,
    chunk_len: usize,
    queue_wait_ms: f64,
) {
    let queued_ms = elapsed_ms(job.enqueued_at);
    for layer in layers
        .iter_mut()
        .filter(|layer| layer.level == "L3" && layer.layer_type == "onnx")
    {
        layer
            .details
            .entry("decision_cache_hit".to_string())
            .or_insert_with(|| serde_json::json!(false));
        layer
            .details
            .insert("l3_worker".to_string(), serde_json::json!("rust_l3_worker"));
        layer
            .details
            .insert("category".to_string(), serde_json::json!(job.category));
        layer
            .details
            .insert("queued_ms".to_string(), serde_json::json!(queued_ms));
        layer.details.insert(
            "l3_queue_wait_ms".to_string(),
            serde_json::json!(queue_wait_ms),
        );
        layer
            .details
            .insert("ttl_ms".to_string(), serde_json::json!(job.ttl_ms));
        layer
            .details
            .insert("priority".to_string(), serde_json::json!(job.priority));
        layer
            .details
            .insert("job_id".to_string(), serde_json::json!(job.job_id));
        layer.details.insert(
            "l3_chunk_cache_namespace".to_string(),
            serde_json::json!(cache_namespace),
        );
        layer
            .details
            .insert("l3_chunk_len".to_string(), serde_json::json!(chunk_len));
    }
}

fn l3_strategy(job: &L3WorkerJob) -> PipelineStrategy {
    PipelineStrategy::for_category_model(&job.category, &job.model)
}

fn l3_safe_class(job: &L3WorkerJob) -> &'static str {
    if job.category == "injection" || job.model == "wolf-defender-small" {
        "benign"
    } else {
        "safe"
    }
}

fn finish_job(
    requests: &Arc<RequestRegistry>,
    job_id: u64,
    request_id: RequestId,
    result: SecurityScanResult,
) {
    let mut registry = requests
        .state
        .lock()
        .expect("request registry mutex poisoned");
    if let Some(state) = registry.requests.get_mut(&request_id) {
        if !state.pending_l3_job_ids.remove(&job_id) {
            return;
        }
        if state.pending_l3_job_ids.is_empty() {
            state.finished = true;
        }
        registry
            .ready
            .push_back(QueuedSecurityScanResult { request_id, result });
    }
    requests.available.notify_all();
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_spans_reduce_l3_chunks() {
        let text = "x".repeat(1_000);
        let chunking = crate::TextChunking::new(256, 96).unwrap();

        let full = selected_l3_chunks(&text, &[], chunking);
        let selected = selected_l3_chunks(
            &text,
            &[ByteSpan {
                start: 400,
                end: 500,
            }],
            chunking,
        );

        assert!(selected.len() < full.len());
        assert_eq!(selected.len(), 2);
    }
}
