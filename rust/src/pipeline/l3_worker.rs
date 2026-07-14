// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::ml::dynamic_pii::DynamicPiiRuntime;
use crate::ml::ntdb_executor::ByteSpan;
use crate::ml::onnx::{LazyOnnxTextClassifier, TokenTextChunk};
use crate::{
    DynamicPiiConfig, EvaluationResult, LayerResult, QueuedSecurityEvent, QueuedSecurityScanResult,
    RequestId, ScanExecution, SecurityFailure, SecurityFailureKind, SecurityFailureStage,
    SecurityLevel, SecurityRequestCompletion, SecurityScanResult,
};

use super::decision_cache::DecisionCache;
use super::l3_routing::estimated_cost_ms;
use super::long_text::aggregate_chunk_outputs;
use super::{degraded_error_result, degraded_timeout_result, l3_metadata_layer, PipelineStrategy};

type L3ModelHandle = Arc<Mutex<LazyOnnxTextClassifier>>;
type DynamicPiiHandle = Arc<Mutex<DynamicPiiRuntime>>;
const L3_OVERLAP_TOKENS: usize = 32;
const L3_IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

pub(crate) struct RequestRegistry {
    pub state: Mutex<RequestRegistryState>,
    pub available: Condvar,
}

pub(crate) struct RequestRegistryState {
    pub requests: HashMap<RequestId, RequestState>,
    pub ready: VecDeque<QueuedSecurityEvent>,
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
    pub pending_l3_job_ids: HashSet<u64>,
    pub pending_l3_job_categories: HashMap<u64, String>,
    pub gate_results: HashMap<String, Vec<String>>,
    pub pending_dynamic_pii: Option<PendingDynamicPii>,
    pub usable_results: usize,
    pub failures: Vec<SecurityFailure>,
    pub completion: Option<SecurityRequestCompletion>,
}

impl RequestState {
    pub(crate) fn running() -> Self {
        Self {
            pending_l3_job_ids: HashSet::new(),
            pending_l3_job_categories: HashMap::new(),
            gate_results: HashMap::new(),
            pending_dynamic_pii: None,
            usable_results: 0,
            failures: Vec::new(),
            completion: None,
        }
    }
}

#[derive(Clone)]
pub(crate) struct L3Worker {
    state: Arc<L3WorkerState>,
}

struct L3WorkerState {
    jobs: Mutex<Vec<L3WorkerJob>>,
    scheduler: Mutex<FairSchedulerState>,
    available: Condvar,
    models: Mutex<HashMap<String, L3ModelHandle>>,
    dynamic_pii_models: Mutex<HashMap<String, DynamicPiiHandle>>,
    chunk_cache: Arc<DecisionCache>,
    requests: Arc<RequestRegistry>,
    next_sequence: Mutex<u64>,
}

#[derive(Default)]
struct FairSchedulerState {
    deficits_ms: HashMap<String, f64>,
    observed_cost_ms: HashMap<String, f64>,
    cursor: Option<String>,
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
    estimated_cost_ms: u64,
    fairness_quantum_ms: u64,
    max_wait_ms: u64,
    enqueued_at: Instant,
    execution: ScanExecution,
    degraded_factor: f64,
    l3_candidate_spans: Vec<ByteSpan>,
    dynamic_pii_config: Option<DynamicPiiConfig>,
    dynamic_pii_activated_rules: Vec<usize>,
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
    pub dynamic_pii_config: Option<DynamicPiiConfig>,
    pub dynamic_pii_activated_rules: Vec<usize>,
}

pub(crate) struct PendingDynamicPii {
    pub job: L3JobSpec,
    pub accepted_at: Instant,
}

impl L3Worker {
    pub(crate) fn start(requests: Arc<RequestRegistry>) -> Self {
        let state = Arc::new(L3WorkerState {
            jobs: Mutex::new(Vec::new()),
            scheduler: Mutex::new(FairSchedulerState::default()),
            available: Condvar::new(),
            models: Mutex::new(HashMap::new()),
            dynamic_pii_models: Mutex::new(HashMap::new()),
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

    pub(crate) fn has_model(&self, model: &str) -> bool {
        self.state
            .models
            .lock()
            .expect("l3 model registry mutex poisoned")
            .contains_key(model)
            || self
                .state
                .dynamic_pii_models
                .lock()
                .expect("dynamic-pii model registry mutex poisoned")
                .contains_key(model)
    }

    pub(crate) fn register_dynamic_pii(
        &self,
        model: impl Into<String>,
        runtime: DynamicPiiRuntime,
    ) {
        self.state
            .dynamic_pii_models
            .lock()
            .expect("dynamic-pii model registry mutex poisoned")
            .insert(model.into(), Arc::new(Mutex::new(runtime)));
    }

    pub(crate) fn enqueue(&self, spec: L3JobSpec) {
        let (estimated_cost_ms, fairness_quantum_ms, max_wait_ms) = scheduling_values(&spec);
        let job = L3WorkerJob {
            job_id: spec.job_id,
            request_id: spec.request_id,
            category: spec.category,
            model: spec.model,
            text: spec.text,
            fallback: spec.fallback,
            priority: spec.priority,
            ttl_ms: spec.ttl_ms,
            estimated_cost_ms,
            fairness_quantum_ms,
            max_wait_ms,
            enqueued_at: Instant::now(),
            execution: spec.execution,
            degraded_factor: spec.degraded_factor,
            l3_candidate_spans: spec.l3_candidate_spans,
            dynamic_pii_config: spec.dynamic_pii_config,
            dynamic_pii_activated_rules: spec.dynamic_pii_activated_rules,
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

    pub(crate) fn resolve_dynamic_pii(&self, request_id: &str) {
        resolve_dynamic_pii(&self.state, request_id);
    }

    #[cfg(feature = "test-util")]
    pub(crate) fn enqueue_test_delay(&self, spec: L3JobSpec, delay_ms: u64) {
        self.enqueue_test_delays(vec![(spec, delay_ms)]);
    }

    #[cfg(feature = "test-util")]
    pub(crate) fn enqueue_test_delays(&self, specs: Vec<(L3JobSpec, u64)>) {
        let mut jobs = self.state.jobs.lock().expect("l3 job queue mutex poisoned");
        for (spec, delay_ms) in specs {
            let (estimated_cost_ms, fairness_quantum_ms, max_wait_ms) = scheduling_values(&spec);
            jobs.push(L3WorkerJob {
                job_id: spec.job_id,
                request_id: spec.request_id,
                category: spec.category,
                model: spec.model,
                text: spec.text,
                fallback: spec.fallback,
                priority: spec.priority,
                ttl_ms: spec.ttl_ms,
                estimated_cost_ms,
                fairness_quantum_ms,
                max_wait_ms,
                enqueued_at: Instant::now(),
                execution: spec.execution,
                degraded_factor: spec.degraded_factor,
                l3_candidate_spans: spec.l3_candidate_spans,
                dynamic_pii_config: spec.dynamic_pii_config,
                dynamic_pii_activated_rules: spec.dynamic_pii_activated_rules,
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
        sweep_expired_models(&state);
        let workload = job.category.clone();
        let configured_cost_ms = job.estimated_cost_ms;
        let started = Instant::now();
        let (job_id, request_id, result) = execute_job(&state, job);
        observe_cost(
            &state,
            &workload,
            configured_cost_ms,
            started.elapsed().as_secs_f64() * 1_000.0,
        );
        finish_job(&state, job_id, request_id, result);
    }
}

fn next_job(state: &L3WorkerState) -> L3WorkerJob {
    let mut jobs = state.jobs.lock().expect("l3 job queue mutex poisoned");
    loop {
        if !jobs.is_empty() {
            let mut scheduler = state.scheduler.lock().expect("l3 scheduler mutex poisoned");
            let selected = select_fair_job(&jobs, &mut scheduler);
            return jobs.swap_remove(selected);
        }
        let (next_jobs, wait) = state
            .available
            .wait_timeout(jobs, L3_IDLE_SWEEP_INTERVAL)
            .expect("l3 job queue mutex poisoned");
        jobs = next_jobs;
        if wait.timed_out() && jobs.is_empty() {
            drop(jobs);
            sweep_expired_models(state);
            jobs = state.jobs.lock().expect("l3 job queue mutex poisoned");
        }
    }
}

fn scheduling_values(spec: &L3JobSpec) -> (u64, u64, u64) {
    let policy = spec.execution.l3_policy();
    (
        estimated_cost_ms(policy, &spec.category, &spec.model),
        policy.fairness_quantum_ms.max(1),
        policy.max_wait_ms,
    )
}

fn select_fair_job(jobs: &[L3WorkerJob], scheduler: &mut FairSchedulerState) -> usize {
    if let Some((index, _)) = jobs
        .iter()
        .enumerate()
        .filter(|(_, job)| {
            job.max_wait_ms > 0
                && job.enqueued_at.elapsed().as_millis() >= u128::from(job.max_wait_ms)
        })
        .min_by(|(_, left), (_, right)| {
            left.enqueued_at
                .cmp(&right.enqueued_at)
                .then_with(|| left.sequence.cmp(&right.sequence))
        })
    {
        return index;
    }

    let mut workloads = jobs
        .iter()
        .map(|job| job.category.clone())
        .collect::<Vec<_>>();
    workloads.sort();
    workloads.dedup();
    workloads.sort_by_key(|workload| {
        jobs.iter()
            .filter(|job| &job.category == workload)
            .map(|job| (job.priority, job.sequence))
            .min()
            .unwrap()
    });
    let active = workloads.iter().cloned().collect::<HashSet<_>>();
    scheduler
        .deficits_ms
        .retain(|workload, _| active.contains(workload));

    let mut cursor = scheduler
        .cursor
        .as_ref()
        .and_then(|workload| workloads.iter().position(|item| item == workload))
        .unwrap_or(0);
    loop {
        let workload = &workloads[cursor];
        let candidate = jobs
            .iter()
            .enumerate()
            .filter(|(_, job)| &job.category == workload)
            .min_by_key(|(_, job)| (job.priority, job.sequence))
            .map(|(index, _)| index)
            .unwrap();
        let job = &jobs[candidate];
        let cost_ms = scheduler
            .observed_cost_ms
            .get(workload)
            .copied()
            .unwrap_or(job.estimated_cost_ms as f64)
            .max(1.0);
        let is_new = !scheduler.deficits_ms.contains_key(workload);
        let deficit = scheduler
            .deficits_ms
            .entry(workload.clone())
            .or_insert(cost_ms);
        if !is_new {
            *deficit += job.fairness_quantum_ms as f64;
        }
        if *deficit >= cost_ms {
            *deficit -= cost_ms;
            cursor = (cursor + 1) % workloads.len();
            scheduler.cursor = Some(workloads[cursor].clone());
            return candidate;
        }
        cursor = (cursor + 1) % workloads.len();
    }
}

fn observe_cost(state: &L3WorkerState, workload: &str, configured_ms: u64, actual_ms: f64) {
    let mut scheduler = state.scheduler.lock().expect("l3 scheduler mutex poisoned");
    let previous = scheduler
        .observed_cost_ms
        .entry(workload.to_string())
        .or_insert(configured_ms.max(1) as f64);
    *previous = (*previous * 0.8 + actual_ms.max(1.0) * 0.2).clamp(1.0, 60_000.0);
}

fn sweep_expired_models(state: &L3WorkerState) {
    if let Ok(models) = state.models.try_lock() {
        for model in models.values() {
            if let Ok(mut model) = model.try_lock() {
                model.evict_expired();
            }
        }
    }
    if let Ok(models) = state.dynamic_pii_models.try_lock() {
        for model in models.values() {
            if let Ok(mut model) = model.try_lock() {
                model.evict_expired();
            }
        }
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

    if job.dynamic_pii_config.is_some() {
        let model = match state
            .dynamic_pii_models
            .lock()
            .expect("dynamic-pii model registry mutex poisoned")
            .get(&job.model)
            .cloned()
        {
            Some(model) => model,
            None => {
                let result = degraded_error_result(
                    job.fallback.clone(),
                    elapsed_ms(job.enqueued_at),
                    job.ttl_ms,
                    job.degraded_factor,
                    format!("L3 model '{}' is not registered", job.model),
                );
                return (job.job_id, job.request_id, result);
            }
        };
        return execute_with_deadline(job, move |job| run_dynamic_pii_job(job, model));
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

fn run_dynamic_pii_job(
    job: L3WorkerJob,
    runtime: DynamicPiiHandle,
) -> Result<SecurityScanResult, String> {
    let config = job
        .dynamic_pii_config
        .as_ref()
        .ok_or_else(|| "dynamic-pii job is missing its configuration".to_string())?;
    let output = runtime
        .lock()
        .map_err(|error| format!("dynamic-pii runtime mutex poisoned: {error}"))?
        .infer(&job.text, config)
        .map_err(|error| error.to_string())?;
    let confidence = output
        .evidence_spans
        .iter()
        .map(|span| span.score)
        .max_by(f64::total_cmp)
        .unwrap_or(0.0);
    let has_entities = !output.evidence_spans.is_empty();
    let class_name = if has_entities {
        "entities"
    } else {
        "no_entities"
    };
    let layer = LayerResult {
        level: SecurityLevel::L3.as_str().to_string(),
        layer_type: "dynamic_pii".to_string(),
        class_name: class_name.to_string(),
        confidence,
        matched: true,
        duration_ms: output.duration_ms,
        thresholds: HashMap::from([("default".to_string(), f64::from(config.threshold))]),
        details: HashMap::from([
            ("pipeline".to_string(), serde_json::json!(job.category)),
            ("model".to_string(), serde_json::json!(job.model)),
            (
                "model_path".to_string(),
                serde_json::json!(output.model_path.display().to_string()),
            ),
            ("labels".to_string(), serde_json::json!(config.labels)),
            (
                "execution_gate".to_string(),
                serde_json::json!(config.execution_gate),
            ),
            (
                "activated_conditional_rules".to_string(),
                serde_json::json!(job.dynamic_pii_activated_rules),
            ),
            (
                "entity_count".to_string(),
                serde_json::json!(output.evidence_spans.len()),
            ),
            (
                "l3_queue_wait_ms".to_string(),
                serde_json::json!((elapsed_ms(job.enqueued_at) - output.duration_ms).max(0.0)),
            ),
            ("ttl_ms".to_string(), serde_json::json!(job.ttl_ms)),
            ("priority".to_string(), serde_json::json!(job.priority)),
            ("job_id".to_string(), serde_json::json!(job.job_id)),
        ]),
    };
    let mut result = job.fallback;
    result.class_name = class_name.to_string();
    result.confidence = confidence;
    result.level = SecurityLevel::L3.as_str().to_string();
    result.duration_ms = output.duration_ms;
    result.layers = vec![layer];
    result.evidence_spans = output.evidence_spans;
    Ok(result)
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
    let token_chunks = model
        .lock()
        .map_err(|err| format!("L3 model mutex poisoned: {err}"))?
        .token_chunks(&job.text, L3_OVERLAP_TOKENS, job.execution.backend())
        .map_err(|err| err.to_string())?;
    let chunks = selected_l3_chunks(token_chunks, &job.l3_candidate_spans);
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

fn selected_l3_chunks(chunks: Vec<TokenTextChunk>, candidate_spans: &[ByteSpan]) -> Vec<String> {
    if candidate_spans.is_empty() {
        return chunks.into_iter().map(|chunk| chunk.text).collect();
    }

    let selected = chunks
        .iter()
        .filter(|chunk| {
            candidate_spans
                .iter()
                .any(|span| span.start < chunk.end_byte && span.end > chunk.start_byte)
        })
        .map(|chunk| chunk.text.clone())
        .collect::<Vec<_>>();
    if selected.is_empty() {
        chunks.into_iter().map(|chunk| chunk.text).collect()
    } else {
        selected
    }
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
    worker: &Arc<L3WorkerState>,
    job_id: u64,
    request_id: RequestId,
    result: SecurityScanResult,
) {
    let mut registry = worker
        .requests
        .state
        .lock()
        .expect("request registry mutex poisoned");
    let failure = failure_from_scan_result(&result);
    let publish_result = if let Some(state) = registry.requests.get_mut(&request_id) {
        if state.completion.is_some() || !state.pending_l3_job_ids.remove(&job_id) {
            return;
        }
        state.pending_l3_job_categories.remove(&job_id);
        match failure {
            Some(failure) => {
                state.failures.push(failure);
                false
            }
            None => {
                state.usable_results += 1;
                state
                    .gate_results
                    .entry(result.category.clone())
                    .or_default()
                    .push(result.class_name.clone());
                true
            }
        }
    } else {
        false
    };
    if publish_result {
        registry
            .ready
            .push_back(QueuedSecurityEvent::Result(QueuedSecurityScanResult {
                request_id: request_id.clone(),
                result,
            }));
    }
    drop(registry);
    resolve_dynamic_pii(worker, &request_id);
    let mut registry = worker
        .requests
        .state
        .lock()
        .expect("request registry mutex poisoned");
    finish_request_if_ready(&mut registry, &request_id);
    worker.requests.available.notify_all();
}

fn resolve_dynamic_pii(worker: &Arc<L3WorkerState>, request_id: &str) {
    let job = {
        let mut registry = worker
            .requests
            .state
            .lock()
            .expect("request registry mutex poisoned");
        let Some(request) = registry.requests.get(request_id) else {
            return;
        };
        let Some(pending) = request.pending_dynamic_pii.as_ref() else {
            return;
        };
        let config = pending
            .job
            .dynamic_pii_config
            .as_ref()
            .expect("pending dynamic-pii job is missing config");
        let waiting_for_source = config.referenced_pipelines().iter().any(|pipeline| {
            request
                .pending_l3_job_categories
                .values()
                .any(|category| category == pipeline)
        });
        if waiting_for_source {
            return;
        }

        let request = registry
            .requests
            .get_mut(request_id)
            .expect("request disappeared while resolving dynamic-pii");
        let mut pending = request
            .pending_dynamic_pii
            .take()
            .expect("pending dynamic-pii job disappeared");
        let config = pending
            .job
            .dynamic_pii_config
            .as_ref()
            .expect("pending dynamic-pii job is missing config");
        let timeout_ms = config.timeout_ms;
        match config.resolve(&request.gate_results) {
            Some(resolution) => {
                pending.job.dynamic_pii_config = Some(resolution.config);
                pending.job.dynamic_pii_activated_rules = resolution.activated_conditional_rules;
                pending.job.ttl_ms =
                    timeout_ms.saturating_sub(pending.accepted_at.elapsed().as_millis() as u64);
                Some(pending.job)
            }
            None => {
                request.pending_l3_job_ids.remove(&pending.job.job_id);
                finish_request_if_ready(&mut registry, request_id);
                worker.requests.available.notify_all();
                None
            }
        }
    };
    if let Some(job) = job {
        L3Worker {
            state: Arc::clone(worker),
        }
        .enqueue(job);
    }
}

pub(crate) fn failure_from_scan_result(result: &SecurityScanResult) -> Option<SecurityFailure> {
    let layer = result.layers.iter().find(|layer| {
        matches!(
            layer.layer_type.as_str(),
            "scanner_error" | "ntdb_error" | "degraded_timeout" | "degraded_error"
        )
    })?;
    let (stage, kind, retryable, message_key) = match layer.layer_type.as_str() {
        "scanner_error" => (
            SecurityFailureStage::Scanner,
            SecurityFailureKind::Internal,
            false,
            "error",
        ),
        "ntdb_error" => (
            SecurityFailureStage::Inference,
            SecurityFailureKind::InferenceFailure,
            true,
            "error",
        ),
        "degraded_timeout" => (
            SecurityFailureStage::Worker,
            SecurityFailureKind::Timeout,
            true,
            "degraded_reason",
        ),
        "degraded_error" => (
            SecurityFailureStage::Worker,
            SecurityFailureKind::WorkerUnavailable,
            true,
            "error",
        ),
        _ => unreachable!(),
    };
    let message = layer
        .details
        .get(message_key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or(layer.layer_type.as_str())
        .to_string();
    Some(SecurityFailure {
        stage,
        level: layer.level.parse::<SecurityLevel>().ok(),
        detector_id: Some(result.model.clone()),
        kind,
        retryable,
        message,
    })
}

pub(crate) fn finish_request_if_ready(
    registry: &mut RequestRegistryState,
    request_id: &str,
) -> Option<SecurityRequestCompletion> {
    let completion = {
        let state = registry.requests.get_mut(request_id)?;
        if state.completion.is_some() || !state.pending_l3_job_ids.is_empty() {
            return None;
        }
        let completion = if state.failures.is_empty() {
            SecurityRequestCompletion::Complete
        } else if state.usable_results > 0 {
            SecurityRequestCompletion::Degraded {
                failures: state.failures.clone(),
            }
        } else {
            SecurityRequestCompletion::Failed {
                failures: state.failures.clone(),
            }
        };
        state.completion = Some(completion.clone());
        completion
    };

    registry.ready.push_back(QueuedSecurityEvent::Finished {
        request_id: request_id.to_string(),
        completion: completion.clone(),
    });
    Some(completion)
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_spans_reduce_l3_chunks() {
        let chunks = (0..4)
            .map(|index| TokenTextChunk {
                start_byte: index * 200,
                end_byte: index * 200 + 256,
                text: index.to_string(),
            })
            .collect::<Vec<_>>();
        let full = selected_l3_chunks(chunks.clone(), &[]);
        let selected = selected_l3_chunks(
            chunks,
            &[ByteSpan {
                start: 400,
                end: 500,
            }],
        );

        assert!(selected.len() < full.len());
        assert_eq!(selected, ["1", "2"]);
    }
}
