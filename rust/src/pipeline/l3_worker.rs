// SPDX-License-Identifier: GPL-3.0-only
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::cache::{
    CacheCoordinator, CacheError, ExactCacheConfig, HistoricalSimilarityCache, PiiChunkCache,
};
use crate::ml::dynamic_pii::DynamicPiiRuntime;
use crate::ml::ntdb_executor::{L2ChunkOutput, L3Candidate};
use crate::ml::onnx::{LazyOnnxTextClassifier, TokenTextChunk};
use crate::ml::unified_onnx::{LazyUnifiedOnnxClassifier, UNIFIED_MODEL};
use crate::pipeline::l3_schedule::{attach_l2_embeddings, selected_l3_chunks, SelectedL3Chunk};
use crate::{
    dynamic_pii::{DynamicPiiInferenceGroup, DynamicPiiSourceChunk, DynamicPiiTextRange},
    DynamicPiiConfig, L3Strategy, QueuedSecurityEvent, QueuedSecurityProgress,
    QueuedSecurityScanResult, RequestId, ScanExecution, SecurityFailure, SecurityFailureKind,
    SecurityFailureStage, SecurityLevel, SecurityRequestCompletion, SecurityScanResult,
};

use super::decision_cache::DecisionCache;
use super::l3_routing::estimated_cost_ms;
use super::{degraded_error_result, degraded_timeout_result};

mod dedicated;
mod unified;

#[cfg(feature = "test-util")]
pub use dedicated::selected_l3_chunks_for_test;
#[cfg(feature = "test-util")]
pub use unified::{
    aggregate_unified_head_for_test, public_unified_class_for_test,
    replace_unified_pending_layer_for_test, unified_coalescing_snapshot,
    unified_metadata_details_for_test, unified_outputs_have_same_classes_for_heads_for_test,
    UnifiedCoalescingSnapshot,
};

type L3ModelHandle = Arc<Mutex<LazyOnnxTextClassifier>>;
type DynamicPiiHandle = Arc<Mutex<DynamicPiiRuntime>>;
type UnifiedModelHandle = Arc<Mutex<LazyUnifiedOnnxClassifier>>;
pub(super) const L3_DIRECT_CONTENT_TOKEN_LIMIT: usize = crate::ml::tokenizer::CONTENT_TOKENS;
const L3_IDLE_SWEEP_INTERVAL: Duration = Duration::from_secs(30);
/// Minimum L3 confidence for an `injection`/`threat` positive to stop the whole request.
const REQUEST_WIDE_EARLY_EXIT_CONFIDENCE: f64 = 0.93;

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
    pub gate_chunk_results: HashMap<String, Vec<DynamicPiiSourceChunk>>,
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
            gate_chunk_results: HashMap::new(),
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
    unified_model: Mutex<Option<UnifiedModelHandle>>,
    unified_runs: Mutex<HashMap<String, unified::UnifiedRunState>>,
    unified_cache: Mutex<HashMap<String, unified::UnifiedCacheEntry>>,
    chunk_cache: Arc<DecisionCache>,
    exact_cache: Arc<CacheCoordinator>,
    pii_chunk_cache: Arc<PiiChunkCache>,
    similarity_cache: Arc<HistoricalSimilarityCache>,
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
    input: L3WorkerInput,
    fallback: SecurityScanResult,
    priority: usize,
    ttl_ms: u64,
    inference_timeout_ms: u64,
    estimated_cost_ms: u64,
    fairness_quantum_ms: u64,
    max_wait_ms: u64,
    enqueued_at: Instant,
    execution: ScanExecution,
    unified_run_key: Option<String>,
    unified_cache_key: Option<String>,
    degraded_factor: f64,
    l3_candidates: Vec<L3Candidate>,
    l2_chunk_outputs: Arc<[L2ChunkOutput]>,
    dynamic_pii_config: Option<DynamicPiiConfig>,
    dynamic_pii_inference_groups: Vec<DynamicPiiInferenceGroup>,
    dynamic_pii_activated_rules: Vec<usize>,
    sequence: u64,
    #[cfg(feature = "test-util")]
    test_delay_ms: Option<u64>,
}

#[derive(Clone)]
enum L3WorkerInput {
    Text(Arc<str>),
    PlannedChunks(Vec<SelectedL3Chunk>),
}

#[derive(Clone)]
pub(crate) struct L3JobSpec {
    pub job_id: u64,
    pub request_id: RequestId,
    pub category: String,
    pub model: String,
    pub text: Arc<str>,
    pub fallback: SecurityScanResult,
    pub priority: usize,
    pub ttl_ms: u64,
    pub inference_timeout_ms: u64,
    pub execution: ScanExecution,
    pub degraded_factor: f64,
    pub l3_candidates: Vec<L3Candidate>,
    pub l2_chunk_outputs: Arc<[L2ChunkOutput]>,
    pub dynamic_pii_config: Option<DynamicPiiConfig>,
    pub dynamic_pii_inference_groups: Vec<DynamicPiiInferenceGroup>,
    pub dynamic_pii_activated_rules: Vec<usize>,
}

pub(crate) struct PendingDynamicPii {
    pub job: L3JobSpec,
}

impl L3Worker {
    pub(crate) fn start_with_cache(
        requests: Arc<RequestRegistry>,
        cache_config: ExactCacheConfig,
    ) -> Result<Self, CacheError> {
        let exact_cache = Arc::new(CacheCoordinator::from_config(cache_config)?);
        let pii_chunk_cache = Arc::new(PiiChunkCache::new(Arc::clone(&exact_cache)));
        let similarity_cache = Arc::new(HistoricalSimilarityCache::new(Arc::clone(&exact_cache)));
        let state = Arc::new(L3WorkerState {
            jobs: Mutex::new(Vec::new()),
            scheduler: Mutex::new(FairSchedulerState::default()),
            available: Condvar::new(),
            models: Mutex::new(HashMap::new()),
            dynamic_pii_models: Mutex::new(HashMap::new()),
            unified_model: Mutex::new(None),
            unified_runs: Mutex::new(HashMap::new()),
            unified_cache: Mutex::new(HashMap::new()),
            chunk_cache: Arc::new(DecisionCache::default()),
            exact_cache,
            pii_chunk_cache,
            similarity_cache,
            requests,
            next_sequence: Mutex::new(0),
        });
        let worker_state = Arc::clone(&state);
        thread::spawn(move || worker_loop(worker_state));
        Ok(Self { state })
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

    pub(crate) fn flush_cache(&self) -> Result<(), CacheError> {
        self.state.exact_cache.flush()
    }

    pub(crate) fn reset_cache_connections(&self) -> Result<(), CacheError> {
        self.state.exact_cache.reset_persistent_connections()
    }

    pub(crate) fn reset_cache(&self, until_unix_ms: u64) -> Result<usize, CacheError> {
        self.state.exact_cache.reset_cache(until_unix_ms)
    }

    pub(crate) fn cache_storage_location(&self) -> Option<std::path::PathBuf> {
        self.state
            .exact_cache
            .storage_location()
            .map(std::path::Path::to_path_buf)
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

    pub(crate) fn stop_models(&self) {
        let models = self
            .state
            .models
            .lock()
            .expect("l3 model registry mutex poisoned");
        for model in models.values() {
            model
                .lock()
                .expect("l3 model mutex poisoned")
                .force_unload();
        }
        drop(models);

        let dynamic_models = self
            .state
            .dynamic_pii_models
            .lock()
            .expect("dynamic-pii model registry mutex poisoned");
        for model in dynamic_models.values() {
            model
                .lock()
                .expect("dynamic-pii model mutex poisoned")
                .force_unload();
        }
        drop(dynamic_models);

        let unified = self
            .state
            .unified_model
            .lock()
            .expect("unified model registry mutex poisoned");
        if let Some(model) = unified.as_ref() {
            model
                .lock()
                .expect("unified model mutex poisoned")
                .force_unload();
        }
        drop(unified);

        self.state
            .unified_runs
            .lock()
            .expect("unified run mutex poisoned")
            .clear();
        self.state
            .unified_cache
            .lock()
            .expect("unified cache mutex poisoned")
            .clear();
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
            || (model == UNIFIED_MODEL
                && self
                    .state
                    .unified_model
                    .lock()
                    .expect("unified model registry mutex poisoned")
                    .is_some())
    }

    pub(crate) fn register_unified(&self, classifier: LazyUnifiedOnnxClassifier) {
        *self
            .state
            .unified_model
            .lock()
            .expect("unified model registry mutex poisoned") =
            Some(Arc::new(Mutex::new(classifier)));
    }

    pub(crate) fn configure_strategy(&self, strategy: L3Strategy) {
        match strategy {
            L3Strategy::Dedicated => {
                *self
                    .state
                    .unified_model
                    .lock()
                    .expect("unified model registry mutex poisoned") = None;
                self.state
                    .unified_runs
                    .lock()
                    .expect("unified run mutex poisoned")
                    .clear();
                self.state
                    .unified_cache
                    .lock()
                    .expect("unified cache mutex poisoned")
                    .clear();
            }
            L3Strategy::Multi => {
                self.state
                    .models
                    .lock()
                    .expect("l3 model registry mutex poisoned")
                    .clear();
            }
        }
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
        if spec.execution.l3_strategy() == L3Strategy::Multi && spec.dynamic_pii_config.is_none() {
            unified::enqueue(self, spec);
            return;
        }
        self.enqueue_physical(spec);
    }

    fn enqueue_physical(&self, spec: L3JobSpec) {
        let job = match self.build_physical_job(spec, None, None) {
            Ok(job) => job,
            Err((job_id, request_id, result)) => {
                finish_job(&self.state, job_id, request_id, result);
                return;
            }
        };
        self.state
            .jobs
            .lock()
            .expect("l3 job queue mutex poisoned")
            .push(job);
        self.state.available.notify_one();
    }

    fn enqueue_unified_physical(&self, spec: L3JobSpec, run_key: String, cache_key: String) {
        let job = match self.build_physical_job(spec, Some(run_key), Some(cache_key)) {
            Ok(job) => job,
            Err((job_id, request_id, result)) => {
                finish_job(&self.state, job_id, request_id, result);
                return;
            }
        };
        self.state
            .jobs
            .lock()
            .expect("l3 job queue mutex poisoned")
            .push(job);
        self.state.available.notify_one();
    }

    #[allow(clippy::result_large_err)]
    fn build_physical_job(
        &self,
        spec: L3JobSpec,
        unified_run_key: Option<String>,
        unified_cache_key: Option<String>,
    ) -> Result<L3WorkerJob, (u64, RequestId, SecurityScanResult)> {
        let (estimated_cost_ms, fairness_quantum_ms, max_wait_ms) = scheduling_values(&spec);
        let input = match self.input_for_spec(&spec) {
            Ok(input) => input,
            Err(error) => {
                let result = degraded_error_result(
                    spec.fallback,
                    0.0,
                    spec.ttl_ms,
                    spec.degraded_factor,
                    error,
                );
                return Err((spec.job_id, spec.request_id, result));
            }
        };
        Ok(L3WorkerJob {
            job_id: spec.job_id,
            request_id: spec.request_id,
            category: spec.category,
            model: spec.model,
            input,
            fallback: spec.fallback,
            priority: spec.priority,
            ttl_ms: spec.ttl_ms,
            inference_timeout_ms: spec.inference_timeout_ms,
            estimated_cost_ms,
            fairness_quantum_ms,
            max_wait_ms,
            enqueued_at: Instant::now(),
            execution: spec.execution,
            unified_run_key,
            unified_cache_key,
            degraded_factor: spec.degraded_factor,
            l3_candidates: spec.l3_candidates,
            l2_chunk_outputs: spec.l2_chunk_outputs,
            dynamic_pii_config: spec.dynamic_pii_config,
            dynamic_pii_inference_groups: spec.dynamic_pii_inference_groups,
            dynamic_pii_activated_rules: spec.dynamic_pii_activated_rules,
            sequence: spec.job_id,
            #[cfg(feature = "test-util")]
            test_delay_ms: None,
        })
    }

    fn input_for_spec(&self, spec: &L3JobSpec) -> Result<L3WorkerInput, String> {
        if spec.dynamic_pii_config.is_some() {
            return Ok(L3WorkerInput::Text(spec.text.clone()));
        }
        self.plan_chunks_for_spec(spec)
            .map(L3WorkerInput::PlannedChunks)
    }

    fn plan_chunks_for_spec(&self, spec: &L3JobSpec) -> Result<Vec<SelectedL3Chunk>, String> {
        let token_chunks = token_chunks_from_l2_outputs(spec)?;
        let clustering = if spec.execution.l3_strategy() == L3Strategy::Multi {
            unified::selection_clustering_for_spec(spec)
        } else {
            spec.execution
                .l3_policy()
                .pipeline_policy(&spec.category, &spec.model)
                .clustering
        };
        let mut chunks = selected_l3_chunks(token_chunks, &spec.l3_candidates, clustering);
        if chunks.is_empty() {
            return Err("L3 candidates do not contain any prepared L2 chunk".to_string());
        }
        attach_l2_embeddings(&mut chunks, &spec.l2_chunk_outputs);
        Ok(chunks)
    }

    pub(crate) fn resolve_dynamic_pii(&self, request_id: &str) {
        resolve_dynamic_pii(&self.state, request_id);
    }

    pub(crate) fn remove_request(&self, request_id: &str) {
        unified::remove_request(&self.state, request_id);
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
                input: L3WorkerInput::Text(spec.text),
                fallback: spec.fallback,
                priority: spec.priority,
                ttl_ms: spec.ttl_ms,
                inference_timeout_ms: spec.inference_timeout_ms,
                estimated_cost_ms,
                fairness_quantum_ms,
                max_wait_ms,
                enqueued_at: Instant::now(),
                execution: spec.execution,
                unified_run_key: None,
                unified_cache_key: None,
                degraded_factor: spec.degraded_factor,
                l3_candidates: spec.l3_candidates,
                l2_chunk_outputs: spec.l2_chunk_outputs,
                dynamic_pii_config: spec.dynamic_pii_config,
                dynamic_pii_inference_groups: spec.dynamic_pii_inference_groups,
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
        #[cfg(feature = "test-util")]
        let simulated_cost_ms = job.test_delay_ms.map(|delay| delay as f64);
        let started = Instant::now();
        if job.execution.l3_strategy() == L3Strategy::Multi && job.dynamic_pii_config.is_none() {
            let run_key = unified::run_key_for_job(&job);
            let cache_key = unified::cache_key_for_job(&job);
            let outcome = unified::execute(&state, job);
            observe_cost(
                &state,
                UNIFIED_MODEL,
                configured_cost_ms,
                started.elapsed().as_secs_f64() * 1_000.0,
            );
            unified::finish_run(&state, run_key, cache_key, outcome);
            continue;
        }
        let (job_id, request_id, result) = dedicated::execute(&state, job);
        let actual_cost_ms = started.elapsed().as_secs_f64() * 1_000.0;
        // Synthetic delay jobs model a known service cost. OS scheduling jitter
        // must not change the fairness policy exercised by those tests.
        #[cfg(feature = "test-util")]
        let actual_cost_ms = simulated_cost_ms.unwrap_or(actual_cost_ms);
        observe_cost(&state, &workload, configured_cost_ms, actual_cost_ms);
        finish_job(&state, job_id, request_id, result);
    }
}

fn next_job(state: &Arc<L3WorkerState>) -> L3WorkerJob {
    let mut jobs = state.jobs.lock().expect("l3 job queue mutex poisoned");
    loop {
        let expired = drain_expired_jobs(&mut jobs);
        if !expired.is_empty() {
            drop(jobs);
            finish_expired_jobs(state, expired);
            jobs = state.jobs.lock().expect("l3 job queue mutex poisoned");
            continue;
        }
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

fn drain_expired_jobs(jobs: &mut Vec<L3WorkerJob>) -> Vec<L3WorkerJob> {
    let mut expired = Vec::new();
    let mut index = 0;
    while index < jobs.len() {
        if queue_ttl_expired(&jobs[index]) {
            expired.push(jobs.swap_remove(index));
        } else {
            index += 1;
        }
    }
    expired
}

fn queue_ttl_expired(job: &L3WorkerJob) -> bool {
    job.enqueued_at.elapsed().as_millis() >= u128::from(job.ttl_ms)
}

fn finish_expired_jobs(state: &Arc<L3WorkerState>, jobs: Vec<L3WorkerJob>) {
    for job in jobs {
        finish_expired_job(state, job);
    }
}

fn finish_expired_job(state: &Arc<L3WorkerState>, job: L3WorkerJob) {
    let queued_ms = elapsed_ms(job.enqueued_at);
    if job.execution.l3_strategy() == L3Strategy::Multi && job.dynamic_pii_config.is_none() {
        let run_key = unified::run_key_for_job(&job);
        let cache_key = unified::cache_key_for_job(&job);
        unified::finish_run(
            state,
            run_key,
            cache_key,
            unified::UnifiedRunOutcome::Failed(unified::UnifiedRunFailure::Timeout {
                queued_ms,
                timeout_ms: job.ttl_ms,
                reason: "expired_before_inference",
            }),
        );
        return;
    }

    let result = queue_timeout_result(&job, queued_ms, "expired_before_inference");
    finish_job(state, job.job_id, job.request_id, result);
}

fn queue_timeout_result(job: &L3WorkerJob, queued_ms: f64, reason: &str) -> SecurityScanResult {
    let mut result = degraded_timeout_result(
        job.fallback.clone(),
        queued_ms,
        job.ttl_ms,
        job.degraded_factor,
    );
    if let Some(layer) = result
        .layers
        .iter_mut()
        .find(|layer| layer.layer_type == "degraded_timeout")
    {
        layer
            .details
            .insert("timeout_reason".to_string(), serde_json::json!(reason));
        layer.details.insert(
            "queue_timeout_ms".to_string(),
            serde_json::json!(job.ttl_ms),
        );
        layer.details.insert(
            "inference_timeout_ms".to_string(),
            serde_json::json!(job.inference_timeout_ms),
        );
    }
    result
}

fn scheduling_values(spec: &L3JobSpec) -> (u64, u64, u64) {
    let policy = spec.execution.l3_policy();
    (
        estimated_cost_ms(policy, &spec.category, &spec.model),
        policy.fairness_quantum_ms.max(1),
        policy.max_wait_ms,
    )
}

fn token_chunks_from_l2_outputs(spec: &L3JobSpec) -> Result<Vec<TokenTextChunk>, String> {
    if spec.l2_chunk_outputs.is_empty() {
        return Err("L3 requires prepared NTDB v4 token chunks".to_string());
    }

    let mut outputs = spec.l2_chunk_outputs.to_vec();
    outputs.sort_by_key(|output| (output.span.start, output.span.end));

    let mut chunks = Vec::with_capacity(outputs.len());
    let mut index = 0;
    while index < outputs.len() {
        let span = outputs[index].span;
        let mut group_end = index + 1;
        while group_end < outputs.len() && outputs[group_end].span == span {
            group_end += 1;
        }
        let output = &outputs[index];
        for duplicate in &outputs[index..group_end] {
            if !direct_l3_token_handoff_usable(duplicate) {
                return Err(format!(
                    "invalid mmBERT L2 chunk at {}..{}: {} content tokens",
                    span.start,
                    span.end,
                    duplicate.token_ids.len()
                ));
            }
            if duplicate.token_ids != output.token_ids {
                return Err(format!(
                    "conflicting L2 token IDs at {}..{}",
                    span.start, span.end
                ));
            }
        }
        let text = spec.text.get(span.start..span.end).ok_or_else(|| {
            format!(
                "L2 chunk span {}..{} is not a valid source text range",
                span.start, span.end
            )
        })?;
        chunks.push(TokenTextChunk {
            text: text.to_string(),
            start_byte: span.start,
            end_byte: span.end,
            token_ids: output.token_ids.clone(),
            tokenizer_family: output.tokenizer_family.clone(),
        });
        index = group_end;
    }
    Ok(chunks)
}

fn direct_l3_token_handoff_usable(output: &L2ChunkOutput) -> bool {
    (!output.token_ids.is_empty() || output.span.start == output.span.end)
        && output.token_ids.len() <= L3_DIRECT_CONTENT_TOKEN_LIMIT
        && output.tokenizer_family.eq_ignore_ascii_case("mmbert")
}

fn select_fair_job(jobs: &[L3WorkerJob], scheduler: &mut FairSchedulerState) -> usize {
    let eligible_indices = eligible_l3_job_indices(jobs);
    if let Some((index, _)) = jobs
        .iter()
        .enumerate()
        .filter(|(index, _)| eligible_indices.contains(index))
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

    let mut workloads = eligible_indices
        .iter()
        .map(|index| jobs[*index].category.clone())
        .collect::<Vec<_>>();
    if workloads.is_empty() {
        workloads = jobs
            .iter()
            .map(|job| job.category.clone())
            .collect::<Vec<_>>();
    }
    workloads.sort();
    workloads.dedup();
    workloads.sort_by_key(|workload| {
        eligible_indices
            .iter()
            .filter(|index| jobs[**index].category == *workload)
            .map(|index| (jobs[*index].priority, jobs[*index].sequence))
            .min()
            .or_else(|| {
                jobs.iter()
                    .filter(|job| &job.category == workload)
                    .map(|job| (job.priority, job.sequence))
                    .min()
            })
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
        let candidate = eligible_indices
            .iter()
            .copied()
            .filter(|index| jobs[*index].category == *workload)
            .min_by_key(|index| (jobs[*index].priority, jobs[*index].sequence))
            .or_else(|| {
                jobs.iter()
                    .enumerate()
                    .filter(|(_, job)| &job.category == workload)
                    .min_by_key(|(_, job)| (job.priority, job.sequence))
                    .map(|(index, _)| index)
            })
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

fn eligible_l3_job_indices(jobs: &[L3WorkerJob]) -> HashSet<usize> {
    let mut best_priority_by_request: HashMap<&str, usize> = HashMap::new();
    for job in jobs {
        best_priority_by_request
            .entry(job.request_id.as_str())
            .and_modify(|priority| *priority = (*priority).min(job.priority))
            .or_insert(job.priority);
    }
    jobs.iter()
        .enumerate()
        .filter_map(|(index, job)| {
            let best = best_priority_by_request
                .get(job.request_id.as_str())
                .copied()
                .unwrap_or(job.priority);
            (job.priority == best).then_some(index)
        })
        .collect()
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
    unified::sweep_expired(state);
}

fn finish_job(
    worker: &Arc<L3WorkerState>,
    job_id: u64,
    request_id: RequestId,
    result: SecurityScanResult,
) {
    let request_wide_stop = request_wide_early_exit(&result);
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
                // L3 is authoritative for this pipeline: replace provisional
                // L1/L2 classes instead of keeping stale alternatives alive.
                state
                    .gate_results
                    .insert(result.category.clone(), vec![result.class_name.clone()]);
                let chunks = dynamic_pii_source_chunks(&result);
                if !chunks.is_empty() {
                    state
                        .gate_chunk_results
                        .insert(result.category.clone(), chunks);
                } else {
                    state.gate_chunk_results.remove(&result.category);
                }
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
    if let Some(reason) = request_wide_stop {
        abort_queued_l3_jobs_for_request(worker, &request_id, &reason);
    }
    resolve_dynamic_pii(worker, &request_id);
    let mut registry = worker
        .requests
        .state
        .lock()
        .expect("request registry mutex poisoned");
    finish_request_if_ready(&mut registry, &request_id);
    worker.requests.available.notify_all();
}

fn dynamic_pii_source_chunks(result: &SecurityScanResult) -> Vec<DynamicPiiSourceChunk> {
    result
        .internal_l2_chunk_outputs
        .iter()
        .filter(|output| {
            output
                .source_pipeline
                .split(',')
                .map(str::trim)
                .any(|pipeline| pipeline == result.category)
        })
        .map(|output| DynamicPiiSourceChunk {
            class_name: output.class_name.clone(),
            range: DynamicPiiTextRange {
                start_byte: output.span.start,
                end_byte: output.span.end,
            },
        })
        .collect()
}

fn final_l3_chunk_outputs(
    l2_outputs: &[L2ChunkOutput],
    pipeline: &str,
    model: &str,
    l3_outputs: &[(crate::ml::ntdb_executor::ByteSpan, String, f32)],
) -> Vec<L2ChunkOutput> {
    // L3 windows may overlap and disagree. Keep their exact ranges and remove
    // only their covered regions from L2; processing order must not erase labels.
    let mut covered = l3_outputs
        .iter()
        .map(|(span, _, _)| *span)
        .collect::<Vec<_>>();
    covered.sort_by_key(|span| (span.start, span.end));
    let mut coverage = Vec::<crate::ml::ntdb_executor::ByteSpan>::new();
    for span in covered {
        if let Some(previous) = coverage
            .last_mut()
            .filter(|previous| span.start <= previous.end)
        {
            previous.end = previous.end.max(span.end);
        } else {
            coverage.push(span);
        }
    }
    let mut outputs = l2_outputs
        .iter()
        .filter(|output| {
            output
                .source_pipeline
                .split(',')
                .map(str::trim)
                .any(|source| source == pipeline)
        })
        .flat_map(|output| {
            let mut remainder = Vec::new();
            let mut cursor = output.span.start;
            for span in &coverage {
                if span.end <= cursor {
                    continue;
                }
                if span.start >= output.span.end {
                    break;
                }
                if cursor < span.start {
                    let mut part = output.clone();
                    part.span = crate::ml::ntdb_executor::ByteSpan {
                        start: cursor,
                        end: span.start,
                    };
                    remainder.push(part);
                }
                cursor = cursor.max(span.end);
            }
            if cursor < output.span.end {
                let mut part = output.clone();
                part.span.start = cursor;
                remainder.push(part);
            }
            remainder
        })
        .map(|mut output| {
            output.embedding.clear();
            output.embedding_space.clear();
            output.token_ids.clear();
            output.tokenizer_family.clear();
            output.class_probabilities.clear();
            output.joint_v3_decision = None;
            output
        })
        .collect::<Vec<_>>();
    for (span, class_name, confidence) in l3_outputs {
        outputs.push(L2ChunkOutput {
            span: *span,
            class_name: class_name.clone(),
            confidence: *confidence,
            promoted: true,
            promote_score: None,
            promote_threshold: None,
            source_pipeline: pipeline.to_string(),
            source_model: model.to_string(),
            embedding: Vec::new(),
            embedding_space: String::new(),
            token_ids: Vec::new(),
            tokenizer_family: String::new(),
            class_probabilities: Vec::new(),
            joint_v3_decision: None,
        });
    }
    outputs.sort_by(|left, right| {
        (left.span.start, left.span.end, &left.class_name)
            .cmp(&(right.span.start, right.span.end, &right.class_name))
            .then_with(|| right.confidence.total_cmp(&left.confidence))
    });
    outputs.dedup_by(|left, right| left.span == right.span && left.class_name == right.class_name);
    outputs
}

pub(super) fn request_wide_early_exit(result: &SecurityScanResult) -> Option<String> {
    if result.level != SecurityLevel::L3.as_str() {
        return None;
    }
    if result.category != "injection" && result.category != "threat" {
        return None;
    }
    let class = result.class_name.as_str();
    if matches!(class, "safe" | "benign") {
        return None;
    }
    if result.confidence < REQUEST_WIDE_EARLY_EXIT_CONFIDENCE {
        return None;
    }
    Some(format!(
        "{}:{}:{:.4}",
        result.category, result.class_name, result.confidence
    ))
}

fn abort_queued_l3_jobs_for_request(worker: &Arc<L3WorkerState>, request_id: &str, reason: &str) {
    let aborted = {
        let mut jobs = worker.jobs.lock().expect("l3 job mutex poisoned");
        let mut aborted = Vec::new();
        let mut kept = Vec::with_capacity(jobs.len());
        for job in jobs.drain(..) {
            if job.request_id == request_id {
                aborted.push(job);
            } else {
                kept.push(job);
            }
        }
        *jobs = kept;
        aborted
    };
    if aborted.is_empty() {
        return;
    }

    let mut registry = worker
        .requests
        .state
        .lock()
        .expect("request registry mutex poisoned");
    let Some(state) = registry.requests.get_mut(request_id) else {
        return;
    };
    if state.completion.is_some() {
        return;
    }
    let mut ready = Vec::new();
    for job in aborted {
        if state.pending_l3_job_ids.remove(&job.job_id) {
            state.pending_l3_job_categories.remove(&job.job_id);
            state.usable_results += 1;
            ready.push(QueuedSecurityEvent::Result(QueuedSecurityScanResult {
                request_id: request_id.to_string(),
                result: request_wide_degraded_result(job, reason),
            }));
        }
    }
    registry.ready.extend(ready);
    worker.requests.available.notify_all();
}

fn request_wide_degraded_result(job: L3WorkerJob, reason: &str) -> SecurityScanResult {
    let mut result = job.fallback;
    result.confidence = (result.confidence * job.degraded_factor).clamp(0.0, 1.0);
    for layer in &mut result.layers {
        if layer.level == result.level && layer.layer_type != "l3_pending" {
            layer.confidence = result.confidence;
            layer
                .details
                .insert("degraded".to_string(), serde_json::json!(true));
            layer.details.insert(
                "degraded_reason".to_string(),
                serde_json::json!("request_wide_early_exit"),
            );
        }
        if layer.layer_type == "l3_pending" {
            layer.layer_type = "l3_skipped".to_string();
            layer.class_name = "skipped".to_string();
            layer.details.insert(
                "skip_reason".to_string(),
                serde_json::json!("request_wide_early_exit"),
            );
            layer.details.insert(
                "request_wide_early_exit_reason".to_string(),
                serde_json::json!(reason),
            );
        }
    }
    super::mark_decision_degraded(&mut result, "request_wide_early_exit");
    result.duration_ms = result.layers.iter().map(|layer| layer.duration_ms).sum();
    result
}

fn publish_progress(worker: &L3WorkerState, progress: QueuedSecurityProgress) {
    let mut registry = worker
        .requests
        .state
        .lock()
        .expect("request registry mutex poisoned");
    if registry
        .requests
        .get(&progress.request_id)
        .is_some_and(|state| state.completion.is_none())
    {
        registry
            .ready
            .push_back(QueuedSecurityEvent::Progress(progress));
        worker.requests.available.notify_all();
    }
}

fn publish_provisional(
    worker: &L3WorkerState,
    request_id: RequestId,
    mut result: SecurityScanResult,
) {
    result.decision = None;
    let mut registry = worker
        .requests
        .state
        .lock()
        .expect("request registry mutex poisoned");
    if registry
        .requests
        .get(&request_id)
        .is_some_and(|state| state.completion.is_none())
    {
        registry
            .ready
            .push_back(QueuedSecurityEvent::Provisional(QueuedSecurityScanResult {
                request_id,
                result,
            }));
        worker.requests.available.notify_all();
    }
}

/// Publishes a provisional early result without marking a scanner job complete.
/// Dynamic PII uses this for a first-entity preview; consumers must wait for the
/// final result before treating it as an authoritative scan outcome.
fn publish_result_preview(
    worker: &L3WorkerState,
    request_id: RequestId,
    mut result: SecurityScanResult,
) {
    result.decision = None;
    let mut registry = worker
        .requests
        .state
        .lock()
        .expect("request registry mutex poisoned");
    if registry
        .requests
        .get(&request_id)
        .is_some_and(|state| state.completion.is_none())
    {
        registry
            .ready
            .push_back(QueuedSecurityEvent::Provisional(QueuedSecurityScanResult {
                request_id,
                result,
            }));
        worker.requests.available.notify_all();
    }
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
        if request.pending_dynamic_pii.is_none() {
            return;
        }
        let config = request
            .pending_dynamic_pii
            .as_ref()
            .and_then(|pending| pending.job.dynamic_pii_config.as_ref())
            .expect("pending dynamic-pii job is missing config");
        let dependencies = config.dependency_pipelines();
        if request
            .pending_l3_job_categories
            .values()
            .any(|pipeline| dependencies.contains(pipeline.as_str()))
        {
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
        match config.resolve(&request.gate_results, &request.gate_chunk_results) {
            Some(resolution) => {
                pending.job.dynamic_pii_inference_groups = resolution.inference_groups;
                pending.job.dynamic_pii_activated_rules = resolution.activated_conditional_rules;
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
            "timeout_reason",
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
    use crate::LayerResult;

    #[test]
    fn fair_scheduler_does_not_run_lower_priority_job_before_same_request_threat() {
        let jobs = vec![
            test_job("rq-a", "tool_class", 10, 1),
            test_job("rq-a", "threat", 2, 2),
        ];
        let mut scheduler = FairSchedulerState {
            deficits_ms: HashMap::from([("tool_class".to_string(), 10_000.0)]),
            observed_cost_ms: HashMap::from([("tool_class".to_string(), 1.0)]),
            cursor: Some("tool_class".to_string()),
        };

        let selected = select_fair_job(&jobs, &mut scheduler);

        assert_eq!(jobs[selected].request_id, "rq-a");
        assert_eq!(jobs[selected].category, "threat");
    }

    #[test]
    fn request_wide_early_exit_requires_confidence_threshold() {
        let mut result = test_result("injection", "attack", 0.62, "L3");
        assert_eq!(request_wide_early_exit(&result), None);

        result.confidence = 0.94;
        assert_eq!(
            request_wide_early_exit(&result),
            Some("injection:attack:0.9400".to_string())
        );
    }

    #[test]
    fn dynamic_pii_waits_for_final_l3_gate_and_discards_provisional_hr() {
        let requests = Arc::new(RequestRegistry::default());
        let worker = Arc::new(test_worker_state(Arc::clone(&requests)));
        let source_job_id = 1;
        let dynamic_job_id = 2;
        let mut dynamic = test_l3_spec(
            "rq-final-gate",
            "dynamic-pii",
            dynamic_job_id,
            ScanExecution::new(SecurityLevel::L3),
        );
        dynamic.text = Arc::<str>::from("Hey");
        dynamic.dynamic_pii_config = Some(
            DynamicPiiConfig {
                labels: vec!["person".to_string()],
                conditional_labels: vec![crate::DynamicPiiConditionalLabels {
                    labels: ["person", "employee_id"].map(String::from).to_vec(),
                    when: crate::DynamicPiiResultCondition {
                        pipeline: "sensitive_document".to_string(),
                        results: vec!["hr".to_string()],
                    },
                }],
                ..DynamicPiiConfig::default()
            }
            .validated()
            .unwrap(),
        );
        let provisional_range = DynamicPiiTextRange {
            start_byte: 0,
            end_byte: 3,
        };
        requests.state.lock().unwrap().requests.insert(
            "rq-final-gate".to_string(),
            RequestState {
                pending_l3_job_ids: HashSet::from([source_job_id, dynamic_job_id]),
                pending_l3_job_categories: HashMap::from([(
                    source_job_id,
                    "sensitive_document".to_string(),
                )]),
                gate_results: HashMap::from([(
                    "sensitive_document".to_string(),
                    vec!["hr".to_string()],
                )]),
                gate_chunk_results: HashMap::from([(
                    "sensitive_document".to_string(),
                    vec![DynamicPiiSourceChunk {
                        class_name: "hr".to_string(),
                        range: provisional_range,
                    }],
                )]),
                pending_dynamic_pii: Some(PendingDynamicPii { job: dynamic }),
                usable_results: 1,
                failures: Vec::new(),
                completion: None,
            },
        );

        resolve_dynamic_pii(&worker, "rq-final-gate");
        assert!(worker.jobs.lock().unwrap().is_empty());
        assert!(requests.state.lock().unwrap().requests["rq-final-gate"]
            .pending_dynamic_pii
            .is_some());

        let mut final_result = test_result("sensitive_document", "other", 0.94, "L3");
        final_result.internal_l2_chunk_outputs =
            vec![test_l2_chunk_output(0, 3, "sensitive_document", true)];
        final_result.internal_l2_chunk_outputs[0].class_name = "other".to_string();
        finish_job(
            &worker,
            source_job_id,
            "rq-final-gate".to_string(),
            final_result,
        );

        let registry = requests.state.lock().unwrap();
        let state = &registry.requests["rq-final-gate"];
        assert_eq!(state.gate_results["sensitive_document"], ["other"]);
        assert_eq!(
            state.gate_chunk_results["sensitive_document"],
            vec![DynamicPiiSourceChunk {
                class_name: "other".to_string(),
                range: provisional_range,
            }]
        );
        assert!(state.pending_dynamic_pii.is_none());
        drop(registry);
        let jobs = worker.jobs.lock().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].dynamic_pii_activated_rules, Vec::<usize>::new());
        assert_eq!(jobs[0].dynamic_pii_inference_groups.len(), 1);
        assert_eq!(
            jobs[0].dynamic_pii_inference_groups[0].config.labels,
            ["person"]
        );
    }

    #[test]
    fn preview_event_is_provisional_and_does_not_complete_the_request() {
        let requests = Arc::new(RequestRegistry::default());
        requests
            .state
            .lock()
            .unwrap()
            .requests
            .insert("rq-pii".to_string(), RequestState::running());
        let result = test_result("dynamic-pii", "entities", 0.91, "L3");

        publish_result_preview(
            &L3WorkerState {
                jobs: Mutex::new(Vec::new()),
                scheduler: Mutex::new(FairSchedulerState::default()),
                available: Condvar::new(),
                models: Mutex::new(HashMap::new()),
                dynamic_pii_models: Mutex::new(HashMap::new()),
                unified_model: Mutex::new(None),
                unified_runs: Mutex::new(HashMap::new()),
                unified_cache: Mutex::new(HashMap::new()),
                chunk_cache: Arc::new(DecisionCache::default()),
                exact_cache: Arc::new(
                    CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap(),
                ),
                pii_chunk_cache: Arc::new(PiiChunkCache::new(Arc::new(
                    CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap(),
                ))),
                similarity_cache: Arc::new(HistoricalSimilarityCache::new(Arc::new(
                    CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap(),
                ))),
                requests: Arc::clone(&requests),
                next_sequence: Mutex::new(0),
            },
            "rq-pii".to_string(),
            result,
        );

        // The preview is explicitly provisional; request accounting remains
        // untouched until the final L3 job finishes.
        let state = requests.state.lock().unwrap();
        assert!(matches!(
            state.ready.front(),
            Some(QueuedSecurityEvent::Provisional(_))
        ));
        assert_eq!(state.requests["rq-pii"].usable_results, 0);
        assert!(state.requests["rq-pii"].completion.is_none());
    }

    #[test]
    fn result_preview_event_strips_authoritative_decision() {
        let requests = Arc::new(RequestRegistry::default());
        requests
            .state
            .lock()
            .unwrap()
            .requests
            .insert("rq-preview".to_string(), RequestState::running());
        let mut result = test_result("dynamic-pii", "entities", 0.91, "L3");
        result.decision = Some(test_decision("dynamic-pii"));

        publish_result_preview(
            &test_worker_state(Arc::clone(&requests)),
            "rq-preview".to_string(),
            result,
        );

        let state = requests.state.lock().unwrap();
        let Some(QueuedSecurityEvent::Provisional(queued)) = state.ready.front() else {
            panic!("expected result preview event");
        };
        assert!(queued.result.decision.is_none());
    }

    #[test]
    fn provisional_event_strips_authoritative_decision() {
        let requests = Arc::new(RequestRegistry::default());
        requests
            .state
            .lock()
            .unwrap()
            .requests
            .insert("rq-provisional".to_string(), RequestState::running());
        let mut result = test_result("injection", "attack", 0.91, "L3");
        result.decision = Some(test_decision("injection"));

        publish_provisional(
            &test_worker_state(Arc::clone(&requests)),
            "rq-provisional".to_string(),
            result,
        );

        let state = requests.state.lock().unwrap();
        let Some(QueuedSecurityEvent::Provisional(queued)) = state.ready.front() else {
            panic!("expected provisional event");
        };
        assert!(queued.result.decision.is_none());
    }

    #[test]
    fn stop_models_preserves_registered_l3_model_metadata() {
        let worker = L3Worker {
            state: Arc::new(test_worker_state(Arc::new(RequestRegistry::default()))),
        };
        let model_dir = fake_lazy_onnx_dir("stop-models-preserves-registered-l3-model-metadata");
        let classifier = LazyOnnxTextClassifier::from_dir_with_paths(
            &model_dir,
            vec!["benign".to_string(), "attack".to_string()],
            "fake-l3",
            &["onnx/model.onnx"],
            "tokenizer.json",
            16,
        )
        .unwrap()
        .expect("fake L3 metadata should be registered");
        worker.register_model("fake-l3", classifier);

        assert!(worker.has_model("fake-l3"));

        worker.stop_models();
        worker.stop_models();

        assert!(worker.has_model("fake-l3"));
        let _ = std::fs::remove_dir_all(model_dir);
    }

    #[test]
    fn token_pipeline_e2e_preserves_v4_chunks_through_promotion_and_l3_inputs() {
        use crate::ml::{
            ntdb_executor::token_outputs_for_test,
            tokenizer::{fixture_tokenizer, CONTENT_TOKENS, MODEL_TOKENS, TEXT_WINDOW_BYTES},
        };
        let tokenizer = fixture_tokenizer();
        let mut cases = [0, 1, 253, 254, 255, 256, 257, 508, 509]
            .into_iter()
            .map(|count| " a".repeat(count))
            .collect::<Vec<_>>();
        cases.extend([
            "é🙂界 a   <mask>a".repeat(100),
            " a".repeat(TEXT_WINDOW_BYTES + 1),
            "   ".to_string(),
        ]);
        for text in cases {
            tokenizer.0.encoded_windows.lock().unwrap().clear();
            let l2_chunks = tokenizer.token_chunks(&text);
            let promote = vec![true; l2_chunks.len()];
            let l2 = token_outputs_for_test(l2_chunks.clone(), &promote);
            let mut spec = test_l3_spec(
                "token-e2e",
                "injection",
                1,
                ScanExecution::new(SecurityLevel::L3),
            );
            spec.text = Arc::from(text.as_str());
            spec.l3_candidates = l2.l3_candidates;
            // Multi-head requests may carry the same L2 chunk more than once.
            spec.l2_chunk_outputs = l2
                .l2_chunk_outputs
                .iter()
                .cloned()
                .chain(l2.l2_chunk_outputs.iter().cloned())
                .collect::<Vec<_>>()
                .into();
            let worker = L3Worker {
                state: Arc::new(test_worker_state(Arc::new(RequestRegistry::default()))),
            };
            let job = worker.build_physical_job(spec, None, None).unwrap();
            let L3WorkerInput::PlannedChunks(mut l3_chunks) = job.input else {
                panic!("expected planned tokens");
            };
            l3_chunks.sort_by_key(|chunk| chunk.source_order);
            assert_eq!(l3_chunks.len(), l2_chunks.len());
            for (l2, l3) in l2_chunks.iter().zip(l3_chunks) {
                assert_eq!(l3.token_ids, l2.token_ids);
                assert_eq!((l3.start_byte, l3.end_byte), l2.byte_span);
                assert_eq!(l3.text, text[l2.byte_span.0..l2.byte_span.1]);
                assert!(l3.token_ids.len() <= CONTENT_TOKENS);
                let (ids, mask, _) = tokenizer.inputs(&l3.token_ids).unwrap();
                assert_eq!(ids.len(), MODEL_TOKENS);
                assert_eq!(ids[0], 1);
                assert_eq!(ids[l2.token_ids.len() + 1], 2);
                assert_eq!(
                    &ids[1..l2.token_ids.len() + 1],
                    l2.token_ids
                        .iter()
                        .copied()
                        .map(i64::from)
                        .collect::<Vec<_>>()
                );
                assert_eq!(mask.iter().sum::<i64>() as usize, l2.token_ids.len() + 2);
            }
            let calls = tokenizer.0.encoded_windows.lock().unwrap();
            assert_eq!(calls.iter().sum::<usize>(), text.len());
            assert!(calls.iter().all(|bytes| *bytes <= TEXT_WINDOW_BYTES));
        }
    }

    #[test]
    fn token_pipeline_e2e_promotes_only_the_original_selected_chunk() {
        use crate::ml::{ntdb_executor::token_outputs_for_test, tokenizer::fixture_tokenizer};
        let tokenizer = fixture_tokenizer();
        for text in [" a".repeat(254 * 3), "🙂".repeat(200)] {
            tokenizer.0.encoded_windows.lock().unwrap().clear();
            let chunks = tokenizer.token_chunks(&text);
            let l2 = token_outputs_for_test(
                chunks.clone(),
                &(0..chunks.len())
                    .map(|index| index == 1)
                    .collect::<Vec<_>>(),
            );
            let mut spec = test_l3_spec(
                "selected-token-e2e",
                "injection",
                1,
                ScanExecution::new(SecurityLevel::L3),
            );
            spec.text = Arc::from(text);
            spec.l3_candidates = l2.l3_candidates;
            spec.l2_chunk_outputs = l2.l2_chunk_outputs.into();
            let worker = L3Worker {
                state: Arc::new(test_worker_state(Arc::new(RequestRegistry::default()))),
            };
            let job = worker.build_physical_job(spec, None, None).unwrap();
            let L3WorkerInput::PlannedChunks(selected) = job.input else {
                panic!("expected token chunks");
            };
            assert_eq!(selected.len(), 1);
            assert_eq!(selected[0].token_ids, chunks[1].token_ids);
            assert_eq!(
                (selected[0].start_byte, selected[0].end_byte),
                chunks[1].byte_span
            );
            assert_eq!(tokenizer.0.encoded_windows.lock().unwrap().len(), 1);
        }
    }

    #[test]
    fn physical_l3_job_uses_l2_chunk_spans_without_full_text_tokenization() {
        let worker = L3Worker {
            state: Arc::new(test_worker_state(Arc::new(RequestRegistry::default()))),
        };
        let mut spec = test_l3_spec(
            "rq-chunks",
            "threat",
            1,
            ScanExecution::new(SecurityLevel::L3),
        );
        spec.text = Arc::<str>::from("safe prefix ATTACK_CHUNK safe suffix");
        let mut l2_output = test_l2_chunk_output(12, 24, "threat", true);
        l2_output.token_ids = vec![42];
        l2_output.tokenizer_family = "mmbert".to_string();
        spec.l2_chunk_outputs = vec![l2_output].into();
        spec.l3_candidates = vec![test_l3_candidate(12, 24, "threat")];

        let job = worker
            .build_physical_job(spec, None, None)
            .expect("L2 chunk spans should avoid model-backed full-text tokenization");

        let L3WorkerInput::PlannedChunks(chunks) = job.input else {
            panic!("normal L3 jobs should queue planned chunks, not source text");
        };
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].text, "ATTACK_CHUNK");
        assert_eq!(chunks[0].start_byte, 12);
        assert_eq!(chunks[0].end_byte, 24);
        assert_eq!(chunks[0].token_ids, [42]);
    }

    #[test]
    fn invalid_l2_token_handoff_is_rejected_without_retokenizing() {
        for (token_ids, tokenizer_family) in [
            (Vec::new(), "mmbert"),
            (vec![1; L3_DIRECT_CONTENT_TOKEN_LIMIT + 1], "mmbert"),
            (vec![1], "modernbert"),
        ] {
            let mut spec = test_l3_spec(
                "rq-invalid-handoff",
                "threat",
                1,
                ScanExecution::new(SecurityLevel::L3),
            );
            let mut output = test_l2_chunk_output(0, 4, "threat", true);
            output.token_ids = token_ids;
            output.tokenizer_family = tokenizer_family.to_string();
            spec.l2_chunk_outputs = vec![output].into();

            assert!(token_chunks_from_l2_outputs(&spec).is_err());
        }
    }

    #[test]
    fn malformed_token_handoffs_report_errors_without_model_loading() {
        let mut spec = test_l3_spec(
            "malformed-token-e2e",
            "injection",
            1,
            ScanExecution::new(SecurityLevel::L3),
        );
        assert!(token_chunks_from_l2_outputs(&spec).is_err());
        spec.text = Arc::from("é🙂");
        for (start, end) in [(1, 2), (0, 99), (4, 2)] {
            let mut output = test_l2_chunk_output(start, end, "injection", true);
            output.token_ids = vec![1];
            output.tokenizer_family = "mmbert".to_string();
            spec.l2_chunk_outputs = vec![output].into();
            assert!(token_chunks_from_l2_outputs(&spec).is_err());
        }
        let mut first = test_l2_chunk_output(0, 2, "injection", true);
        first.token_ids = vec![1];
        first.tokenizer_family = "mmbert".to_string();
        let mut conflicting = first.clone();
        conflicting.token_ids = vec![2];
        spec.l2_chunk_outputs = vec![first, conflicting].into();
        assert!(token_chunks_from_l2_outputs(&spec)
            .err()
            .unwrap()
            .contains("conflicting L2 token IDs"));
    }

    #[test]
    fn incompatible_duplicate_l2_handoff_is_rejected() {
        let mut spec = test_l3_spec(
            "rq-compatible-handoff",
            "threat",
            1,
            ScanExecution::new(SecurityLevel::L3),
        );
        let incompatible = test_l2_chunk_output(0, 4, "threat", true);
        let mut compatible = test_l2_chunk_output(0, 4, "injection", true);
        compatible.token_ids = vec![7, 8];
        compatible.tokenizer_family = "mmbert".to_string();
        spec.l2_chunk_outputs = vec![incompatible, compatible].into();

        assert!(token_chunks_from_l2_outputs(&spec).is_err());
    }

    #[test]
    fn expired_unified_physical_job_finishes_all_subscribers() {
        let requests = Arc::new(RequestRegistry::default());
        let state = Arc::new(test_worker_state(Arc::clone(&requests)));
        let worker = L3Worker {
            state: Arc::clone(&state),
        };
        requests.state.lock().unwrap().requests.insert(
            "rq-unified".to_string(),
            RequestState {
                pending_l3_job_ids: HashSet::from([1, 2]),
                pending_l3_job_categories: HashMap::from([
                    (1, "injection".to_string()),
                    (2, "threat".to_string()),
                ]),
                gate_results: HashMap::new(),
                gate_chunk_results: HashMap::new(),
                pending_dynamic_pii: None,
                usable_results: 1,
                failures: Vec::new(),
                completion: None,
            },
        );
        let mut execution = ScanExecution::new(SecurityLevel::L3);
        execution.set_l3_strategy(L3Strategy::Multi);
        let candidates = vec![
            test_l3_candidate(0, 4, "injection"),
            test_l3_candidate(0, 4, "threat"),
        ];
        let chunk_outputs = vec![
            {
                let mut output = test_l2_chunk_output(0, 4, "injection", true);
                output.token_ids = vec![1, 2, 3];
                output.tokenizer_family = "mmbert".to_string();
                output
            },
            {
                let mut output = test_l2_chunk_output(0, 4, "threat", true);
                output.token_ids = vec![1, 2, 3];
                output.tokenizer_family = "mmbert".to_string();
                output
            },
        ];
        let mut injection = test_l3_spec("rq-unified", "injection", 1, execution.clone());
        injection.l3_candidates = candidates.clone();
        injection.l2_chunk_outputs = chunk_outputs.clone().into();
        let mut threat = test_l3_spec("rq-unified", "threat", 2, execution);
        threat.l3_candidates = candidates;
        threat.l2_chunk_outputs = chunk_outputs.into();

        worker.enqueue(injection);
        worker.enqueue(threat);
        let physical = state.jobs.lock().unwrap().pop().unwrap();

        finish_expired_job(&state, physical);

        let registry = requests.state.lock().unwrap();
        let completion = registry.requests["rq-unified"]
            .completion
            .as_ref()
            .expect("unified subscribers should finish together");
        let SecurityRequestCompletion::Degraded { failures } = completion else {
            panic!("expired unified run should degrade the request");
        };
        assert_eq!(failures.len(), 2);
        assert!(failures
            .iter()
            .all(|failure| failure.message == "expired_before_inference"));
    }

    fn test_worker_state(requests: Arc<RequestRegistry>) -> L3WorkerState {
        L3WorkerState {
            jobs: Mutex::new(Vec::new()),
            scheduler: Mutex::new(FairSchedulerState::default()),
            available: Condvar::new(),
            models: Mutex::new(HashMap::new()),
            dynamic_pii_models: Mutex::new(HashMap::new()),
            unified_model: Mutex::new(None),
            unified_runs: Mutex::new(HashMap::new()),
            unified_cache: Mutex::new(HashMap::new()),
            chunk_cache: Arc::new(DecisionCache::default()),
            exact_cache: Arc::new(
                CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap(),
            ),
            pii_chunk_cache: Arc::new(PiiChunkCache::new(Arc::new(
                CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap(),
            ))),
            similarity_cache: Arc::new(HistoricalSimilarityCache::new(Arc::new(
                CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap(),
            ))),
            requests,
            next_sequence: Mutex::new(0),
        }
    }

    fn fake_lazy_onnx_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("patronus-ark-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("onnx")).unwrap();
        std::fs::write(dir.join("tokenizer.json"), "{}").unwrap();
        std::fs::write(dir.join("onnx/model.onnx"), []).unwrap();
        dir
    }

    fn test_l3_spec(
        request_id: &str,
        category: &str,
        job_id: u64,
        execution: ScanExecution,
    ) -> L3JobSpec {
        L3JobSpec {
            job_id,
            request_id: request_id.to_string(),
            category: category.to_string(),
            model: category.to_string(),
            text: Arc::<str>::from("test"),
            fallback: test_result(category, "benign", 0.5, "L2"),
            priority: 0,
            ttl_ms: 1,
            inference_timeout_ms: 1,
            execution,
            degraded_factor: 0.75,
            l3_candidates: vec![test_l3_candidate(0, 4, category)],
            l2_chunk_outputs: vec![test_l2_chunk_output(0, 4, category, true)].into(),
            dynamic_pii_config: None,
            dynamic_pii_inference_groups: Vec::new(),
            dynamic_pii_activated_rules: Vec::new(),
        }
    }

    fn test_l3_candidate(
        start: usize,
        end: usize,
        source_pipeline: &str,
    ) -> crate::ml::ntdb_executor::L3Candidate {
        crate::ml::ntdb_executor::L3Candidate {
            span: crate::ml::ntdb_executor::ByteSpan { start, end },
            promote_score: 0.9,
            promote_threshold: 0.7,
            source_pipeline: source_pipeline.to_string(),
            source_model: source_pipeline.to_string(),
            l2_class: "attack".to_string(),
        }
    }

    #[test]
    fn final_l3_ranges_preserve_overlapping_labels_and_l2_remainders() {
        use crate::ml::ntdb_executor::ByteSpan;
        let l2 = [
            test_l2_chunk_output(0, 120, "sensitive_document", true),
            test_l2_chunk_output(0, 120, "injection", true),
        ];
        let mut l3 = vec![
            (ByteSpan { start: 20, end: 70 }, "hr".to_string(), 0.8),
            (
                ByteSpan {
                    start: 60,
                    end: 100,
                },
                "other".to_string(),
                0.9,
            ),
            (ByteSpan { start: 20, end: 70 }, "hr".to_string(), 0.95),
            (ByteSpan { start: 20, end: 70 }, "finance".to_string(), 0.85),
        ];
        let summarize = |outputs: Vec<L2ChunkOutput>| {
            outputs
                .into_iter()
                .map(|output| {
                    (
                        output.span.start,
                        output.span.end,
                        output.class_name,
                        output.confidence,
                    )
                })
                .collect::<Vec<_>>()
        };
        let actual = summarize(final_l3_chunk_outputs(&l2, "sensitive_document", "l3", &l3));
        l3.reverse();
        assert_eq!(
            actual,
            summarize(final_l3_chunk_outputs(&l2, "sensitive_document", "l3", &l3))
        );
        assert_eq!(
            actual,
            vec![
                (0, 20, "attack".into(), 0.9),
                (20, 70, "finance".into(), 0.85),
                (20, 70, "hr".into(), 0.95),
                (60, 100, "other".into(), 0.9),
                (100, 120, "attack".into(), 0.9),
            ]
        );
    }

    fn test_l2_chunk_output(
        start: usize,
        end: usize,
        source_pipeline: &str,
        promoted: bool,
    ) -> crate::ml::ntdb_executor::L2ChunkOutput {
        crate::ml::ntdb_executor::L2ChunkOutput {
            span: crate::ml::ntdb_executor::ByteSpan { start, end },
            class_name: "attack".to_string(),
            confidence: 0.9,
            promoted,
            promote_score: Some(0.9),
            promote_threshold: Some(0.7),
            source_pipeline: source_pipeline.to_string(),
            source_model: source_pipeline.to_string(),
            embedding: Vec::new(),
            embedding_space: String::new(),
            token_ids: Vec::new(),
            tokenizer_family: String::new(),
            class_probabilities: Vec::new(),
            joint_v3_decision: None,
        }
    }

    fn test_decision(model: &str) -> crate::DecisionEnvelope {
        crate::DecisionEnvelope {
            schema_version: "ark.decision.v1".to_string(),
            final_result: crate::DecisionResult {
                class_name: "attack".to_string(),
                confidence: 0.91,
                source: "l3".to_string(),
            },
            decision_candidate: None,
            recommendation: crate::DecisionRecommendation {
                accepted: true,
                final_arbitration: "l3".to_string(),
                operating_point: "best_f1".to_string(),
                acceptance_threshold: None,
            },
            candidates: Vec::new(),
            terminality: crate::DecisionTerminality {
                completion: "complete".to_string(),
                degraded: false,
                degradation_reason: None,
            },
            provenance: crate::DecisionProvenance {
                ark_version: "test".to_string(),
                schema_version: "ark.decision.v1".to_string(),
                model: model.to_string(),
            },
        }
    }

    fn test_job(request_id: &str, category: &str, priority: usize, sequence: u64) -> L3WorkerJob {
        L3WorkerJob {
            job_id: sequence,
            request_id: request_id.to_string(),
            category: category.to_string(),
            model: category.to_string(),
            input: L3WorkerInput::Text(Arc::<str>::from("test")),
            fallback: SecurityScanResult {
                category: category.to_string(),
                class_name: "benign".to_string(),
                confidence: 0.5,
                level: "L2".to_string(),
                model: category.to_string(),
                duration_ms: 0.0,
                layers: vec![LayerResult {
                    level: "L2".to_string(),
                    layer_type: "test".to_string(),
                    class_name: "benign".to_string(),
                    confidence: 0.5,
                    matched: false,
                    duration_ms: 0.0,
                    thresholds: HashMap::new(),
                    details: HashMap::new(),
                }],
                internal_l2_chunk_outputs: Vec::new(),
                evidence_spans: Vec::new(),
                label_scores: Vec::new(),
                decision: None,
            },
            priority,
            ttl_ms: 10_000,
            inference_timeout_ms: 10_000,
            estimated_cost_ms: 100,
            fairness_quantum_ms: 50,
            max_wait_ms: 2_000,
            enqueued_at: Instant::now(),
            execution: ScanExecution::new(SecurityLevel::L3),
            unified_run_key: None,
            unified_cache_key: None,
            degraded_factor: 0.75,
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new().into(),
            dynamic_pii_config: None,
            dynamic_pii_inference_groups: Vec::new(),
            dynamic_pii_activated_rules: Vec::new(),
            sequence,
            #[cfg(feature = "test-util")]
            test_delay_ms: None,
        }
    }

    fn test_result(
        category: &str,
        class_name: &str,
        confidence: f64,
        level: &str,
    ) -> SecurityScanResult {
        SecurityScanResult {
            category: category.to_string(),
            class_name: class_name.to_string(),
            confidence,
            level: level.to_string(),
            model: category.to_string(),
            duration_ms: 0.0,
            layers: Vec::new(),
            internal_l2_chunk_outputs: Vec::new(),
            evidence_spans: Vec::new(),
            label_scores: Vec::new(),
            decision: None,
        }
    }
}
