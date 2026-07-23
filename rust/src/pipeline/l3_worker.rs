// SPDX-License-Identifier: GPL-3.0-only
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::cache::{
    CacheCoordinator, CacheError, ExactCacheConfig, HistoricalSimilarityCache, PiiChunkCache,
    PiiEntityCache,
};
use crate::ml::dynamic_pii::DynamicPiiRuntime;
use crate::ml::ntdb_executor::{L2ChunkOutput, L3Candidate};
use crate::ml::onnx::LazyOnnxTextClassifier;
use crate::ml::unified_onnx::{LazyUnifiedOnnxClassifier, UNIFIED_MODEL};
use crate::{
    DynamicPiiConfig, L3Strategy, QueuedSecurityEvent, QueuedSecurityProgress,
    QueuedSecurityScanResult, RequestId, ScanExecution, SecurityFailure, SecurityFailureKind,
    SecurityFailureStage, SecurityLevel, SecurityRequestCompletion, SecurityScanResult,
};

use super::decision_cache::DecisionCache;
use super::l3_routing::estimated_cost_ms;

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
const L3_OVERLAP_TOKENS: usize = 32;
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
    unified_model: Mutex<Option<UnifiedModelHandle>>,
    unified_runs: Mutex<HashMap<String, unified::UnifiedRunState>>,
    unified_cache: Mutex<HashMap<String, unified::UnifiedCacheEntry>>,
    chunk_cache: Arc<DecisionCache>,
    exact_cache: Arc<CacheCoordinator>,
    pii_entity_cache: Arc<PiiEntityCache>,
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
    text: String,
    fallback: SecurityScanResult,
    priority: usize,
    ttl_ms: u64,
    inference_timeout_ms: u64,
    estimated_cost_ms: u64,
    fairness_quantum_ms: u64,
    max_wait_ms: u64,
    enqueued_at: Instant,
    execution: ScanExecution,
    degraded_factor: f64,
    l3_candidates: Vec<L3Candidate>,
    l2_chunk_outputs: Vec<L2ChunkOutput>,
    dynamic_pii_config: Option<DynamicPiiConfig>,
    dynamic_pii_activated_rules: Vec<usize>,
    sequence: u64,
    #[cfg(feature = "test-util")]
    test_delay_ms: Option<u64>,
}

#[derive(Clone)]
pub(crate) struct L3JobSpec {
    pub job_id: u64,
    pub request_id: RequestId,
    pub category: String,
    pub model: String,
    pub text: String,
    pub fallback: SecurityScanResult,
    pub priority: usize,
    pub ttl_ms: u64,
    pub inference_timeout_ms: u64,
    pub execution: ScanExecution,
    pub degraded_factor: f64,
    pub l3_candidates: Vec<L3Candidate>,
    pub l2_chunk_outputs: Vec<L2ChunkOutput>,
    pub dynamic_pii_config: Option<DynamicPiiConfig>,
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
        let pii_entity_cache = Arc::new(PiiEntityCache::new(Arc::clone(&exact_cache)));
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
            pii_entity_cache,
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
            inference_timeout_ms: spec.inference_timeout_ms,
            estimated_cost_ms,
            fairness_quantum_ms,
            max_wait_ms,
            enqueued_at: Instant::now(),
            execution: spec.execution,
            degraded_factor: spec.degraded_factor,
            l3_candidates: spec.l3_candidates,
            l2_chunk_outputs: spec.l2_chunk_outputs,
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
                text: spec.text,
                fallback: spec.fallback,
                priority: spec.priority,
                ttl_ms: spec.ttl_ms,
                inference_timeout_ms: spec.inference_timeout_ms,
                estimated_cost_ms,
                fairness_quantum_ms,
                max_wait_ms,
                enqueued_at: Instant::now(),
                execution: spec.execution,
                degraded_factor: spec.degraded_factor,
                l3_candidates: spec.l3_candidates,
                l2_chunk_outputs: spec.l2_chunk_outputs,
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

fn publish_provisional(worker: &L3WorkerState, request_id: RequestId, result: SecurityScanResult) {
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

/// Publishes an early result-shaped event without marking a scanner job
/// complete. Used by Dynamic PII so UI consumers can react to the first entity.
fn publish_result_preview(
    worker: &L3WorkerState,
    request_id: RequestId,
    result: SecurityScanResult,
) {
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
            .push_back(QueuedSecurityEvent::Result(QueuedSecurityScanResult {
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
        match config.resolve(&request.gate_results) {
            Some(resolution) => {
                pending.job.dynamic_pii_config = Some(resolution.config);
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
    fn partial_result_event_does_not_complete_or_count_the_request() {
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
                pii_entity_cache: Arc::new(PiiEntityCache::new(Arc::new(
                    CacheCoordinator::from_config(ExactCacheConfig::default()).unwrap(),
                ))),
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

        // The preview is externally a Result event, but request accounting
        // remains untouched until the final L3 job finishes.
        let state = requests.state.lock().unwrap();
        assert!(matches!(
            state.ready.front(),
            Some(QueuedSecurityEvent::Result(_))
        ));
        assert_eq!(state.requests["rq-pii"].usable_results, 0);
        assert!(state.requests["rq-pii"].completion.is_none());
    }

    fn test_job(request_id: &str, category: &str, priority: usize, sequence: u64) -> L3WorkerJob {
        L3WorkerJob {
            job_id: sequence,
            request_id: request_id.to_string(),
            category: category.to_string(),
            model: category.to_string(),
            text: "test".to_string(),
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
                evidence_spans: Vec::new(),
                label_scores: Vec::new(),
            },
            priority,
            ttl_ms: 10_000,
            inference_timeout_ms: 10_000,
            estimated_cost_ms: 100,
            fairness_quantum_ms: 50,
            max_wait_ms: 2_000,
            enqueued_at: Instant::now(),
            execution: ScanExecution::new(SecurityLevel::L3),
            degraded_factor: 0.75,
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
            dynamic_pii_config: None,
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
            evidence_spans: Vec::new(),
            label_scores: Vec::new(),
        }
    }
}
