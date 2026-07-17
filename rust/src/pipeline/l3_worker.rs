// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::ml::dynamic_pii::DynamicPiiRuntime;
use crate::ml::ntdb_executor::ByteSpan;
use crate::ml::onnx::LazyOnnxTextClassifier;
use crate::ml::unified_onnx::{LazyUnifiedOnnxClassifier, UNIFIED_MODEL};
use crate::{
    DynamicPiiConfig, L3Strategy, QueuedSecurityEvent, QueuedSecurityScanResult, RequestId,
    ScanExecution, SecurityFailure, SecurityFailureKind, SecurityFailureStage, SecurityLevel,
    SecurityRequestCompletion, SecurityScanResult,
};

use super::decision_cache::DecisionCache;
use super::l3_routing::estimated_cost_ms;

mod dedicated;
mod unified;

#[cfg(feature = "test-util")]
pub use dedicated::selected_l3_chunks_for_test;
#[cfg(feature = "test-util")]
pub use unified::{
    aggregate_unified_head_for_test, public_unified_class_for_test, unified_coalescing_snapshot,
    UnifiedCoalescingSnapshot,
};

type L3ModelHandle = Arc<Mutex<LazyOnnxTextClassifier>>;
type DynamicPiiHandle = Arc<Mutex<DynamicPiiRuntime>>;
type UnifiedModelHandle = Arc<Mutex<LazyUnifiedOnnxClassifier>>;
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
    unified_model: Mutex<Option<UnifiedModelHandle>>,
    unified_runs: Mutex<HashMap<String, unified::UnifiedRunState>>,
    unified_cache: Mutex<HashMap<String, unified::UnifiedCacheEntry>>,
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
            unified_model: Mutex::new(None),
            unified_runs: Mutex::new(HashMap::new()),
            unified_cache: Mutex::new(HashMap::new()),
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
    unified::sweep_expired(state);
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
