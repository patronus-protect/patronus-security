// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;
use std::sync::{mpsc, Arc};
#[cfg(feature = "test-util")]
use std::sync::{Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::ml::unified_onnx::{
    UnifiedHeadOutput, UnifiedModelOutput, UNIFIED_MODEL, UNIFIED_REVISION,
};
#[cfg(feature = "test-util")]
use crate::{L3Strategy, ScanExecution};
use crate::{SecurityLevel, SecurityScanResult};

#[cfg(feature = "test-util")]
use super::super::decision_cache::DecisionCache;
use super::super::l3_routing::{priority_index, ttl_ms};
use super::super::{degraded_error_result, degraded_timeout_result, l3_metadata_layer};
use super::{
    elapsed_ms, finish_job, L3JobSpec, L3Worker, L3WorkerJob, L3WorkerState, UnifiedModelHandle,
    L3_OVERLAP_TOKENS,
};
#[cfg(feature = "test-util")]
use super::{FairSchedulerState, RequestRegistry};

pub(super) enum UnifiedRunState {
    Running { subscribers: Vec<L3JobSpec> },
    Completed(UnifiedRunResult),
    Failed(UnifiedRunFailure),
}

#[derive(Clone)]
pub(super) struct UnifiedRunResult {
    output: UnifiedModelOutput,
    duration_ms: f64,
    queue_wait_ms: f64,
    chunk_count: usize,
    physical_job_id: u64,
}

#[derive(Clone)]
pub(super) enum UnifiedRunFailure {
    Timeout {
        queued_ms: f64,
        ttl_ms: u64,
    },
    Error {
        queued_ms: f64,
        ttl_ms: u64,
        error: String,
    },
}

#[derive(Clone)]
pub(super) struct UnifiedCacheEntry {
    result: UnifiedRunResult,
    expires_at: Instant,
}

pub(super) fn enqueue(worker: &L3Worker, spec: L3JobSpec) {
    let run_key = unified_run_key(&spec);
    let cache_key = unified_cache_key(&spec);
    if let Some(result) = cached_unified_result(&worker.state, &cache_key) {
        worker
            .state
            .unified_runs
            .lock()
            .expect("unified run mutex poisoned")
            .insert(run_key, UnifiedRunState::Completed(result.clone()));
        let output = materialize_unified_result(&spec, &result);
        finish_job(&worker.state, spec.job_id, spec.request_id.clone(), output);
        return;
    }

    let mut runs = worker
        .state
        .unified_runs
        .lock()
        .expect("unified run mutex poisoned");
    match runs.get_mut(&run_key) {
        Some(UnifiedRunState::Running { subscribers }) => {
            subscribers.push(spec);
            return;
        }
        Some(UnifiedRunState::Completed(result)) => {
            let result = result.clone();
            drop(runs);
            let output = materialize_unified_result(&spec, &result);
            finish_job(&worker.state, spec.job_id, spec.request_id.clone(), output);
            return;
        }
        Some(UnifiedRunState::Failed(failure)) => {
            let failure = failure.clone();
            drop(runs);
            let output = materialize_unified_failure(&spec, &failure);
            finish_job(&worker.state, spec.job_id, spec.request_id.clone(), output);
            return;
        }
        None => {
            runs.insert(
                run_key,
                UnifiedRunState::Running {
                    subscribers: vec![spec.clone()],
                },
            );
        }
    }
    drop(runs);

    let mut physical = spec;
    physical.category = UNIFIED_MODEL.to_string();
    physical.model = UNIFIED_MODEL.to_string();
    physical.priority =
        priority_index(physical.execution.l3_policy(), UNIFIED_MODEL, UNIFIED_MODEL);
    physical.ttl_ms = ttl_ms(physical.execution.l3_policy(), UNIFIED_MODEL, UNIFIED_MODEL);
    physical.l3_candidate_spans.clear();
    worker.enqueue_physical(physical);
}

pub(super) fn remove_request(state: &L3WorkerState, request_id: &str) {
    let prefix = format!("{request_id}:");
    state
        .unified_runs
        .lock()
        .expect("unified run mutex poisoned")
        .retain(|key, _| !key.starts_with(&prefix));
}

pub(super) fn sweep_expired(state: &L3WorkerState) {
    if let Ok(model) = state.unified_model.try_lock() {
        if let Some(model) = model.as_ref() {
            if let Ok(mut model) = model.try_lock() {
                model.evict_expired();
            }
        }
    }
    if let Ok(mut cache) = state.unified_cache.try_lock() {
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
    }
}

pub(super) fn execute(state: &L3WorkerState, job: L3WorkerJob) -> UnifiedRunOutcome {
    let queued_ms = elapsed_ms(job.enqueued_at);
    if queued_ms >= job.ttl_ms as f64 {
        return UnifiedRunOutcome::Failed(UnifiedRunFailure::Timeout {
            queued_ms,
            ttl_ms: job.ttl_ms,
        });
    }
    let model = state
        .unified_model
        .lock()
        .expect("unified model registry mutex poisoned")
        .clone();
    let Some(model) = model else {
        return UnifiedRunOutcome::Failed(UnifiedRunFailure::Error {
            queued_ms,
            ttl_ms: job.ttl_ms,
            error: "unified L3 model is not registered".to_string(),
        });
    };
    let remaining = Duration::from_millis(job.ttl_ms).saturating_sub(job.enqueued_at.elapsed());
    let (tx, rx) = mpsc::channel();
    let thread_job = job.clone();
    thread::spawn(move || {
        let _ = tx.send(run_unified_model_job(&thread_job, model));
    });
    match rx.recv_timeout(remaining) {
        Ok(Ok(result)) => UnifiedRunOutcome::Completed(result),
        Ok(Err(error)) => UnifiedRunOutcome::Failed(UnifiedRunFailure::Error {
            queued_ms: elapsed_ms(job.enqueued_at),
            ttl_ms: job.ttl_ms,
            error,
        }),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            UnifiedRunOutcome::Failed(UnifiedRunFailure::Timeout {
                queued_ms: elapsed_ms(job.enqueued_at),
                ttl_ms: job.ttl_ms,
            })
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            UnifiedRunOutcome::Failed(UnifiedRunFailure::Error {
                queued_ms: elapsed_ms(job.enqueued_at),
                ttl_ms: job.ttl_ms,
                error: "unified L3 inference thread terminated without a result".to_string(),
            })
        }
    }
}

pub(super) enum UnifiedRunOutcome {
    Completed(UnifiedRunResult),
    Failed(UnifiedRunFailure),
}

fn run_unified_model_job(
    job: &L3WorkerJob,
    model: UnifiedModelHandle,
) -> Result<UnifiedRunResult, String> {
    let queue_wait_ms = elapsed_ms(job.enqueued_at);
    let started = Instant::now();
    let chunks = model
        .lock()
        .map_err(|error| format!("unified L3 model mutex poisoned: {error}"))?
        .token_chunks(&job.text, L3_OVERLAP_TOKENS, job.execution.backend())
        .map_err(|error| error.to_string())?;
    let texts = chunks
        .iter()
        .map(|chunk| chunk.text.clone())
        .collect::<Vec<_>>();
    let outputs = model
        .lock()
        .map_err(|error| format!("unified L3 model mutex poisoned: {error}"))?
        .infer_batch(&texts, job.execution.backend())
        .map_err(|error| error.to_string())?;
    let chunk_count = outputs.len();
    Ok(UnifiedRunResult {
        output: aggregate_unified_outputs(outputs)?,
        duration_ms: started.elapsed().as_secs_f64() * 1_000.0,
        queue_wait_ms,
        chunk_count,
        physical_job_id: job.job_id,
    })
}

fn aggregate_unified_outputs(
    outputs: Vec<UnifiedModelOutput>,
) -> Result<UnifiedModelOutput, String> {
    let first = outputs
        .first()
        .ok_or_else(|| "unified L3 produced no chunk output".to_string())?;
    let mut heads = HashMap::new();
    for head in first.heads.keys() {
        let candidates = outputs
            .iter()
            .filter_map(|output| output.heads.get(head))
            .collect::<Vec<_>>();
        let selected = aggregate_unified_head(head, &candidates)
            .ok_or_else(|| format!("unified L3 head '{head}' produced no output"))?;
        heads.insert(head.clone(), selected);
    }
    Ok(UnifiedModelOutput { heads })
}

fn aggregate_unified_head(
    head: &str,
    candidates: &[&UnifiedHeadOutput],
) -> Option<UnifiedHeadOutput> {
    if head == "tool_tags" {
        let labels = candidates
            .first()?
            .label_scores
            .iter()
            .map(|score| score.label.clone())
            .collect::<Vec<_>>();
        let label_scores = labels
            .iter()
            .map(|label| {
                candidates
                    .iter()
                    .filter_map(|output| {
                        output
                            .label_scores
                            .iter()
                            .find(|score| &score.label == label)
                    })
                    .max_by(|left, right| left.confidence.total_cmp(&right.confidence))
                    .cloned()
            })
            .collect::<Option<Vec<_>>>()?;
        let matched = label_scores
            .iter()
            .filter(|score| score.matched)
            .map(|score| score.label.as_str())
            .collect::<Vec<_>>();
        return Some(UnifiedHeadOutput {
            class_name: if matched.is_empty() {
                "none".to_string()
            } else {
                matched.join(",")
            },
            confidence: label_scores
                .iter()
                .map(|score| score.confidence)
                .max_by(f64::total_cmp)
                .unwrap_or(0.0),
            label_scores,
        });
    }
    if matches!(
        head,
        "sensitive_document" | "tool_class" | "tool_action" | "routing"
    ) {
        let mut counts = HashMap::<&str, usize>::new();
        for output in candidates {
            *counts.entry(output.class_name.as_str()).or_default() += 1;
        }
        let winning_label = counts
            .into_iter()
            .max_by(|(left_label, left_count), (right_label, right_count)| {
                left_count
                    .cmp(right_count)
                    .then_with(|| right_label.cmp(left_label))
            })?
            .0;
        return candidates
            .iter()
            .copied()
            .filter(|output| output.class_name == winning_label)
            .max_by(|left, right| left.confidence.total_cmp(&right.confidence))
            .cloned();
    }
    let risky = match head {
        "injection" => candidates
            .iter()
            .copied()
            .filter(|output| output.class_name == "injection")
            .max_by(|left, right| left.confidence.total_cmp(&right.confidence)),
        "threat" => candidates
            .iter()
            .copied()
            .filter(|output| output.class_name != "benign")
            .max_by(|left, right| left.confidence.total_cmp(&right.confidence)),
        _ => None,
    };
    risky
        .or_else(|| {
            candidates
                .iter()
                .copied()
                .max_by(|left, right| left.confidence.total_cmp(&right.confidence))
        })
        .cloned()
}

#[cfg(feature = "test-util")]
#[doc(hidden)]
pub fn aggregate_unified_head_for_test(
    head: &str,
    candidates: &[UnifiedHeadOutput],
) -> Option<UnifiedHeadOutput> {
    aggregate_unified_head(head, &candidates.iter().collect::<Vec<_>>())
}

#[cfg(feature = "test-util")]
#[doc(hidden)]
pub fn public_unified_class_for_test(head: &str, class_name: &str) -> String {
    public_class_name(head, class_name).to_string()
}

#[cfg(feature = "test-util")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct UnifiedCoalescingSnapshot {
    pub physical_jobs: usize,
    pub physical_model: String,
    pub physical_ttl_ms: u64,
    pub subscribers: Vec<String>,
}

#[cfg(feature = "test-util")]
#[doc(hidden)]
pub fn unified_coalescing_snapshot(categories: &[&str]) -> UnifiedCoalescingSnapshot {
    let worker = L3Worker {
        state: Arc::new(L3WorkerState {
            jobs: Mutex::new(Vec::new()),
            scheduler: Mutex::new(FairSchedulerState::default()),
            available: Condvar::new(),
            models: Mutex::new(HashMap::new()),
            dynamic_pii_models: Mutex::new(HashMap::new()),
            unified_model: Mutex::new(None),
            unified_runs: Mutex::new(HashMap::new()),
            unified_cache: Mutex::new(HashMap::new()),
            chunk_cache: Arc::new(DecisionCache::default()),
            requests: Arc::new(RequestRegistry::default()),
            next_sequence: Mutex::new(0),
        }),
    };
    for (index, category) in categories.iter().enumerate() {
        let mut execution = ScanExecution::new(SecurityLevel::L3);
        execution.set_l3_strategy(L3Strategy::Multi);
        enqueue(
            &worker,
            L3JobSpec {
                job_id: index as u64,
                request_id: "request-1".to_string(),
                category: (*category).to_string(),
                model: format!("dedicated-{category}"),
                text: "same request text".to_string(),
                fallback: SecurityScanResult {
                    category: (*category).to_string(),
                    class_name: "fallback".to_string(),
                    confidence: 0.5,
                    level: "L2".to_string(),
                    model: format!("l2-{category}"),
                    duration_ms: 1.0,
                    layers: Vec::new(),
                    evidence_spans: Vec::new(),
                    label_scores: Vec::new(),
                },
                priority: 0,
                ttl_ms: 10_000,
                execution,
                degraded_factor: 0.75,
                l3_candidate_spans: Vec::new(),
                dynamic_pii_config: None,
                dynamic_pii_activated_rules: Vec::new(),
            },
        );
    }

    let jobs = worker
        .state
        .jobs
        .lock()
        .expect("l3 job queue mutex poisoned");
    let physical_jobs = jobs.len();
    let physical_model = jobs
        .first()
        .map(|job| job.model.clone())
        .unwrap_or_default();
    let physical_ttl_ms = jobs.first().map(|job| job.ttl_ms).unwrap_or_default();
    drop(jobs);
    let runs = worker
        .state
        .unified_runs
        .lock()
        .expect("unified run mutex poisoned");
    let subscribers = runs
        .values()
        .find_map(|state| match state {
            UnifiedRunState::Running { subscribers } => Some(
                subscribers
                    .iter()
                    .map(|subscriber| subscriber.category.clone())
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default();
    UnifiedCoalescingSnapshot {
        physical_jobs,
        physical_model,
        physical_ttl_ms,
        subscribers,
    }
}

pub(super) fn finish_run(
    worker: &Arc<L3WorkerState>,
    run_key: String,
    cache_key: String,
    outcome: UnifiedRunOutcome,
) {
    let (subscribers, completed, failure) = {
        let mut runs = worker
            .unified_runs
            .lock()
            .expect("unified run mutex poisoned");
        let subscribers = match runs.remove(&run_key) {
            Some(UnifiedRunState::Running { subscribers }) => subscribers,
            Some(state) => {
                runs.insert(run_key, state);
                return;
            }
            None => return,
        };
        match outcome {
            UnifiedRunOutcome::Completed(result) => {
                runs.insert(run_key, UnifiedRunState::Completed(result.clone()));
                (subscribers, Some(result), None)
            }
            UnifiedRunOutcome::Failed(failure) => {
                runs.insert(run_key, UnifiedRunState::Failed(failure.clone()));
                (subscribers, None, Some(failure))
            }
        }
    };

    if let Some(result) = completed {
        worker
            .unified_cache
            .lock()
            .expect("unified cache mutex poisoned")
            .insert(
                cache_key,
                UnifiedCacheEntry {
                    result: result.clone(),
                    expires_at: Instant::now() + Duration::from_secs(60 * 60),
                },
            );
        for subscriber in subscribers {
            let output = materialize_unified_result(&subscriber, &result);
            finish_job(
                worker,
                subscriber.job_id,
                subscriber.request_id.clone(),
                output,
            );
        }
    } else if let Some(failure) = failure {
        for subscriber in subscribers {
            let output = materialize_unified_failure(&subscriber, &failure);
            finish_job(
                worker,
                subscriber.job_id,
                subscriber.request_id.clone(),
                output,
            );
        }
    }
}

fn materialize_unified_result(
    subscriber: &L3JobSpec,
    run: &UnifiedRunResult,
) -> SecurityScanResult {
    let head = subscriber.category.as_str();
    let Some(output) = run.output.heads.get(head) else {
        return degraded_error_result(
            subscriber.fallback.clone(),
            run.queue_wait_ms,
            subscriber.ttl_ms,
            subscriber.degraded_factor,
            format!("unified L3 result is missing head '{head}'"),
        );
    };
    let class_name = public_class_name(head, &output.class_name);
    let mut result = subscriber.fallback.clone();
    for layer in &mut result.layers {
        layer.matched = false;
    }
    let mut layer = l3_metadata_layer(
        class_name,
        UNIFIED_MODEL,
        output.confidence,
        run.duration_ms,
    );
    layer.details.extend(HashMap::from([
        ("head".to_string(), serde_json::json!(head)),
        ("revision".to_string(), serde_json::json!(UNIFIED_REVISION)),
        ("l3_worker".to_string(), serde_json::json!("rust_l3_worker")),
        (
            "l3_queue_wait_ms".to_string(),
            serde_json::json!(run.queue_wait_ms),
        ),
        (
            "chunk_count".to_string(),
            serde_json::json!(run.chunk_count),
        ),
        (
            "physical_job_id".to_string(),
            serde_json::json!(run.physical_job_id),
        ),
    ]));
    result.layers.push(layer);
    result.class_name = class_name.to_string();
    result.confidence = output.confidence;
    result.level = SecurityLevel::L3.as_str().to_string();
    result.model = UNIFIED_MODEL.to_string();
    result.label_scores = output
        .label_scores
        .iter()
        .cloned()
        .map(|mut score| {
            score.label = public_class_name(head, &score.label).to_string();
            score
        })
        .collect();
    result.duration_ms = result.layers.iter().map(|layer| layer.duration_ms).sum();
    result
}

fn public_class_name<'a>(head: &str, class_name: &'a str) -> &'a str {
    if head == "injection" && class_name == "injection" {
        "attack"
    } else {
        class_name
    }
}

fn materialize_unified_failure(
    subscriber: &L3JobSpec,
    failure: &UnifiedRunFailure,
) -> SecurityScanResult {
    match failure {
        UnifiedRunFailure::Timeout { queued_ms, ttl_ms } => degraded_timeout_result(
            subscriber.fallback.clone(),
            *queued_ms,
            *ttl_ms,
            subscriber.degraded_factor,
        ),
        UnifiedRunFailure::Error {
            queued_ms,
            ttl_ms,
            error,
        } => degraded_error_result(
            subscriber.fallback.clone(),
            *queued_ms,
            *ttl_ms,
            subscriber.degraded_factor,
            error.clone(),
        ),
    }
}

fn unified_run_key(spec: &L3JobSpec) -> String {
    unified_key(
        Some(spec.request_id.as_str()),
        &spec.text,
        spec.execution.backend(),
    )
}

pub(super) fn run_key_for_job(job: &L3WorkerJob) -> String {
    unified_key(
        Some(job.request_id.as_str()),
        &job.text,
        job.execution.backend(),
    )
}

fn unified_cache_key(spec: &L3JobSpec) -> String {
    unified_key(None, &spec.text, spec.execution.backend())
}

pub(super) fn cache_key_for_job(job: &L3WorkerJob) -> String {
    unified_key(None, &job.text, job.execution.backend())
}

fn unified_key(request_id: Option<&str>, text: &str, backend: crate::ExecutionBackend) -> String {
    let hash = blake3::hash(text.as_bytes());
    format!(
        "{}{}:{}:{}",
        request_id
            .map(|value| format!("{value}:"))
            .unwrap_or_default(),
        UNIFIED_REVISION,
        backend.as_str(),
        hash.to_hex()
    )
}

fn cached_unified_result(state: &L3WorkerState, key: &str) -> Option<UnifiedRunResult> {
    let now = Instant::now();
    let mut cache = state
        .unified_cache
        .lock()
        .expect("unified cache mutex poisoned");
    match cache.get(key) {
        Some(entry) if entry.expires_at > now => Some(entry.result.clone()),
        Some(_) => {
            cache.remove(key);
            None
        }
        None => None,
    }
}
