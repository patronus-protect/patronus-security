// SPDX-License-Identifier: GPL-3.0-only
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
#[cfg(feature = "test-util")]
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::assets::UNIFIED_L3_ASSET;
use crate::cache::{
    decision_output, CacheCoordinator, CacheKey, CacheNamespace, CacheSource, CachedHeadOutput,
    CachedModelOutput, HistoricalSimilarityCache,
};
use crate::ml::unified_onnx::{
    UnifiedHeadOutput, UnifiedModelOutput, UnifiedRawModelOutput, UNIFIED_MODEL,
};
use crate::{L3ClusteringStrategy, L3EarlyExitMode, SecurityLevel, SecurityScanResult};
#[cfg(feature = "test-util")]
use crate::{L3Strategy, ScanExecution};

#[cfg(feature = "test-util")]
use super::super::decision_cache::DecisionCache;
use super::super::l3_routing::{priority_index, ttl_ms};
use super::super::{degraded_error_result, degraded_timeout_result, l3_metadata_layer};
use super::{
    elapsed_ms, finish_job, request_wide_early_exit, L3JobSpec, L3Worker, L3WorkerInput,
    L3WorkerJob, L3WorkerState, UnifiedModelHandle,
};
#[cfg(feature = "test-util")]
use super::{FairSchedulerState, RequestRegistry};
use crate::pipeline::decision_thresholds::arbitrate_l3_l2;
use crate::pipeline::l3_engine::{execute_l3_plan, L3ExecutionAdapter, L3ResolvedKind};
use crate::pipeline::l3_schedule::SelectedL3Chunk;
use crate::pipeline::strategy::{
    aggregate_decision_index, ChunkAggregation, ChunkDecision, HeadDecisionState, PipelineStrategy,
};

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
    inferred_chunks: usize,
    propagated_chunks: usize,
    planned_l3_chunks: usize,
    resolved_chunks: usize,
    total_effective_chunks: usize,
    head_early_exits: HashSet<String>,
    resolved_chunks_by_head: HashMap<String, usize>,
    total_chunks_by_head: HashMap<String, usize>,
    cache_hits: usize,
    clustering: L3ClusteringStrategy,
    physical_job_id: u64,
    chunk_trace: Option<Vec<serde_json::Value>>,
}

#[derive(Clone)]
struct UnifiedChunkOutput {
    chunk_index: usize,
    output: UnifiedModelOutput,
    allowed_heads: HashSet<String>,
}

struct UnifiedHeadChunkPlan {
    heads_by_chunk: Vec<HashSet<String>>,
    l3_chunks_by_head: HashMap<String, usize>,
    rank_by_chunk: Vec<HashMap<String, (usize, f32)>>,
}

#[derive(Clone)]
pub(super) enum UnifiedRunFailure {
    Timeout {
        queued_ms: f64,
        timeout_ms: u64,
        reason: &'static str,
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
    if let Some(mut result) = cached_unified_result(&worker.state, &cache_key) {
        result.duration_ms = 0.0;
        result.queue_wait_ms = 0.0;
        result.cache_hits = 1;
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
            subscribers.push(subscriber_spec(spec));
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
                run_key.clone(),
                UnifiedRunState::Running {
                    subscribers: vec![subscriber_spec(spec.clone())],
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
    physical.inference_timeout_ms = physical.ttl_ms;
    worker.enqueue_unified_physical(physical, run_key, cache_key);
}

fn subscriber_spec(mut spec: L3JobSpec) -> L3JobSpec {
    spec.l3_candidates.clear();
    spec.l2_chunk_outputs = Vec::new().into();
    spec
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
            timeout_ms: job.ttl_ms,
            reason: "expired_before_inference",
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
    let exact_cache = Arc::clone(&state.exact_cache);
    let similarity_cache = Arc::clone(&state.similarity_cache);
    match run_unified_model_job(&job, model, exact_cache, similarity_cache) {
        Ok(result) => UnifiedRunOutcome::Completed(result),
        Err(error) => UnifiedRunOutcome::Failed(UnifiedRunFailure::Error {
            queued_ms: elapsed_ms(job.enqueued_at),
            ttl_ms: job.ttl_ms,
            error,
        }),
    }
}

pub(super) enum UnifiedRunOutcome {
    Completed(UnifiedRunResult),
    Failed(UnifiedRunFailure),
}

fn run_unified_model_job(
    job: &L3WorkerJob,
    model: UnifiedModelHandle,
    exact_cache: Arc<CacheCoordinator>,
    similarity_cache: Arc<HistoricalSimilarityCache>,
) -> Result<UnifiedRunResult, String> {
    let queue_wait_ms = elapsed_ms(job.enqueued_at);
    let started = Instant::now();
    let chunks = planned_chunks(job)?;
    let selection_clustering = selection_clustering_for_job(job);
    let head_plan = unified_head_chunk_plan(&chunks, &job.l3_candidates, &job.category);
    let mut promoted_heads = head_plan
        .l3_chunks_by_head
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    promoted_heads.sort_by_key(|head| priority_index(job.execution.l3_policy(), head, head));
    let mut outputs = Vec::new();
    let mut physical_outputs = HashMap::<usize, UnifiedModelOutput>::new();
    let mut chunk_trace = l3_chunk_trace_enabled().then(Vec::new);
    let mut inferred_chunks = 0usize;
    let mut cache_hits = 0usize;
    let mut propagated_chunks = 0usize;
    let mut resolved_chunks = 0usize;
    let mut total_effective_chunks = 0usize;
    let mut head_early_exits = HashSet::new();
    let mut resolved_chunks_by_head = HashMap::new();
    let mut total_chunks_by_head = HashMap::new();

    for head in promoted_heads {
        let policy = job.execution.l3_policy().pipeline_policy(&head, &head);
        let mut head_entries = head_plan
            .heads_by_chunk
            .iter()
            .enumerate()
            .filter_map(|(index, heads)| {
                if !heads.contains(&head) {
                    return None;
                }
                let mut chunk = chunks[index].clone();
                if let Some((head_priority, priority)) = head_plan.rank_by_chunk[index].get(&head) {
                    chunk.head_priority = *head_priority;
                    chunk.priority = *priority;
                }
                if historical_unified_non_safe(&similarity_cache, &chunk, &head) {
                    chunk.head_priority = 0;
                    chunk.priority = 1.0;
                }
                Some((index, chunk))
            })
            .collect::<Vec<_>>();
        if policy.clustering == L3ClusteringStrategy::Disabled {
            head_entries.sort_by_key(|(_, chunk)| chunk.source_order);
        } else {
            head_entries.sort_by(|left, right| {
                left.1
                    .head_priority
                    .cmp(&right.1.head_priority)
                    .then_with(|| right.1.priority.total_cmp(&left.1.priority))
                    .then_with(|| left.1.source_order.cmp(&right.1.source_order))
            });
        }
        let global_indices = head_entries
            .iter()
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        if global_indices.is_empty() {
            continue;
        }
        let head_chunks = head_entries
            .into_iter()
            .map(|(_, chunk)| chunk)
            .collect::<Vec<_>>();
        let mut strategy = PipelineStrategy::for_category_model(&head, &head);
        if let Some(aggregation) = policy.aggregation.clone() {
            strategy.aggregation = aggregation.into();
        } else if let Some(aggregation) = unified_head_aggregation(&head) {
            strategy.aggregation = aggregation;
        }
        let safe_class = unified_safe_class(&head);
        let head_total = head_chunks.len();
        total_effective_chunks = total_effective_chunks.max(head_total);
        total_chunks_by_head.insert(head.clone(), head_total);
        let decision = HeadDecisionState::new(
            strategy.aggregation.clone(),
            safe_class,
            policy.early_exit,
            head_total,
        );
        if decision.head_is_stable() {
            head_early_exits.insert(head.clone());
            resolved_chunks_by_head.insert(head.clone(), decision.observed_chunks());
            if decision.request_should_stop() {
                break;
            }
            continue;
        }
        let mut adapter = UnifiedExecutionAdapter {
            head: &head,
            model: &model,
            exact_cache: &exact_cache,
            similarity_cache: &similarity_cache,
            backend: job.execution.backend(),
            onnx_runtime_options: job.execution.onnx_runtime_options(),
            chunks: &chunks,
            head_chunks: &head_chunks,
            global_indices: &global_indices,
            physical_outputs: &mut physical_outputs,
            outputs: &mut outputs,
            trace: &mut chunk_trace,
            decision,
            aggregation: strategy.aggregation,
            safe_class,
            physical_inferred_chunks: &mut inferred_chunks,
            cache_hits: &mut cache_hits,
            propagated_chunks: &mut propagated_chunks,
            request_stop: false,
        };
        let summary = execute_l3_plan(&head_chunks, &policy, &mut adapter)?;
        resolved_chunks = resolved_chunks.max(adapter.decision.observed_chunks());
        resolved_chunks_by_head.insert(head.clone(), adapter.decision.observed_chunks());
        if summary.stopped_early {
            head_early_exits.insert(head.clone());
        }
        let request_stop = adapter.request_stop;
        drop(adapter);
        if request_stop {
            break;
        }
    }

    Ok(UnifiedRunResult {
        output: aggregate_unified_outputs(outputs, Some(job.execution.l3_policy()))?,
        duration_ms: started.elapsed().as_secs_f64() * 1_000.0,
        queue_wait_ms,
        chunk_count: chunks.len(),
        inferred_chunks,
        propagated_chunks,
        planned_l3_chunks: chunks.len(),
        resolved_chunks,
        total_effective_chunks,
        head_early_exits,
        resolved_chunks_by_head,
        total_chunks_by_head,
        cache_hits,
        clustering: selection_clustering,
        physical_job_id: job.job_id,
        chunk_trace,
    })
}

fn candidate_head_names(
    candidates: &[crate::ml::ntdb_executor::L3Candidate],
    fallback_head: &str,
) -> HashSet<String> {
    let mut heads = HashSet::new();
    for candidate in candidates {
        for head in candidate.source_pipeline.split(',').map(str::trim) {
            if !head.is_empty() {
                heads.insert(head.to_string());
            }
        }
    }
    if heads.is_empty() && !fallback_head.is_empty() {
        heads.insert(fallback_head.to_string());
    }
    heads
}

pub(super) fn selection_clustering_for_spec(spec: &L3JobSpec) -> L3ClusteringStrategy {
    selection_clustering(
        &spec.l3_candidates,
        &spec.category,
        spec.execution.l3_policy(),
    )
}

fn selection_clustering_for_job(job: &L3WorkerJob) -> L3ClusteringStrategy {
    selection_clustering(&job.l3_candidates, &job.category, job.execution.l3_policy())
}

fn selection_clustering(
    candidates: &[crate::ml::ntdb_executor::L3Candidate],
    fallback_head: &str,
    policy: &crate::L3SchedulerPolicy,
) -> L3ClusteringStrategy {
    candidate_head_names(candidates, fallback_head)
        .iter()
        .map(|head| policy.pipeline_policy(head, head).clustering)
        .find(|clustering| {
            matches!(
                clustering,
                L3ClusteringStrategy::Representative | L3ClusteringStrategy::VerifyRepresentative
            )
        })
        .unwrap_or(policy.clustering)
}

fn planned_chunks(job: &L3WorkerJob) -> Result<Vec<SelectedL3Chunk>, String> {
    match &job.input {
        L3WorkerInput::PlannedChunks(chunks) => Ok(chunks.clone()),
        L3WorkerInput::Text(_) => Err("unified L3 job is missing planned chunks".to_string()),
    }
}

struct UnifiedExecutionAdapter<'a> {
    head: &'a str,
    model: &'a UnifiedModelHandle,
    exact_cache: &'a Arc<CacheCoordinator>,
    similarity_cache: &'a Arc<HistoricalSimilarityCache>,
    backend: crate::ExecutionBackend,
    onnx_runtime_options: crate::OnnxRuntimeOptions,
    chunks: &'a [SelectedL3Chunk],
    head_chunks: &'a [SelectedL3Chunk],
    global_indices: &'a [usize],
    physical_outputs: &'a mut HashMap<usize, UnifiedModelOutput>,
    outputs: &'a mut Vec<UnifiedChunkOutput>,
    trace: &'a mut Option<Vec<serde_json::Value>>,
    decision: HeadDecisionState,
    aggregation: ChunkAggregation,
    safe_class: &'static str,
    physical_inferred_chunks: &'a mut usize,
    cache_hits: &'a mut usize,
    propagated_chunks: &'a mut usize,
    request_stop: bool,
}

impl L3ExecutionAdapter for UnifiedExecutionAdapter<'_> {
    type Output = UnifiedModelOutput;

    fn infer(&mut self, chunk_index: usize) -> Result<Self::Output, String> {
        let global_index = self.global_indices[chunk_index];
        let mut exact_cache_hit = false;
        let mut similarity_propagated = false;
        let (output, inferred) =
            unified_physical_output(self.physical_outputs, global_index, || {
                let (output, cache_hit, propagated) = infer_unified_exact(
                    self.model,
                    self.exact_cache,
                    self.similarity_cache,
                    &self.head_chunks[chunk_index],
                    self.head,
                    self.backend,
                    self.onnx_runtime_options,
                )?;
                exact_cache_hit = cache_hit;
                similarity_propagated = propagated;
                Ok(output)
            })?;
        if inferred {
            *self.physical_inferred_chunks += 1;
            if exact_cache_hit {
                *self.cache_hits += 1;
            }
            if similarity_propagated {
                *self.propagated_chunks += 1;
                // A propagated output is authoritative only for this head. Do
                // not let the physical-output reuse map suppress another head.
                self.physical_outputs.remove(&global_index);
            }
        }
        Ok(output)
    }

    fn combine_representatives(
        &self,
        representatives: &[(usize, Self::Output)],
    ) -> Option<Self::Output> {
        let head_outputs = representatives
            .iter()
            .map(|(_, output)| output.heads.get(self.head))
            .collect::<Option<Vec<_>>>()?;
        let decisions = head_outputs
            .iter()
            .map(|output| ChunkDecision {
                class_name: &output.class_name,
                confidence: output.confidence,
            })
            .collect::<Vec<_>>();
        let selected = aggregate_decision_index(&decisions, &self.aggregation, self.safe_class)?;
        Some(representatives[selected].1.clone())
    }

    fn verification_matches(
        &self,
        representative: &Self::Output,
        verifiers: &[(usize, Self::Output)],
    ) -> bool {
        let Some(representative) = representative.heads.get(self.head) else {
            return false;
        };
        verifiers.iter().all(|(_, output)| {
            output
                .heads
                .get(self.head)
                .is_some_and(|output| output.class_name == representative.class_name)
        })
    }

    fn propagated_output(
        &self,
        representative: &Self::Output,
        _representative_index: usize,
        _member_index: usize,
    ) -> Option<Self::Output> {
        representative
            .heads
            .contains_key(self.head)
            .then(|| representative.clone())
    }

    fn observe(&mut self, chunk_index: usize, output: &Self::Output, kind: L3ResolvedKind) -> bool {
        let global_index = self.global_indices[chunk_index];
        let Some(head_output) = output.heads.get(self.head) else {
            return false;
        };
        self.decision
            .observe(&head_output.class_name, head_output.confidence);
        let chunk_output = UnifiedChunkOutput {
            chunk_index: global_index,
            output: output.clone(),
            allowed_heads: HashSet::from([self.head.to_string()]),
        };
        let propagated = kind == L3ResolvedKind::Propagated;
        if propagated {
            *self.propagated_chunks += 1;
        }
        push_unified_chunk_trace(
            self.trace,
            &self.chunks[global_index],
            &chunk_output,
            propagated,
        );
        self.outputs.push(chunk_output);
        self.request_stop |= self.decision.request_should_stop();
        self.decision.head_is_stable()
    }
}

fn infer_unified_exact(
    model: &UnifiedModelHandle,
    exact_cache: &CacheCoordinator,
    similarity_cache: &HistoricalSimilarityCache,
    chunk: &SelectedL3Chunk,
    requested_head: &str,
    backend: crate::ExecutionBackend,
    onnx_runtime_options: crate::OnnxRuntimeOptions,
) -> Result<(UnifiedModelOutput, bool, bool), String> {
    const CACHE_SCHEMA_VERSION: u32 = 1;

    let namespace = CacheNamespace::from_model_sha(CACHE_SCHEMA_VERSION, UNIFIED_L3_ASSET.revision);
    let key = CacheKey::for_chunk(namespace, chunk.text.as_bytes());
    if let Some(matched) = similarity_cache.find_best_for_head(
        &chunk.embedding_space,
        &chunk.embedding,
        requested_head,
    ) {
        if matched.propagation_similarity > 0.985 {
            if let Some(decision) = matched
                .decision
                .filter(|decision| decision.class_name != unified_safe_class(requested_head))
            {
                let class_name = if requested_head == "injection" && decision.class_name == "attack"
                {
                    "injection".to_string()
                } else {
                    decision.class_name
                };
                return Ok((
                    UnifiedModelOutput {
                        heads: HashMap::from([(
                            requested_head.to_string(),
                            UnifiedHeadOutput {
                                class_name,
                                confidence: decision.confidence,
                                label_scores: Vec::new(),
                            },
                        )]),
                    },
                    true,
                    true,
                ));
            }
        }
    }
    let lookup = exact_cache
        .get_or_compute_heads(key, || {
            let raw = model
                .lock()
                .map_err(|error| format!("unified L3 model mutex poisoned: {error}"))?
                .infer_raw(&chunk.text, backend, onnx_runtime_options)
                .map_err(|error| error.to_string())?;
            Ok::<_, String>(
                raw.heads
                    .into_iter()
                    .map(|(head, logits)| CachedHeadOutput { head, logits })
                    .collect(),
            )
        })
        .map_err(|error| error.to_string())?;
    let raw = cached_unified_output(&lookup.output)?;
    let output = model
        .lock()
        .map_err(|error| format!("unified L3 model mutex poisoned: {error}"))?
        .decode_raw(&raw)
        .map_err(|error| error.to_string())?;
    let mut similarity_heads = lookup.output.heads.clone();
    similarity_heads.extend(output.heads.iter().map(|(head, output)| {
        decision_output(
            head,
            public_class_name(head, &output.class_name),
            output.confidence,
        )
    }));
    similarity_cache.remember(
        &chunk.embedding_space,
        &chunk.embedding,
        UNIFIED_L3_ASSET.revision,
        similarity_heads,
    );
    Ok((output, lookup.source != CacheSource::Computed, false))
}

fn historical_unified_non_safe(
    cache: &HistoricalSimilarityCache,
    chunk: &SelectedL3Chunk,
    head: &str,
) -> bool {
    let Some(matched) = cache.find_best_for_head(&chunk.embedding_space, &chunk.embedding, head)
    else {
        return false;
    };
    matched
        .decision
        .is_some_and(|decision| decision.class_name != unified_safe_class(head))
}

fn cached_unified_output(output: &CachedModelOutput) -> Result<UnifiedRawModelOutput, String> {
    if output.schema_version != 1 {
        return Err(format!(
            "unsupported cached model output schema {}",
            output.schema_version
        ));
    }
    Ok(UnifiedRawModelOutput {
        heads: output
            .heads
            .iter()
            .map(|head| (head.head.clone(), head.logits.clone()))
            .collect(),
    })
}

fn unified_physical_output<T: Clone>(
    cache: &mut HashMap<usize, T>,
    chunk_index: usize,
    infer: impl FnOnce() -> Result<T, String>,
) -> Result<(T, bool), String> {
    if let Some(output) = cache.get(&chunk_index) {
        return Ok((output.clone(), false));
    }
    let output = infer()?;
    cache.insert(chunk_index, output.clone());
    Ok((output, true))
}

fn l3_chunk_trace_enabled() -> bool {
    std::env::var("PATRONUS_L3_TRACE_CHUNKS").is_ok_and(|value| value == "1")
}

fn push_unified_chunk_trace(
    trace: &mut Option<Vec<serde_json::Value>>,
    chunk: &crate::pipeline::l3_schedule::SelectedL3Chunk,
    output: &UnifiedChunkOutput,
    propagated: bool,
) {
    let Some(trace) = trace else {
        return;
    };
    let mut heads = serde_json::Map::new();
    for (head, head_output) in &output.output.heads {
        heads.insert(
            head.clone(),
            serde_json::json!({
                "class_name": public_class_name(head, &head_output.class_name),
                "internal_class_name": head_output.class_name,
                "confidence": head_output.confidence,
                "allowed": output.allowed_heads.contains(head),
            }),
        );
    }
    trace.push(serde_json::json!({
        "chunk_index": output.chunk_index,
        "source_order": chunk.source_order,
        "start_byte": chunk.start_byte,
        "end_byte": chunk.end_byte,
        "priority": chunk.priority,
        "head_priority": chunk.head_priority,
        "allowed_heads": output.allowed_heads,
        "propagated": propagated,
        "heads": heads,
    }));
}

fn unified_head_chunk_plan(
    chunks: &[crate::pipeline::l3_schedule::SelectedL3Chunk],
    candidates: &[crate::ml::ntdb_executor::L3Candidate],
    fallback_head: &str,
) -> UnifiedHeadChunkPlan {
    let mut heads_by_chunk = vec![HashSet::<String>::new(); chunks.len()];
    let mut rank_by_chunk = vec![HashMap::<String, (usize, f32)>::new(); chunks.len()];
    for (chunk_index, chunk) in chunks.iter().enumerate() {
        for candidate in candidates {
            if candidate.span.start >= chunk.end_byte || candidate.span.end <= chunk.start_byte {
                continue;
            }
            for head in candidate.source_pipeline.split(',').map(str::trim) {
                if !head.is_empty() {
                    heads_by_chunk[chunk_index].insert(head.to_string());
                    let rank = (
                        crate::pipeline::l3_schedule::candidate_head_priority(candidate),
                        crate::pipeline::l3_schedule::candidate_priority(candidate),
                    );
                    rank_by_chunk[chunk_index]
                        .entry(head.to_string())
                        .and_modify(|current| {
                            current.0 = current.0.min(rank.0);
                            current.1 = current.1.max(rank.1);
                        })
                        .or_insert(rank);
                }
            }
        }
    }
    if candidates.is_empty() && !fallback_head.is_empty() {
        for heads in &mut heads_by_chunk {
            heads.insert(fallback_head.to_string());
        }
    }
    let mut l3_chunks_by_head = HashMap::<String, usize>::new();
    for heads in &heads_by_chunk {
        for head in heads {
            *l3_chunks_by_head.entry(head.clone()).or_default() += 1;
        }
    }
    UnifiedHeadChunkPlan {
        heads_by_chunk,
        l3_chunks_by_head,
        rank_by_chunk,
    }
}

fn aggregate_unified_outputs(
    outputs: Vec<UnifiedChunkOutput>,
    policy: Option<&crate::L3SchedulerPolicy>,
) -> Result<UnifiedModelOutput, String> {
    let mut head_names = HashSet::new();
    for output in &outputs {
        head_names.extend(output.allowed_heads.iter().cloned());
    }
    if head_names.is_empty() {
        return Err("unified L3 produced no chunk output".to_string());
    }
    let mut heads = HashMap::new();
    for head in head_names {
        let candidates = outputs
            .iter()
            .filter(|output| output.allowed_heads.contains(&head))
            .filter_map(|output| output.output.heads.get(&head))
            .collect::<Vec<_>>();
        let aggregation = policy
            .and_then(|policy| policy.pipeline_policy(&head, &head).aggregation)
            .map(ChunkAggregation::from);
        let selected =
            aggregate_unified_head_with_strategy(&head, &candidates, aggregation.as_ref())
                .ok_or_else(|| format!("unified L3 head '{head}' produced no output"))?;
        heads.insert(head, selected);
    }
    Ok(UnifiedModelOutput { heads })
}

fn unified_head_aggregation(head: &str) -> Option<ChunkAggregation> {
    match head {
        "injection" => Some(ChunkAggregation::AnyPositiveOrHighest {
            positive_class: "injection".to_string(),
            threshold: 0.93,
        }),
        "threat" => {
            Some(ChunkAggregation::HighestRiskAboveThresholdOrConfidence { threshold: 0.93 })
        }
        "sensitive_document" | "tool_class" | "tool_action" | "routing" => {
            Some(ChunkAggregation::MajorityVoteOrHighest)
        }
        _ => None,
    }
}

fn unified_safe_class(head: &str) -> &'static str {
    match head {
        "injection" | "threat" => "benign",
        _ => "safe",
    }
}

#[cfg(feature = "test-util")]
fn unified_outputs_have_same_classes_for_heads(
    left: &UnifiedModelOutput,
    right: &UnifiedModelOutput,
    heads: &HashSet<String>,
) -> bool {
    if heads.is_empty() {
        return true;
    }
    heads.iter().all(|head| {
        let Some(left_output) = left.heads.get(head) else {
            return true;
        };
        right
            .heads
            .get(head)
            .is_some_and(|right_output| right_output.class_name == left_output.class_name)
    })
}

#[cfg(feature = "test-util")]
fn aggregate_unified_head(
    head: &str,
    candidates: &[&UnifiedHeadOutput],
) -> Option<UnifiedHeadOutput> {
    aggregate_unified_head_with_strategy(head, candidates, None)
}

fn aggregate_unified_head_with_strategy(
    head: &str,
    candidates: &[&UnifiedHeadOutput],
    configured: Option<&ChunkAggregation>,
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
    let default_aggregation;
    let aggregation = if let Some(configured) = configured {
        configured
    } else {
        default_aggregation = unified_head_aggregation(head)
            .unwrap_or_else(|| PipelineStrategy::for_category_model(head, head).aggregation);
        &default_aggregation
    };
    let decisions = candidates
        .iter()
        .map(|output| ChunkDecision {
            class_name: &output.class_name,
            confidence: output.confidence,
        })
        .collect::<Vec<_>>();
    let selected = aggregate_decision_index(&decisions, aggregation, unified_safe_class(head))?;
    Some((*candidates[selected]).clone())
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
pub fn unified_outputs_have_same_classes_for_heads_for_test(
    left: &UnifiedModelOutput,
    right: &UnifiedModelOutput,
    heads: &[&str],
) -> bool {
    unified_outputs_have_same_classes_for_heads(
        left,
        right,
        &heads.iter().map(|head| (*head).to_string()).collect(),
    )
}

#[cfg(feature = "test-util")]
#[doc(hidden)]
pub fn public_unified_class_for_test(head: &str, class_name: &str) -> String {
    public_class_name(head, class_name).to_string()
}

#[cfg(feature = "test-util")]
#[doc(hidden)]
pub fn replace_unified_pending_layer_for_test(
    mut layers: Vec<crate::LayerResult>,
    completed: crate::LayerResult,
) -> Vec<crate::LayerResult> {
    replace_unified_pending_layer(&mut layers, completed);
    layers
}

#[cfg(feature = "test-util")]
#[doc(hidden)]
pub fn unified_metadata_details_for_test(
    clustering: L3ClusteringStrategy,
    inferred_chunks: usize,
    propagated_chunks: usize,
    resolved_chunks: usize,
    total_effective_chunks: usize,
) -> HashMap<String, serde_json::Value> {
    let subscriber = L3JobSpec {
        job_id: 7,
        request_id: "request-1".to_string(),
        category: "threat".to_string(),
        model: "dedicated-threat".to_string(),
        text: "same request text".into(),
        fallback: SecurityScanResult {
            category: "threat".to_string(),
            class_name: "benign".to_string(),
            confidence: 0.5,
            level: "L2".to_string(),
            model: "l2-threat".to_string(),
            duration_ms: 1.0,
            layers: vec![crate::pipeline::l3_pending_layer(
                &crate::EvaluationResult {
                    class_name: "benign".to_string(),
                    confidence: 0.5,
                    level: "L2".to_string(),
                },
                &ScanExecution::new(SecurityLevel::L3),
            )],
            internal_l2_chunk_outputs: Vec::new(),
            evidence_spans: Vec::new(),
            label_scores: Vec::new(),
            decision: None,
        },
        priority: 0,
        ttl_ms: 10_000,
        inference_timeout_ms: 10_000,
        execution: ScanExecution::new(SecurityLevel::L3),
        degraded_factor: 0.75,
        l3_candidates: Vec::new(),
        l2_chunk_outputs: Vec::new().into(),
        dynamic_pii_config: None,
        dynamic_pii_activated_rules: Vec::new(),
    };
    let run = UnifiedRunResult {
        output: UnifiedModelOutput {
            heads: HashMap::from([(
                "threat".to_string(),
                UnifiedHeadOutput {
                    class_name: "instruction_override".to_string(),
                    confidence: 0.9,
                    label_scores: Vec::new(),
                },
            )]),
        },
        duration_ms: 12.0,
        queue_wait_ms: 3.0,
        chunk_count: total_effective_chunks,
        inferred_chunks,
        propagated_chunks,
        planned_l3_chunks: total_effective_chunks,
        resolved_chunks,
        total_effective_chunks,
        head_early_exits: HashSet::new(),
        resolved_chunks_by_head: HashMap::from([("threat".to_string(), resolved_chunks)]),
        total_chunks_by_head: HashMap::from([("threat".to_string(), total_effective_chunks)]),
        cache_hits: 0,
        clustering,
        physical_job_id: 5,
        chunk_trace: None,
    };
    let result = materialize_unified_result(&subscriber, &run);
    result
        .layers
        .into_iter()
        .find(|layer| layer.level == "L3" && layer.layer_type == "onnx")
        .expect("materialized unified result must include an onnx layer")
        .details
}

#[cfg(feature = "test-util")]
#[derive(Debug, PartialEq, Eq)]
#[doc(hidden)]
pub struct UnifiedCoalescingSnapshot {
    pub physical_jobs: usize,
    pub physical_model: String,
    pub physical_ttl_ms: u64,
    pub physical_candidate_count: usize,
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
            exact_cache: Arc::new(
                crate::cache::CacheCoordinator::from_config(
                    crate::cache::ExactCacheConfig::default(),
                )
                .expect("memory-only exact cache must initialize"),
            ),
            pii_entity_cache: Arc::new(crate::cache::PiiEntityCache::new(Arc::new(
                crate::cache::CacheCoordinator::from_config(
                    crate::cache::ExactCacheConfig::default(),
                )
                .expect("memory-only PII cache must initialize"),
            ))),
            pii_chunk_cache: Arc::new(crate::cache::PiiChunkCache::new(Arc::new(
                crate::cache::CacheCoordinator::from_config(
                    crate::cache::ExactCacheConfig::default(),
                )
                .expect("memory-only PII chunk cache must initialize"),
            ))),
            similarity_cache: Arc::new(crate::cache::HistoricalSimilarityCache::new(Arc::new(
                crate::cache::CacheCoordinator::from_config(
                    crate::cache::ExactCacheConfig::default(),
                )
                .expect("memory-only similarity cache must initialize"),
            ))),
            requests: Arc::new(RequestRegistry::default()),
            next_sequence: Mutex::new(0),
        }),
    };
    let request_candidates = categories
        .iter()
        .enumerate()
        .map(|(index, category)| crate::ml::ntdb_executor::L3Candidate {
            span: crate::ml::ntdb_executor::ByteSpan {
                start: index * 100,
                end: index * 100 + 80,
            },
            promote_score: 0.9,
            promote_threshold: 0.7,
            source_pipeline: (*category).to_string(),
            source_model: format!("l2-{category}"),
            l2_class: "promote".to_string(),
        })
        .collect::<Vec<_>>();
    let request_l2_chunk_outputs = request_candidates
        .iter()
        .map(|candidate| crate::ml::ntdb_executor::L2ChunkOutput {
            span: candidate.span,
            class_name: "attack".to_string(),
            confidence: 0.9,
            promoted: true,
            promote_score: Some(candidate.promote_score),
            promote_threshold: Some(candidate.promote_threshold),
            source_pipeline: candidate.source_pipeline.clone(),
            source_model: candidate.source_model.clone(),
            embedding: Vec::new(),
            embedding_space: String::new(),
        })
        .collect::<Vec<_>>();
    let request_text = Arc::<str>::from("x".repeat(categories.len() * 100 + 80));
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
                text: Arc::clone(&request_text),
                fallback: SecurityScanResult {
                    category: (*category).to_string(),
                    class_name: "fallback".to_string(),
                    confidence: 0.5,
                    level: "L2".to_string(),
                    model: format!("l2-{category}"),
                    duration_ms: 1.0,
                    layers: Vec::new(),
                    internal_l2_chunk_outputs: Vec::new(),
                    evidence_spans: Vec::new(),
                    label_scores: Vec::new(),
                    decision: None,
                },
                priority: 0,
                ttl_ms: 10_000,
                inference_timeout_ms: 10_000,
                execution,
                degraded_factor: 0.75,
                l3_candidates: request_candidates.clone(),
                l2_chunk_outputs: request_l2_chunk_outputs.clone().into(),
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
    let physical_candidate_count = jobs
        .first()
        .map(|job| job.l3_candidates.len())
        .unwrap_or_default();
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
        physical_candidate_count,
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
        for (subscriber, output) in materialize_completed_unified_subscribers(subscribers, &result)
        {
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

fn materialize_completed_unified_subscribers(
    mut subscribers: Vec<L3JobSpec>,
    run: &UnifiedRunResult,
) -> Vec<(L3JobSpec, SecurityScanResult)> {
    subscribers.sort_by_key(|subscriber| (subscriber.priority, subscriber.job_id));
    let mut request_wide_stop: Option<(usize, String)> = None;
    let mut outputs = Vec::with_capacity(subscribers.len());
    for subscriber in subscribers {
        let output = match &request_wide_stop {
            Some((stop_priority, reason)) if subscriber.priority > *stop_priority => {
                materialize_unified_request_wide_skip(&subscriber, reason)
            }
            _ => materialize_unified_result(&subscriber, run),
        };
        if request_wide_stop.is_none() {
            if let Some(reason) = request_wide_early_exit(&output) {
                request_wide_stop = Some((subscriber.priority, reason));
            }
        }
        outputs.push((subscriber, output));
    }
    outputs
}

fn materialize_unified_request_wide_skip(
    subscriber: &L3JobSpec,
    reason: &str,
) -> SecurityScanResult {
    let mut result = subscriber.fallback.clone();
    result.confidence = (result.confidence * subscriber.degraded_factor).clamp(0.0, 1.0);
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
            layer.details.insert(
                "unified_l3_physical_reuse".to_string(),
                serde_json::json!(true),
            );
        }
    }
    super::super::mark_decision_degraded(&mut result, "request_wide_early_exit");
    result.duration_ms = result.layers.iter().map(|layer| layer.duration_ms).sum();
    result
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
    let head_early_exit = run.head_early_exits.contains(head);
    let resolved_chunks = run
        .resolved_chunks_by_head
        .get(head)
        .copied()
        .unwrap_or(run.resolved_chunks);
    let total_effective_chunks = run
        .total_chunks_by_head
        .get(head)
        .copied()
        .unwrap_or(run.total_effective_chunks);
    let complete = !head_early_exit && resolved_chunks == total_effective_chunks;
    let mut result = subscriber.fallback.clone();
    let mut layer = l3_metadata_layer(
        class_name,
        UNIFIED_MODEL,
        output.confidence,
        run.duration_ms,
    );
    layer.details.extend(HashMap::from([
        ("head".to_string(), serde_json::json!(head)),
        (
            "revision".to_string(),
            serde_json::json!(UNIFIED_L3_ASSET.revision),
        ),
        ("l3_worker".to_string(), serde_json::json!("rust_l3_worker")),
        (
            "l3_queue_wait_ms".to_string(),
            serde_json::json!(run.queue_wait_ms),
        ),
        (
            "l3_worker_wall_ms".to_string(),
            serde_json::json!(run.duration_ms),
        ),
        (
            "chunk_count".to_string(),
            serde_json::json!(run.chunk_count),
        ),
        ("early_exit".to_string(), serde_json::json!(head_early_exit)),
        (
            "coverage".to_string(),
            serde_json::json!(coverage(resolved_chunks, total_effective_chunks)),
        ),
        (
            "confidence_complete".to_string(),
            serde_json::json!(complete),
        ),
        ("evidence_complete".to_string(), serde_json::json!(complete)),
        (
            "inferred_chunks".to_string(),
            serde_json::json!(run.inferred_chunks),
        ),
        (
            "propagated_chunks".to_string(),
            serde_json::json!(run.propagated_chunks),
        ),
        (
            "planned_l3_chunks".to_string(),
            serde_json::json!(run.planned_l3_chunks),
        ),
        (
            "resolved_chunks".to_string(),
            serde_json::json!(resolved_chunks),
        ),
        (
            "total_effective_chunks".to_string(),
            serde_json::json!(total_effective_chunks),
        ),
        ("cache_hits".to_string(), serde_json::json!(run.cache_hits)),
        (
            "l3_clustering_strategy".to_string(),
            serde_json::json!(clustering_name(run.clustering)),
        ),
        (
            "physical_job_id".to_string(),
            serde_json::json!(run.physical_job_id),
        ),
    ]));
    if let Some(chunk_trace) = &run.chunk_trace {
        layer
            .details
            .insert("l3_chunk_trace".to_string(), serde_json::json!(chunk_trace));
    }
    replace_unified_pending_layer(&mut result.layers, layer);
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
    let mut result = arbitrate_l3_l2(
        head,
        Some(result),
        subscriber.fallback.clone(),
        subscriber.execution.ntdb_decision_threshold_point(),
    );
    result.duration_ms = result.layers.iter().map(|layer| layer.duration_ms).sum();
    result
}

fn coverage(resolved_chunks: usize, total_effective_chunks: usize) -> f64 {
    if total_effective_chunks == 0 {
        1.0
    } else {
        resolved_chunks as f64 / total_effective_chunks as f64
    }
}

fn clustering_name(clustering: L3ClusteringStrategy) -> &'static str {
    match clustering {
        L3ClusteringStrategy::Disabled => "disabled",
        L3ClusteringStrategy::RankOnly => "rank_only",
        L3ClusteringStrategy::Representative => "representative",
        L3ClusteringStrategy::VerifyRepresentative => "verify_representative",
    }
}

fn replace_unified_pending_layer(
    layers: &mut Vec<crate::LayerResult>,
    completed: crate::LayerResult,
) {
    layers.retain(|layer| layer.layer_type != "l3_pending");
    for layer in layers.iter_mut() {
        layer.matched = false;
    }
    layers.push(completed);
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
        UnifiedRunFailure::Timeout {
            queued_ms,
            timeout_ms,
            reason,
        } => {
            let mut result = degraded_timeout_result(
                subscriber.fallback.clone(),
                *queued_ms,
                *timeout_ms,
                subscriber.degraded_factor,
            );
            if let Some(layer) = result
                .layers
                .iter_mut()
                .find(|layer| layer.layer_type == "degraded_timeout")
            {
                layer
                    .details
                    .insert("timeout_reason".to_string(), serde_json::json!(reason));
            }
            result
        }
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
        spec.execution.l3_policy(),
        &spec.l3_candidates,
    )
}

pub(super) fn run_key_for_job(job: &L3WorkerJob) -> String {
    if let Some(key) = &job.unified_run_key {
        return key.clone();
    }
    unified_job_key(
        Some(job.request_id.as_str()),
        job,
        job.execution.backend(),
        job.execution.l3_policy(),
    )
}

fn unified_cache_key(spec: &L3JobSpec) -> String {
    unified_key(
        None,
        &spec.text,
        spec.execution.backend(),
        spec.execution.l3_policy(),
        &spec.l3_candidates,
    )
}

pub(super) fn cache_key_for_job(job: &L3WorkerJob) -> String {
    if let Some(key) = &job.unified_cache_key {
        return key.clone();
    }
    unified_job_key(
        None,
        job,
        job.execution.backend(),
        job.execution.l3_policy(),
    )
}

fn unified_job_key(
    request_id: Option<&str>,
    job: &L3WorkerJob,
    backend: crate::ExecutionBackend,
    policy: &crate::L3SchedulerPolicy,
) -> String {
    let mut hasher = blake3::Hasher::new();
    match &job.input {
        L3WorkerInput::PlannedChunks(chunks) => {
            hasher.update(&(chunks.len() as u64).to_le_bytes());
            for chunk in chunks {
                hasher.update(&chunk.start_byte.to_le_bytes());
                hasher.update(&chunk.end_byte.to_le_bytes());
                hasher.update(chunk.text.as_bytes());
            }
        }
        L3WorkerInput::Text(text) => {
            hasher.update(text.as_bytes());
        }
    }
    update_unified_key(&mut hasher, policy, &job.l3_candidates);
    finalized_unified_key(request_id, backend, hasher)
}

fn unified_key(
    request_id: Option<&str>,
    text: &str,
    backend: crate::ExecutionBackend,
    policy: &crate::L3SchedulerPolicy,
    candidates: &[crate::ml::ntdb_executor::L3Candidate],
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(text.as_bytes());
    update_unified_key(&mut hasher, policy, candidates);
    finalized_unified_key(request_id, backend, hasher)
}

fn update_unified_key(
    hasher: &mut blake3::Hasher,
    policy: &crate::L3SchedulerPolicy,
    candidates: &[crate::ml::ntdb_executor::L3Candidate],
) {
    hasher.update(unified_policy_key(policy).as_bytes());
    for candidate in candidates {
        hasher.update(&candidate.span.start.to_le_bytes());
        hasher.update(&candidate.span.end.to_le_bytes());
        hasher.update(&candidate.promote_score.to_bits().to_le_bytes());
        hasher.update(&candidate.promote_threshold.to_bits().to_le_bytes());
        hasher.update(candidate.source_pipeline.as_bytes());
    }
}

fn finalized_unified_key(
    request_id: Option<&str>,
    backend: crate::ExecutionBackend,
    hasher: blake3::Hasher,
) -> String {
    let hash = hasher.finalize();
    format!(
        "{}{}:{}:{}",
        request_id
            .map(|value| format!("{value}:"))
            .unwrap_or_default(),
        UNIFIED_L3_ASSET.revision,
        backend.as_str(),
        hash.to_hex()
    )
}

fn unified_policy_key(policy: &crate::L3SchedulerPolicy) -> String {
    let base = match (policy.clustering, policy.early_exit) {
        (L3ClusteringStrategy::Disabled, L3EarlyExitMode::Disabled) => "disabled:no_early_exit",
        (L3ClusteringStrategy::Disabled, L3EarlyExitMode::ClassStable) => "disabled:class_stable",
        (L3ClusteringStrategy::RankOnly, L3EarlyExitMode::Disabled) => "rank_only:no_early_exit",
        (L3ClusteringStrategy::RankOnly, L3EarlyExitMode::ClassStable) => "rank_only:class_stable",
        (L3ClusteringStrategy::Representative, L3EarlyExitMode::Disabled) => {
            "representative:no_early_exit"
        }
        (L3ClusteringStrategy::Representative, L3EarlyExitMode::ClassStable) => {
            "representative:class_stable"
        }
        (L3ClusteringStrategy::VerifyRepresentative, L3EarlyExitMode::Disabled) => {
            "verify_representative:no_early_exit"
        }
        (L3ClusteringStrategy::VerifyRepresentative, L3EarlyExitMode::ClassStable) => {
            "verify_representative:class_stable"
        }
    };
    let mut pipeline_keys = policy.pipelines.keys().collect::<Vec<_>>();
    pipeline_keys.sort();
    let pipelines = pipeline_keys
        .into_iter()
        .map(|key| {
            let value = serde_json::to_string(&policy.pipelines[key])
                .expect("L3 pipeline policy must serialize");
            format!("{key}={value}")
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "{base}:reps={}:verify_reps={}:similarity={}:max_cluster={}:pipelines={pipelines}",
        policy.representatives_per_cluster,
        policy.verify_representatives_per_cluster,
        policy.min_cluster_similarity,
        policy.max_cluster_size,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml::ntdb_executor::ByteSpan;
    use crate::{LayerResult, ScanExecution};

    fn head_output(class_name: &str, confidence: f64) -> UnifiedHeadOutput {
        UnifiedHeadOutput {
            class_name: class_name.to_string(),
            confidence,
            label_scores: Vec::new(),
        }
    }

    fn observed_chunk(
        chunk_index: usize,
        allowed_heads: &[&str],
        output_heads: &[(&str, UnifiedHeadOutput)],
    ) -> UnifiedChunkOutput {
        UnifiedChunkOutput {
            chunk_index,
            allowed_heads: allowed_heads
                .iter()
                .map(|head| (*head).to_string())
                .collect(),
            output: UnifiedModelOutput {
                heads: output_heads
                    .iter()
                    .map(|(head, output)| ((*head).to_string(), output.clone()))
                    .collect(),
            },
        }
    }

    #[test]
    fn unified_request_wide_early_exit_skips_lower_priority_subscribers() {
        let run = UnifiedRunResult {
            output: UnifiedModelOutput {
                heads: HashMap::from([
                    (
                        "threat".to_string(),
                        head_output("instruction_override", 0.98),
                    ),
                    ("tool_class".to_string(), head_output("database", 0.8)),
                ]),
            },
            duration_ms: 12.0,
            queue_wait_ms: 1.0,
            chunk_count: 2,
            inferred_chunks: 1,
            propagated_chunks: 0,
            planned_l3_chunks: 2,
            resolved_chunks: 1,
            total_effective_chunks: 2,
            head_early_exits: HashSet::from(["threat".to_string()]),
            resolved_chunks_by_head: HashMap::from([("threat".to_string(), 1)]),
            total_chunks_by_head: HashMap::from([("threat".to_string(), 2)]),
            cache_hits: 0,
            clustering: L3ClusteringStrategy::RankOnly,
            physical_job_id: 7,
            chunk_trace: None,
        };
        let subscribers = vec![
            test_subscriber(2, "threat", 2),
            test_subscriber(1, "tool_class", 8),
        ];

        let outputs = materialize_completed_unified_subscribers(subscribers, &run);

        assert_eq!(outputs[0].0.category, "threat");
        assert_eq!(outputs[0].1.level, "L3");
        assert_eq!(outputs[0].1.class_name, "instruction_override");
        assert_eq!(outputs[1].0.category, "tool_class");
        assert_eq!(outputs[1].1.level, "L2");
        assert!(outputs[1].1.layers.iter().any(|layer| {
            layer.layer_type == "l3_skipped"
                && layer
                    .details
                    .get("skip_reason")
                    .and_then(serde_json::Value::as_str)
                    == Some("request_wide_early_exit")
        }));
    }

    #[test]
    fn unified_subscriber_spec_drops_heavy_shared_request_state() {
        let mut spec = test_subscriber(1, "threat", 2);
        spec.text = Arc::<str>::from("large request text".repeat(1024));
        let shared_text = Arc::clone(&spec.text);
        spec.l3_candidates = vec![crate::ml::ntdb_executor::L3Candidate {
            span: ByteSpan { start: 0, end: 10 },
            promote_score: 0.9,
            promote_threshold: 0.7,
            source_pipeline: "threat".to_string(),
            source_model: "threat".to_string(),
            l2_class: "attack".to_string(),
        }];
        spec.l2_chunk_outputs = vec![crate::ml::ntdb_executor::L2ChunkOutput {
            span: ByteSpan { start: 0, end: 10 },
            class_name: "attack".to_string(),
            confidence: 0.9,
            promoted: true,
            promote_score: Some(0.9),
            promote_threshold: Some(0.7),
            source_pipeline: "threat".to_string(),
            source_model: "threat".to_string(),
            embedding: vec![1.0, 0.0],
            embedding_space: "test-space".to_string(),
        }]
        .into();

        let subscriber = subscriber_spec(spec);

        assert!(Arc::ptr_eq(&subscriber.text, &shared_text));
        assert!(subscriber.l3_candidates.is_empty());
        assert!(subscriber.l2_chunk_outputs.is_empty());
        assert_eq!(subscriber.category, "threat");
        assert_eq!(subscriber.priority, 2);
    }

    fn test_subscriber(job_id: u64, category: &str, priority: usize) -> L3JobSpec {
        L3JobSpec {
            job_id,
            request_id: "rq-test".to_string(),
            category: category.to_string(),
            model: UNIFIED_MODEL.to_string(),
            text: "test".into(),
            fallback: SecurityScanResult {
                category: category.to_string(),
                class_name: "benign".to_string(),
                confidence: 0.5,
                level: "L2".to_string(),
                model: category.to_string(),
                duration_ms: 0.0,
                layers: vec![
                    LayerResult {
                        level: "L2".to_string(),
                        layer_type: "ntdb_l2".to_string(),
                        class_name: "benign".to_string(),
                        confidence: 0.5,
                        matched: false,
                        duration_ms: 0.0,
                        thresholds: HashMap::new(),
                        details: HashMap::new(),
                    },
                    LayerResult {
                        level: "L3".to_string(),
                        layer_type: "l3_pending".to_string(),
                        class_name: "benign".to_string(),
                        confidence: 0.0,
                        matched: false,
                        duration_ms: 0.0,
                        thresholds: HashMap::new(),
                        details: HashMap::new(),
                    },
                ],
                internal_l2_chunk_outputs: Vec::new(),
                evidence_spans: Vec::new(),
                label_scores: Vec::new(),
                decision: None,
            },
            priority,
            ttl_ms: 10_000,
            inference_timeout_ms: 10_000,
            execution: ScanExecution::new(SecurityLevel::L3),
            degraded_factor: 0.75,
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new().into(),
            dynamic_pii_config: None,
            dynamic_pii_activated_rules: Vec::new(),
        }
    }

    #[test]
    fn unified_aggregation_ignores_non_promoted_l2_outputs() {
        let outputs = vec![observed_chunk(
            0,
            &["sensitive_document"],
            &[("sensitive_document", head_output("safe", 0.99))],
        )];

        let aggregate = aggregate_unified_outputs(outputs, None).unwrap();

        assert_eq!(
            aggregate
                .heads
                .get("sensitive_document")
                .unwrap()
                .class_name,
            "safe"
        );
    }

    #[test]
    fn unified_aggregation_ignores_heads_on_irrelevant_physical_chunks() {
        let outputs = vec![
            observed_chunk(
                0,
                &["threat"],
                &[
                    ("threat", head_output("benign", 0.8)),
                    ("tool_class", head_output("database", 0.99)),
                ],
            ),
            observed_chunk(
                1,
                &["tool_class"],
                &[("tool_class", head_output("file", 0.8))],
            ),
        ];
        let aggregate = aggregate_unified_outputs(outputs, None).unwrap();

        assert_eq!(
            aggregate.heads.get("tool_class").unwrap().class_name,
            "file"
        );
    }

    #[test]
    fn unified_head_chunk_plan_keeps_per_head_relevance_from_union() {
        let chunks = (0..5)
            .map(|index| crate::pipeline::l3_schedule::SelectedL3Chunk {
                text: format!("chunk-{index}"),
                start_byte: index * 100,
                end_byte: (index + 1) * 100,
                priority: 0.0,
                head_priority: 1,
                source_order: index,
                embedding: vec![1.0, 0.0],
                embedding_space: "test-space".to_string(),
            })
            .collect::<Vec<_>>();
        let candidates = vec![
            crate::ml::ntdb_executor::L3Candidate {
                span: ByteSpan {
                    start: 100,
                    end: 300,
                },
                promote_score: 0.9,
                promote_threshold: 0.7,
                source_pipeline: "threat".to_string(),
                source_model: "threat".to_string(),
                l2_class: "attack".to_string(),
            },
            crate::ml::ntdb_executor::L3Candidate {
                span: ByteSpan { start: 0, end: 400 },
                promote_score: 0.8,
                promote_threshold: 0.7,
                source_pipeline: "tool_class".to_string(),
                source_model: "tool_class".to_string(),
                l2_class: "web".to_string(),
            },
        ];

        let plan = unified_head_chunk_plan(&chunks, &candidates, "tool_class");

        assert_eq!(plan.l3_chunks_by_head.get("threat"), Some(&2));
        assert_eq!(plan.l3_chunks_by_head.get("tool_class"), Some(&4));
        assert!(!plan.heads_by_chunk[0].contains("threat"));
        assert!(plan.heads_by_chunk[1].contains("threat"));
        assert!(plan.heads_by_chunk[1].contains("tool_class"));
        assert!(!plan.heads_by_chunk[4].contains("tool_class"));
    }

    #[test]
    fn unified_physical_chunk_output_is_reused_across_heads() {
        let mut cache = HashMap::new();
        let mut calls = 0usize;

        let (first, first_inferred) = unified_physical_output(&mut cache, 7, || {
            calls += 1;
            Ok("physical-output".to_string())
        })
        .unwrap();
        let (second, second_inferred) = unified_physical_output(&mut cache, 7, || {
            calls += 1;
            Ok("must-not-run".to_string())
        })
        .unwrap();

        assert_eq!(first, second);
        assert!(first_inferred);
        assert!(!second_inferred);
        assert_eq!(calls, 1);
    }

    #[test]
    fn unified_key_includes_l3_policy_and_candidate_threshold() {
        let mut rank_policy = crate::L3SchedulerPolicy::default();
        rank_policy.clustering = L3ClusteringStrategy::RankOnly;
        let mut representative_policy = rank_policy.clone();
        representative_policy.clustering = L3ClusteringStrategy::Representative;
        let candidate = crate::ml::ntdb_executor::L3Candidate {
            span: ByteSpan { start: 0, end: 10 },
            promote_score: 0.9,
            promote_threshold: 0.7,
            source_pipeline: "threat".to_string(),
            source_model: "l2-threat".to_string(),
            l2_class: "promote".to_string(),
        };
        let mut different_threshold = candidate.clone();
        different_threshold.promote_threshold = 0.8;

        let rank_key = unified_key(
            None,
            "same text",
            crate::ExecutionBackend::Auto,
            &rank_policy,
            std::slice::from_ref(&candidate),
        );
        let representative_key = unified_key(
            None,
            "same text",
            crate::ExecutionBackend::Auto,
            &representative_policy,
            std::slice::from_ref(&candidate),
        );
        let threshold_key = unified_key(
            None,
            "same text",
            crate::ExecutionBackend::Auto,
            &rank_policy,
            &[different_threshold],
        );

        assert_ne!(rank_key, representative_key);
        assert_ne!(rank_key, threshold_key);
    }
}
