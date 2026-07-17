// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::HashMap;
use std::sync::{mpsc, Arc};
use std::thread;
use std::time::{Duration, Instant};

use crate::ml::ntdb_executor::ByteSpan;
use crate::ml::onnx::TokenTextChunk;
use crate::{EvaluationResult, LayerResult, RequestId, SecurityLevel, SecurityScanResult};

use super::super::long_text::aggregate_chunk_outputs;
use super::super::{
    degraded_error_result, degraded_timeout_result, l3_metadata_layer, PipelineStrategy,
};
use super::{
    elapsed_ms, DynamicPiiHandle, L3ModelHandle, L3WorkerJob, L3WorkerState, L3_OVERLAP_TOKENS,
};
use crate::pipeline::decision_cache::DecisionCache;

pub(super) fn execute(
    state: &L3WorkerState,
    job: L3WorkerJob,
) -> (u64, RequestId, SecurityScanResult) {
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

#[cfg(feature = "test-util")]
#[doc(hidden)]
pub fn selected_l3_chunks_for_test(
    chunks: &[(usize, usize, &str)],
    candidate_spans: &[ByteSpan],
) -> Vec<String> {
    selected_l3_chunks(
        chunks
            .iter()
            .map(|(start_byte, end_byte, text)| TokenTextChunk {
                start_byte: *start_byte,
                end_byte: *end_byte,
                text: (*text).to_string(),
            })
            .collect(),
        candidate_spans,
    )
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
