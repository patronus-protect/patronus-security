// SPDX-License-Identifier: GPL-3.0-only
use std::{
    collections::{HashMap, HashSet},
    time::Instant,
};

use ark_distributed_protocol::{
    config_fingerprint_v1, ChunkFailureV1, ChunkInferenceResultV1, L2ChunkInferenceV1,
    L3ChunkInferenceV1, LabelScoreV1, PipelineInferenceResultV1, PreparedChunkInputV1,
    WorkerBatchRequestV1, WorkerBatchResponseV1, WorkerBatchTimingsV1, PROTOCOL_VERSION_V1,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use patronus_ark::ml::ntdb_executor::{ByteSpan, NtdbModelChunkInferences, PreparedNtdbChunk};
use patronus_ark::{L3Strategy, NtdbOperatingPoint, ScanExecution, SecurityCategory};
use serde_json::json;

use crate::auth::AuthenticatedKey;
use crate::state::AppState;

pub async fn infer_batch(
    State(state): State<AppState>,
    Extension(AuthenticatedKey(key)): Extension<AuthenticatedKey>,
    Json(request): Json<WorkerBatchRequestV1>,
) -> Response {
    let received_at = Instant::now();
    if let Err(error) = request.validate() {
        return error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request", error);
    }
    if let Err(error) = validate_request_compatibility(&state, &key, &request) {
        return error_response(StatusCode::CONFLICT, "incompatible_worker", error);
    }

    let (permit, job_guard) = match state.try_begin_distributed_inference() {
        Ok(admission) => admission,
        Err(_) => {
            return error_response(
                StatusCode::TOO_MANY_REQUESTS,
                "worker_busy",
                "worker inference capacity exhausted",
            )
        }
    };

    let parent_request_id = request.parent_request_id.clone();
    let batch_id = request.batch_id.clone();
    let attempt_id = request.attempt_id.clone();
    tracing::info!(
        parent_request_id,
        batch_id,
        attempt_id,
        chunks = request.chunks.len(),
        pipelines = request.pipelines.len(),
        "distributed worker batch started"
    );

    let inference_state = state.clone();
    let response = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let _job_guard = job_guard;
        let queue_ms = received_at.elapsed().as_secs_f64() * 1_000.0;
        let processing_started = Instant::now();
        let mut response = infer_batch_blocking(&inference_state, request)?;
        response.timings = WorkerBatchTimingsV1 {
            queue_ms,
            processing_ms: processing_started.elapsed().as_secs_f64() * 1_000.0,
        };
        Ok(response)
    })
    .await
    .unwrap_or_else(|error| {
        Err(format!(
            "distributed inference task failed to join: {error}"
        ))
    });

    match response {
        Ok(response) => {
            tracing::info!(
                parent_request_id,
                batch_id,
                attempt_id,
                results = response.results.len(),
                failures = response.failures.len(),
                "distributed worker batch finished"
            );
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(error) => {
            tracing::warn!(
                parent_request_id,
                batch_id,
                attempt_id,
                error = %error,
                "distributed worker batch failed"
            );
            error_response(StatusCode::INTERNAL_SERVER_ERROR, "inference_failed", error)
        }
    }
}

fn validate_request_compatibility(
    state: &AppState,
    key: &crate::config::ApiKeyConfig,
    request: &WorkerBatchRequestV1,
) -> Result<(), String> {
    let expected_config = config_fingerprint_v1(&request.resolved_policy, &request.pipelines);
    if request.config_fingerprint != expected_config {
        return Err("resolved config fingerprint mismatch".to_string());
    }
    let (tokenizer_fingerprint, model_fingerprint) =
        state.gateway.distributed_ntdb_fingerprints()?;
    if request.tokenizer_fingerprint != tokenizer_fingerprint {
        return Err("tokenizer fingerprint mismatch".to_string());
    }
    if request.model_fingerprint != model_fingerprint {
        return Err("model fingerprint mismatch".to_string());
    }
    validate_execution_policy(request, state.gateway.l3_strategy().as_str())?;
    let execution = execution_from_policy(state, request)?;
    let mut categories = Vec::new();
    for pipeline in &request.pipelines {
        let category = pipeline
            .category
            .parse::<SecurityCategory>()
            .map_err(|error| format!("unknown category '{}': {error}", pipeline.category))?;
        if !state.config.categories.contains(&category) {
            return Err(format!(
                "category '{}' is not configured on this worker",
                pipeline.category
            ));
        }
        if key
            .allowed_categories
            .as_ref()
            .is_some_and(|allowed| !allowed.contains(&category))
        {
            return Err(format!(
                "category '{}' is not permitted for this API key",
                pipeline.category
            ));
        }
        if !categories.contains(&category) {
            categories.push(category);
        }
    }
    let canonical = state
        .gateway
        .distributed_l2_pipelines(&categories, &execution);
    validate_pipeline_bindings(request, &canonical)?;
    Ok(())
}

fn validate_pipeline_bindings(
    request: &WorkerBatchRequestV1,
    canonical: &[patronus_ark::pipeline::DistributedL2Pipeline],
) -> Result<(), String> {
    for requested in &request.pipelines {
        let Some(config) = canonical.iter().find(|config| {
            config.pipeline_id == requested.pipeline_id
                && config.category.as_str() == requested.category
                && config.model_id == requested.model_id
        }) else {
            return Err(format!(
                "pipeline '{}' does not match a canonical {} model configuration",
                requested.pipeline_id, requested.category
            ));
        };
        if requested.run_l3_on_promotion
            && (!config.has_l3 || request.resolved_policy.max_level != "L3")
        {
            return Err(format!(
                "pipeline '{}' is not eligible for immediate L3",
                requested.pipeline_id
            ));
        }
    }
    Ok(())
}

fn execution_from_policy(
    state: &AppState,
    request: &WorkerBatchRequestV1,
) -> Result<ScanExecution, String> {
    let scoring_operating_point = request
        .resolved_policy
        .scoring_operating_point
        .parse::<NtdbOperatingPoint>()?;
    let decision_threshold_point = request
        .resolved_policy
        .decision_threshold_point
        .parse::<NtdbOperatingPoint>()?;
    let mut execution = state.gateway.distributed_execution();
    execution.set_ntdb_operating_point(scoring_operating_point);
    execution.set_ntdb_decision_threshold_point(decision_threshold_point);
    execution.set_l3_strategy(request.resolved_policy.l3_strategy.parse::<L3Strategy>()?);
    Ok(execution)
}

fn validate_execution_policy(
    request: &WorkerBatchRequestV1,
    worker_l3_strategy: &str,
) -> Result<(), String> {
    if request.resolved_policy.l3_strategy != worker_l3_strategy {
        return Err("L3 strategy mismatch".to_string());
    }
    if request
        .pipelines
        .iter()
        .any(|pipeline| pipeline.run_l3_on_promotion)
        && (request.resolved_policy.max_level != "L3"
            || request.resolved_policy.l3_strategy != "multi")
    {
        return Err("immediate L3 requires max_level L3 and the multi strategy".to_string());
    }
    Ok(())
}

fn infer_batch_blocking(
    state: &AppState,
    mut request: WorkerBatchRequestV1,
) -> Result<WorkerBatchResponseV1, String> {
    let execution = execution_from_policy(state, &request)?;
    let scoring_operating_point = execution.ntdb_operating_point();
    let model_ids = request
        .pipelines
        .iter()
        .filter(|pipeline| {
            request
                .chunks
                .iter()
                .any(|chunk| chunk.pipeline_ids.contains(&pipeline.pipeline_id))
        })
        .map(|pipeline| pipeline.model_id.clone())
        .collect::<HashSet<_>>();
    let mut prepared = Vec::new();
    let mut failures = Vec::new();
    let mut chunk_ids = HashMap::new();
    for chunk in &mut request.chunks {
        chunk_ids.insert(chunk.chunk_index, chunk.chunk_id.clone());
        match &mut chunk.input {
            PreparedChunkInputV1::Pretokenized { token_ids } => {
                prepared.push(PreparedNtdbChunk {
                    chunk_index: chunk.chunk_index,
                    span: ByteSpan {
                        start: chunk.byte_span.start,
                        end: chunk.byte_span.end,
                    },
                    token_ids: std::mem::take(token_ids),
                });
            }
            PreparedChunkInputV1::TextRequired { .. } => {
                failures.extend(chunk.pipeline_ids.iter().map(|pipeline_id| ChunkFailureV1 {
                    chunk_id: chunk.chunk_id.clone(),
                    chunk_index: chunk.chunk_index,
                    pipeline_id: Some(pipeline_id.clone()),
                    code: "text_pipeline_unsupported".to_string(),
                    message:
                        "this worker batch contains only pre-tokenized NTDB pipelines".to_string(),
                    retryable: false,
                }));
            }
        }
    }

    let requested_chunks = request
        .chunks
        .iter()
        .map(|chunk| (chunk.chunk_index, chunk))
        .collect::<HashMap<_, _>>();

    let mut inferred = Vec::new();
    if !prepared.is_empty() {
        match state.gateway.infer_distributed_ntdb_chunks(
            model_ids.clone(),
            &prepared,
            request.chunks[0].document_chunk_count,
            scoring_operating_point,
        ) {
            Ok(outputs) => inferred = outputs,
            Err(batch_error) => {
                // Preserve healthy chunks after a data-dependent failure without penalizing
                // the normal batched path.
                for chunk in &prepared {
                    match state.gateway.infer_distributed_ntdb_chunks(
                        model_ids.clone(),
                        std::slice::from_ref(chunk),
                        request.chunks[0].document_chunk_count,
                        scoring_operating_point,
                    ) {
                        Ok(outputs) => merge_model_outputs(&mut inferred, outputs),
                        Err(error) => {
                            let requested = requested_chunks
                                .get(&chunk.chunk_index)
                                .expect("validated prepared chunk must have request metadata");
                            failures.extend(requested.pipeline_ids.iter().map(|pipeline_id| {
                                ChunkFailureV1 {
                                    chunk_id: chunk_ids
                                        .get(&chunk.chunk_index)
                                        .cloned()
                                        .unwrap_or_default(),
                                    chunk_index: chunk.chunk_index,
                                    pipeline_id: Some(pipeline_id.clone()),
                                    code: "chunk_inference_failed".to_string(),
                                    message: format!("{error}; batch error: {batch_error}"),
                                    retryable: false,
                                }
                            }));
                        }
                    }
                }
            }
        }
    }

    let mut results = request
        .chunks
        .iter()
        .filter(|chunk| matches!(chunk.input, PreparedChunkInputV1::Pretokenized { .. }))
        .map(|chunk| ChunkInferenceResultV1 {
            chunk_id: chunk.chunk_id.clone(),
            chunk_index: chunk.chunk_index,
            pipelines: Vec::new(),
        })
        .collect::<Vec<_>>();
    let result_positions = results
        .iter()
        .enumerate()
        .map(|(position, result)| (result.chunk_index, position))
        .collect::<HashMap<_, _>>();
    let by_model = inferred
        .iter()
        .map(|model| (model.model_id.as_str(), model))
        .collect::<HashMap<_, _>>();
    let mut promoted_for_l3 = HashMap::new();
    for pipeline in request
        .pipelines
        .iter()
        .filter(|pipeline| pipeline.run_l3_on_promotion)
    {
        if let Some(model) = by_model.get(pipeline.model_id.as_str()) {
            for chunk in model
                .chunks
                .iter()
                .filter(|chunk| chunk.promote_score >= chunk.promote_threshold)
                .filter(|chunk| {
                    chunk_requests_pipeline(
                        &requested_chunks,
                        chunk.chunk_index,
                        &pipeline.pipeline_id,
                    )
                })
            {
                promoted_for_l3
                    .entry(chunk.chunk_index)
                    .or_insert_with(|| chunk.clone());
            }
        }
    }
    let l3_outputs = if promoted_for_l3.is_empty() {
        Ok(Vec::new())
    } else {
        state.gateway.infer_distributed_unified_l3_chunks(
            &promoted_for_l3.into_values().collect::<Vec<_>>(),
            &execution,
        )
    };
    let l3_by_index = l3_outputs
        .as_ref()
        .map(|outputs| {
            outputs
                .iter()
                .map(|output| (output.chunk_index, output))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    for pipeline in &request.pipelines {
        let Some(model) = by_model.get(pipeline.model_id.as_str()) else {
            for result in results.iter().filter(|result| {
                chunk_requests_pipeline(
                    &requested_chunks,
                    result.chunk_index,
                    &pipeline.pipeline_id,
                )
            }) {
                failures.push(ChunkFailureV1 {
                    chunk_id: result.chunk_id.clone(),
                    chunk_index: result.chunk_index,
                    pipeline_id: Some(pipeline.pipeline_id.clone()),
                    code: "model_not_loaded".to_string(),
                    message: format!("model '{}' is not loaded", pipeline.model_id),
                    retryable: false,
                });
            }
            continue;
        };
        for chunk in &model.chunks {
            if !chunk_requests_pipeline(&requested_chunks, chunk.chunk_index, &pipeline.pipeline_id)
            {
                continue;
            }
            let Some(&position) = result_positions.get(&chunk.chunk_index) else {
                continue;
            };
            let result = &mut results[position];
            let promoted = chunk.promote_score >= chunk.promote_threshold;
            let head = l3_by_index
                .get(&chunk.chunk_index)
                .and_then(|output| output.output.heads.get(&pipeline.category));
            let l3 = match resolve_l3_result(
                promoted,
                pipeline.run_l3_on_promotion,
                &pipeline.category,
                head,
                l3_outputs.as_ref().err().map(String::as_str),
            ) {
                Ok(l3) => l3,
                Err((code, message)) => {
                    failures.push(ChunkFailureV1 {
                        chunk_id: result.chunk_id.clone(),
                        chunk_index: result.chunk_index,
                        pipeline_id: Some(pipeline.pipeline_id.clone()),
                        code: code.to_string(),
                        message,
                        retryable: false,
                    });
                    continue;
                }
            };
            result.pipelines.push(PipelineInferenceResultV1 {
                pipeline_id: pipeline.pipeline_id.clone(),
                task: model.task.clone(),
                labels: model.labels.clone(),
                l2: L2ChunkInferenceV1 {
                    class_probabilities: chunk.class_probabilities.clone(),
                    promoted,
                    promote_score: Some(chunk.promote_score),
                    promote_threshold: Some(chunk.promote_threshold),
                    embedding: chunk.embedding.clone(),
                    embedding_space: chunk.embedding_space.clone(),
                },
                l3,
            });
        }
    }
    results.retain(|result| !result.pipelines.is_empty());

    let response = WorkerBatchResponseV1 {
        protocol_version: PROTOCOL_VERSION_V1,
        parent_request_id: request.parent_request_id,
        batch_id: request.batch_id,
        attempt_id: request.attempt_id,
        timings: WorkerBatchTimingsV1::default(),
        results,
        failures,
    };
    response.validate().map_err(|error| error.to_string())?;
    Ok(response)
}

fn merge_model_outputs(
    target: &mut Vec<NtdbModelChunkInferences>,
    outputs: Vec<NtdbModelChunkInferences>,
) {
    for output in outputs {
        if let Some(existing) = target
            .iter_mut()
            .find(|existing| existing.model_id == output.model_id)
        {
            existing.chunks.extend(output.chunks);
        } else {
            target.push(output);
        }
    }
}

fn chunk_requests_pipeline(
    chunks: &HashMap<usize, &ark_distributed_protocol::PreparedChunkV1>,
    chunk_index: usize,
    pipeline_id: &str,
) -> bool {
    chunks.get(&chunk_index).is_some_and(|chunk| {
        chunk
            .pipeline_ids
            .iter()
            .any(|requested| requested == pipeline_id)
    })
}

fn resolve_l3_result(
    promoted: bool,
    run_l3_on_promotion: bool,
    category: &str,
    head: Option<&patronus_ark::ml::unified_onnx::UnifiedHeadOutput>,
    inference_error: Option<&str>,
) -> Result<Option<L3ChunkInferenceV1>, (&'static str, String)> {
    if !promoted || !run_l3_on_promotion {
        return Ok(None);
    }
    if let Some(error) = inference_error {
        return Err(("l3_inference_failed", error.to_string()));
    }
    let head = head.ok_or_else(|| {
        (
            "l3_head_missing",
            format!("unified L3 response is missing head '{category}'"),
        )
    })?;
    Ok(Some(L3ChunkInferenceV1 {
        model_id: patronus_ark::ml::unified_onnx::UNIFIED_MODEL.to_string(),
        class_name: head.class_name.clone(),
        confidence: head.confidence as f32,
        class_probabilities: head
            .label_scores
            .iter()
            .map(|score| score.confidence as f32)
            .collect(),
        label_scores: head
            .label_scores
            .iter()
            .map(|score| LabelScoreV1 {
                label: score.label.clone(),
                confidence: score.confidence,
                matched: score.matched,
            })
            .collect(),
    }))
}

fn error_response(
    status: StatusCode,
    code: &'static str,
    error: impl std::fmt::Display,
) -> Response {
    (
        status,
        Json(json!({ "error": { "code": code, "message": error.to_string() } })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use ark_distributed_protocol::{
        ByteSpanV1, ChunkPipelineRequestV1, PreparedChunkV1, ResolvedExecutionPolicyV1,
    };

    use super::*;
    use patronus_ark::{pipeline::DistributedL2Pipeline, LabelScore};

    fn request() -> WorkerBatchRequestV1 {
        let pipelines = vec![ChunkPipelineRequestV1 {
            pipeline_id: "injection".into(),
            category: "injection".into(),
            model_id: "injection".into(),
            run_l3_on_promotion: true,
        }];
        let policy = ResolvedExecutionPolicyV1 {
            max_level: "L3".into(),
            scoring_operating_point: "best_promote".into(),
            decision_threshold_point: "best_f1".into(),
            l3_strategy: "multi".into(),
        };
        WorkerBatchRequestV1 {
            protocol_version: PROTOCOL_VERSION_V1,
            parent_request_id: "request".into(),
            batch_id: "batch".into(),
            attempt_id: "attempt".into(),
            tokenizer_fingerprint: "tokenizer".into(),
            model_fingerprint: "models".into(),
            config_fingerprint: config_fingerprint_v1(&policy, &pipelines),
            resolved_policy: policy,
            pipelines,
            chunks: vec![PreparedChunkV1 {
                chunk_id: "chunk".into(),
                chunk_index: 0,
                document_chunk_count: 1,
                byte_span: ByteSpanV1 { start: 0, end: 1 },
                pipeline_ids: vec!["injection".into()],
                input: PreparedChunkInputV1::Pretokenized { token_ids: vec![1] },
            }],
        }
    }

    #[test]
    fn route_policy_requires_matching_multi_l3_worker() {
        let request = request();
        assert!(validate_execution_policy(&request, "multi").is_ok());
        assert_eq!(
            validate_execution_policy(&request, "dedicated").unwrap_err(),
            "L3 strategy mismatch"
        );
    }

    #[test]
    fn route_policy_rejects_l3_work_at_l2() {
        let mut request = request();
        request.resolved_policy.max_level = "L2".into();
        assert!(validate_execution_policy(&request, "multi").is_err());
    }

    #[test]
    fn canonical_binding_rejects_cross_category_model_spoofing() {
        let canonical = vec![DistributedL2Pipeline {
            pipeline_id: "injection".into(),
            category: SecurityCategory::Injection,
            model_id: "injection".into(),
            public_model: "wolf-defender-small".into(),
            has_l3: true,
        }];
        let mut request = request();
        assert!(validate_pipeline_bindings(&request, &canonical).is_ok());
        request.pipelines[0].category = "threat".into();
        assert!(validate_pipeline_bindings(&request, &canonical).is_err());
        request.pipelines[0].category = "injection".into();
        request.pipelines[0].model_id = "threat".into();
        assert!(validate_pipeline_bindings(&request, &canonical).is_err());
        request.pipelines[0].model_id = "injection".into();
        request.pipelines[0].pipeline_id = "threat".into();
        assert!(validate_pipeline_bindings(&request, &canonical).is_err());
    }

    #[test]
    fn heterogeneous_retry_chunks_select_only_missing_pipeline_keys() {
        let mut request = request();
        request.pipelines.push(ChunkPipelineRequestV1 {
            pipeline_id: "threat".into(),
            category: "threat".into(),
            model_id: "threat".into(),
            run_l3_on_promotion: true,
        });
        request.chunks[0].pipeline_ids = vec!["threat".into()];
        let chunks = request
            .chunks
            .iter()
            .map(|chunk| (chunk.chunk_index, chunk))
            .collect();
        assert!(!chunk_requests_pipeline(&chunks, 0, "injection"));
        assert!(chunk_requests_pipeline(&chunks, 0, "threat"));
    }

    #[test]
    fn sparse_unordered_chunk_indices_keep_pipeline_assignments() {
        let mut request = request();
        request.chunks[0].chunk_index = 800;
        let mut other = request.chunks[0].clone();
        other.chunk_index = 4;
        other.pipeline_ids = vec!["threat".into()];
        request.chunks.push(other);
        let chunks = request
            .chunks
            .iter()
            .map(|chunk| (chunk.chunk_index, chunk))
            .collect();
        assert!(chunk_requests_pipeline(&chunks, 800, "injection"));
        assert!(!chunk_requests_pipeline(&chunks, 4, "injection"));
        assert!(chunk_requests_pipeline(&chunks, 4, "threat"));
        assert!(!chunk_requests_pipeline(&chunks, 0, "threat"));
    }

    #[test]
    fn promoted_l3_success_is_lossless_and_failure_has_no_success_value() {
        let head = patronus_ark::ml::unified_onnx::UnifiedHeadOutput {
            class_name: "injection".into(),
            confidence: 0.9,
            label_scores: vec![
                LabelScore {
                    label: "benign".into(),
                    confidence: 0.1,
                    matched: false,
                },
                LabelScore {
                    label: "injection".into(),
                    confidence: 0.9,
                    matched: true,
                },
            ],
        };
        let success = resolve_l3_result(true, true, "injection", Some(&head), None)
            .unwrap()
            .unwrap();
        assert_eq!(success.label_scores.len(), 2);
        assert!(success.label_scores[1].matched);

        let failure = resolve_l3_result(true, true, "injection", None, Some("model failed"));
        assert_eq!(failure.unwrap_err().0, "l3_inference_failed");
    }
}
