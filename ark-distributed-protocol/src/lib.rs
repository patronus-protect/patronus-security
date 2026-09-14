// SPDX-License-Identifier: GPL-3.0-only
//! Wire contract shared by an ARK coordinator and its inference workers.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PROTOCOL_VERSION_V1: u16 = 1;
pub const MAX_CONTENT_TOKENS: usize = 254;
pub const MAX_CHUNKS_PER_BATCH: usize = 64;
pub const MAX_TEXT_SEGMENT_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkerBatchRequestV1 {
    pub protocol_version: u16,
    pub parent_request_id: String,
    pub batch_id: String,
    pub attempt_id: String,
    pub tokenizer_fingerprint: String,
    pub model_fingerprint: String,
    pub config_fingerprint: String,
    pub resolved_policy: ResolvedExecutionPolicyV1,
    pub pipelines: Vec<ChunkPipelineRequestV1>,
    pub chunks: Vec<PreparedChunkV1>,
}

impl WorkerBatchRequestV1 {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ProtocolValidationError::UnsupportedVersion(
                self.protocol_version,
            ));
        }
        require_value("parent_request_id", &self.parent_request_id)?;
        require_value("batch_id", &self.batch_id)?;
        require_value("attempt_id", &self.attempt_id)?;
        require_value("tokenizer_fingerprint", &self.tokenizer_fingerprint)?;
        require_value("model_fingerprint", &self.model_fingerprint)?;
        require_value("config_fingerprint", &self.config_fingerprint)?;
        self.resolved_policy.validate()?;
        if self.pipelines.is_empty() {
            return Err(ProtocolValidationError::EmptyPipelines);
        }
        let mut pipeline_ids = HashSet::with_capacity(self.pipelines.len());
        for pipeline in &self.pipelines {
            pipeline.validate()?;
            if !pipeline_ids.insert(&pipeline.pipeline_id) {
                return Err(ProtocolValidationError::DuplicatePipelineId(
                    pipeline.pipeline_id.clone(),
                ));
            }
        }
        if self.chunks.is_empty() {
            return Err(ProtocolValidationError::EmptyChunks);
        }
        if self.chunks.len() > MAX_CHUNKS_PER_BATCH {
            return Err(ProtocolValidationError::TooManyChunks {
                actual: self.chunks.len(),
                maximum: MAX_CHUNKS_PER_BATCH,
            });
        }
        let mut chunk_ids = HashSet::with_capacity(self.chunks.len());
        let mut chunk_indices = HashSet::with_capacity(self.chunks.len());
        let document_chunk_count = self.chunks[0].document_chunk_count;
        for chunk in &self.chunks {
            chunk.validate()?;
            if chunk.document_chunk_count != document_chunk_count {
                return Err(ProtocolValidationError::InconsistentDocumentChunkCount {
                    expected: document_chunk_count,
                    actual: chunk.document_chunk_count,
                });
            }
            if !chunk_ids.insert(&chunk.chunk_id) {
                return Err(ProtocolValidationError::DuplicateChunkId(
                    chunk.chunk_id.clone(),
                ));
            }
            if !chunk_indices.insert(chunk.chunk_index) {
                return Err(ProtocolValidationError::DuplicateChunkIndex(
                    chunk.chunk_index,
                ));
            }
            let mut requested_pipelines = HashSet::new();
            for pipeline_id in &chunk.pipeline_ids {
                if !pipeline_ids.contains(pipeline_id) {
                    return Err(ProtocolValidationError::UnknownChunkPipelineId {
                        chunk_id: chunk.chunk_id.clone(),
                        pipeline_id: pipeline_id.clone(),
                    });
                }
                if !requested_pipelines.insert(pipeline_id) {
                    return Err(ProtocolValidationError::DuplicateChunkPipelineId {
                        chunk_id: chunk.chunk_id.clone(),
                        pipeline_id: pipeline_id.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Fingerprint the resolved request policy independently of batch membership or order.
pub fn config_fingerprint_v1(
    policy: &ResolvedExecutionPolicyV1,
    pipelines: &[ChunkPipelineRequestV1],
) -> String {
    let mut pipelines = pipelines.to_vec();
    pipelines.sort_by(|left, right| left.pipeline_id.cmp(&right.pipeline_id));
    let encoded = serde_json::to_vec(&(policy, pipelines))
        .expect("distributed policy serialization cannot fail");
    format!("{:x}", Sha256::digest(encoded))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedExecutionPolicyV1 {
    pub max_level: String,
    pub scoring_operating_point: String,
    pub decision_threshold_point: String,
    pub l3_strategy: String,
}

impl ResolvedExecutionPolicyV1 {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        require_value("resolved_policy.max_level", &self.max_level)?;
        require_value(
            "resolved_policy.scoring_operating_point",
            &self.scoring_operating_point,
        )?;
        require_value(
            "resolved_policy.decision_threshold_point",
            &self.decision_threshold_point,
        )?;
        require_value("resolved_policy.l3_strategy", &self.l3_strategy)?;
        if !matches!(self.max_level.as_str(), "L2" | "L3") {
            return Err(ProtocolValidationError::InvalidPolicyValue {
                field: "max_level",
                value: self.max_level.clone(),
            });
        }
        if !matches!(
            self.scoring_operating_point.as_str(),
            "best_f1"
                | "best_promote"
                | "ark_api_short_injection_utility"
                | "best_fpr_in_f1"
                | "best_fnr_in_f1"
                | "best_latency_in_f1"
        ) {
            return Err(ProtocolValidationError::InvalidPolicyValue {
                field: "scoring_operating_point",
                value: self.scoring_operating_point.clone(),
            });
        }
        if !matches!(
            self.decision_threshold_point.as_str(),
            "best_f1" | "best_promote" | "best_fpr_in_f1" | "best_fnr_in_f1" | "best_latency_in_f1"
        ) {
            return Err(ProtocolValidationError::InvalidPolicyValue {
                field: "decision_threshold_point",
                value: self.decision_threshold_point.clone(),
            });
        }
        if !matches!(self.l3_strategy.as_str(), "multi" | "dedicated") {
            return Err(ProtocolValidationError::InvalidPolicyValue {
                field: "l3_strategy",
                value: self.l3_strategy.clone(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChunkPipelineRequestV1 {
    pub pipeline_id: String,
    pub category: String,
    pub model_id: String,
    pub run_l3_on_promotion: bool,
}

impl ChunkPipelineRequestV1 {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        require_value("pipeline_id", &self.pipeline_id)?;
        require_value("category", &self.category)?;
        require_value("model_id", &self.model_id)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PreparedChunkV1 {
    pub chunk_id: String,
    pub chunk_index: usize,
    pub document_chunk_count: usize,
    pub byte_span: ByteSpanV1,
    /// Pipeline keys still required for this chunk. Retries may carry a strict subset.
    pub pipeline_ids: Vec<String>,
    pub input: PreparedChunkInputV1,
}

impl PreparedChunkV1 {
    fn validate(&self) -> Result<(), ProtocolValidationError> {
        require_value("chunk_id", &self.chunk_id)?;
        if self.pipeline_ids.is_empty() {
            return Err(ProtocolValidationError::EmptyChunkPipelines(
                self.chunk_id.clone(),
            ));
        }
        if self.document_chunk_count == 0 || self.chunk_index >= self.document_chunk_count {
            return Err(ProtocolValidationError::InvalidChunkPosition {
                chunk_id: self.chunk_id.clone(),
                chunk_index: self.chunk_index,
                chunk_count: self.document_chunk_count,
            });
        }
        if self.byte_span.end < self.byte_span.start {
            return Err(ProtocolValidationError::InvalidByteSpan {
                chunk_id: self.chunk_id.clone(),
                start: self.byte_span.start,
                end: self.byte_span.end,
            });
        }
        match &self.input {
            PreparedChunkInputV1::Pretokenized { token_ids } => {
                if token_ids.len() > MAX_CONTENT_TOKENS {
                    return Err(ProtocolValidationError::TooManyTokens {
                        chunk_id: self.chunk_id.clone(),
                        actual: token_ids.len(),
                        maximum: MAX_CONTENT_TOKENS,
                    });
                }
            }
            PreparedChunkInputV1::TextRequired { text } => {
                if text.len() > MAX_TEXT_SEGMENT_BYTES {
                    return Err(ProtocolValidationError::TextSegmentTooLarge {
                        chunk_id: self.chunk_id.clone(),
                        actual: text.len(),
                        maximum: MAX_TEXT_SEGMENT_BYTES,
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum PreparedChunkInputV1 {
    Pretokenized { token_ids: Vec<u32> },
    TextRequired { text: String },
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ByteSpanV1 {
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkerBatchResponseV1 {
    pub protocol_version: u16,
    pub parent_request_id: String,
    pub batch_id: String,
    pub attempt_id: String,
    #[serde(default)]
    pub timings: WorkerBatchTimingsV1,
    pub results: Vec<ChunkInferenceResultV1>,
    pub failures: Vec<ChunkFailureV1>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WorkerBatchTimingsV1 {
    pub queue_ms: f64,
    pub processing_ms: f64,
}

impl WorkerBatchResponseV1 {
    pub fn validate(&self) -> Result<(), ProtocolValidationError> {
        if self.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(ProtocolValidationError::UnsupportedVersion(
                self.protocol_version,
            ));
        }
        require_value("parent_request_id", &self.parent_request_id)?;
        require_value("batch_id", &self.batch_id)?;
        require_value("attempt_id", &self.attempt_id)?;
        if !self.timings.queue_ms.is_finite()
            || self.timings.queue_ms < 0.0
            || !self.timings.processing_ms.is_finite()
            || self.timings.processing_ms < 0.0
        {
            return Err(ProtocolValidationError::InvalidTiming);
        }
        let mut chunk_ids = HashSet::new();
        let mut chunk_indices = HashSet::new();
        let mut successful_keys = HashSet::new();
        for result in &self.results {
            require_value("result.chunk_id", &result.chunk_id)?;
            if !chunk_ids.insert(result.chunk_id.as_str()) {
                return Err(ProtocolValidationError::DuplicateChunkId(
                    result.chunk_id.clone(),
                ));
            }
            if !chunk_indices.insert(result.chunk_index) {
                return Err(ProtocolValidationError::DuplicateChunkIndex(
                    result.chunk_index,
                ));
            }
            if result.pipelines.is_empty() {
                return Err(ProtocolValidationError::EmptyResultPipelines(
                    result.chunk_id.clone(),
                ));
            }
            let mut pipelines = HashSet::new();
            for pipeline in &result.pipelines {
                require_value("result.pipeline_id", &pipeline.pipeline_id)?;
                require_value("result.task", &pipeline.task)?;
                if pipeline.labels.is_empty() {
                    return Err(ProtocolValidationError::EmptyResultLabels(
                        pipeline.pipeline_id.clone(),
                    ));
                }
                if !pipelines.insert(pipeline.pipeline_id.as_str()) {
                    return Err(ProtocolValidationError::DuplicatePipelineId(
                        pipeline.pipeline_id.clone(),
                    ));
                }
                successful_keys.insert((result.chunk_id.as_str(), pipeline.pipeline_id.as_str()));
                validate_pipeline_result(pipeline)?;
            }
        }
        let mut failure_keys = HashSet::new();
        for failure in &self.failures {
            require_value("failure.chunk_id", &failure.chunk_id)?;
            require_value("failure.code", &failure.code)?;
            require_value("failure.message", &failure.message)?;
            let key = (failure.chunk_id.as_str(), failure.pipeline_id.as_deref());
            if !failure_keys.insert(key) {
                return Err(ProtocolValidationError::DuplicateFailureKey {
                    chunk_id: failure.chunk_id.clone(),
                    pipeline_id: failure.pipeline_id.clone(),
                });
            }
            if failure.pipeline_id.as_deref().is_some_and(|pipeline_id| {
                successful_keys.contains(&(failure.chunk_id.as_str(), pipeline_id))
            }) {
                return Err(ProtocolValidationError::ResultFailureOverlap {
                    chunk_id: failure.chunk_id.clone(),
                    pipeline_id: failure.pipeline_id.clone().unwrap_or_default(),
                });
            }
        }
        Ok(())
    }
}

fn validate_pipeline_result(
    result: &PipelineInferenceResultV1,
) -> Result<(), ProtocolValidationError> {
    if result.l2.class_probabilities.len() != result.labels.len()
        || result.l2.class_probabilities.is_empty()
    {
        return Err(ProtocolValidationError::ProbabilityLabelMismatch(
            result.pipeline_id.clone(),
        ));
    }
    validate_probabilities(
        &result.pipeline_id,
        "l2.class_probabilities",
        &result.l2.class_probabilities,
    )?;
    for (field, value) in [
        ("l2.promote_score", result.l2.promote_score),
        ("l2.promote_threshold", result.l2.promote_threshold),
    ] {
        if value.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
            return Err(ProtocolValidationError::InvalidNumericField {
                pipeline_id: result.pipeline_id.clone(),
                field,
            });
        }
    }
    if result.l2.embedding.iter().any(|value| !value.is_finite()) {
        return Err(ProtocolValidationError::InvalidNumericField {
            pipeline_id: result.pipeline_id.clone(),
            field: "l2.embedding",
        });
    }
    if let Some(l3) = &result.l3 {
        require_value("l3.model_id", &l3.model_id)?;
        require_value("l3.class_name", &l3.class_name)?;
        if !l3.confidence.is_finite() || !(0.0..=1.0).contains(&l3.confidence) {
            return Err(ProtocolValidationError::InvalidNumericField {
                pipeline_id: result.pipeline_id.clone(),
                field: "l3.confidence",
            });
        }
        if l3.class_probabilities.len() != l3.label_scores.len()
            || l3.class_probabilities.is_empty()
        {
            return Err(ProtocolValidationError::ProbabilityLabelMismatch(
                result.pipeline_id.clone(),
            ));
        }
        validate_probabilities(
            &result.pipeline_id,
            "l3.class_probabilities",
            &l3.class_probabilities,
        )?;
        for score in &l3.label_scores {
            require_value("l3.label_scores.label", &score.label)?;
            if !score.confidence.is_finite() || !(0.0..=1.0).contains(&score.confidence) {
                return Err(ProtocolValidationError::InvalidNumericField {
                    pipeline_id: result.pipeline_id.clone(),
                    field: "l3.label_scores.confidence",
                });
            }
        }
    }
    Ok(())
}

fn validate_probabilities(
    pipeline_id: &str,
    field: &'static str,
    probabilities: &[f32],
) -> Result<(), ProtocolValidationError> {
    if probabilities
        .iter()
        .any(|value| !value.is_finite() || !(0.0..=1.0).contains(value))
    {
        Err(ProtocolValidationError::InvalidNumericField {
            pipeline_id: pipeline_id.to_string(),
            field,
        })
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ChunkInferenceResultV1 {
    pub chunk_id: String,
    pub chunk_index: usize,
    pub pipelines: Vec<PipelineInferenceResultV1>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PipelineInferenceResultV1 {
    pub pipeline_id: String,
    pub task: String,
    pub labels: Vec<String>,
    pub l2: L2ChunkInferenceV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l3: Option<L3ChunkInferenceV1>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct L2ChunkInferenceV1 {
    pub class_probabilities: Vec<f32>,
    pub promoted: bool,
    pub promote_score: Option<f32>,
    pub promote_threshold: Option<f32>,
    pub embedding: Vec<f32>,
    pub embedding_space: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct L3ChunkInferenceV1 {
    pub model_id: String,
    pub class_name: String,
    pub confidence: f32,
    pub class_probabilities: Vec<f32>,
    pub label_scores: Vec<LabelScoreV1>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct LabelScoreV1 {
    pub label: String,
    pub confidence: f64,
    pub matched: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ChunkFailureV1 {
    pub chunk_id: String,
    pub chunk_index: usize,
    pub pipeline_id: Option<String>,
    pub code: String,
    pub message: String,
    pub retryable: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProtocolValidationError {
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u16),
    #[error("{0} must not be empty")]
    EmptyValue(&'static str),
    #[error("at least one pipeline is required")]
    EmptyPipelines,
    #[error("invalid resolved policy {field} value {value}")]
    InvalidPolicyValue { field: &'static str, value: String },
    #[error("duplicate pipeline id {0}")]
    DuplicatePipelineId(String),
    #[error("at least one chunk is required")]
    EmptyChunks,
    #[error("batch has {actual} chunks; maximum is {maximum}")]
    TooManyChunks { actual: usize, maximum: usize },
    #[error("duplicate chunk id {0}")]
    DuplicateChunkId(String),
    #[error("duplicate chunk index {0}")]
    DuplicateChunkIndex(usize),
    #[error("chunk {0} does not request any pipelines")]
    EmptyChunkPipelines(String),
    #[error("chunk {chunk_id} references unknown pipeline {pipeline_id}")]
    UnknownChunkPipelineId {
        chunk_id: String,
        pipeline_id: String,
    },
    #[error("chunk {chunk_id} repeats pipeline {pipeline_id}")]
    DuplicateChunkPipelineId {
        chunk_id: String,
        pipeline_id: String,
    },
    #[error("inconsistent document chunk count: expected {expected}, got {actual}")]
    InconsistentDocumentChunkCount { expected: usize, actual: usize },
    #[error("chunk {0} has no successful pipeline results")]
    EmptyResultPipelines(String),
    #[error("pipeline {0} has no result labels")]
    EmptyResultLabels(String),
    #[error("pipeline {0} probability and label lengths do not match")]
    ProbabilityLabelMismatch(String),
    #[error("pipeline {pipeline_id} has invalid numeric field {field}")]
    InvalidNumericField {
        pipeline_id: String,
        field: &'static str,
    },
    #[error("duplicate failure key for chunk {chunk_id}, pipeline {pipeline_id:?}")]
    DuplicateFailureKey {
        chunk_id: String,
        pipeline_id: Option<String>,
    },
    #[error("chunk {chunk_id}, pipeline {pipeline_id} appears as both result and failure")]
    ResultFailureOverlap {
        chunk_id: String,
        pipeline_id: String,
    },
    #[error("worker timings must be finite and non-negative")]
    InvalidTiming,
    #[error("chunk {chunk_id} has invalid position {chunk_index}/{chunk_count}")]
    InvalidChunkPosition {
        chunk_id: String,
        chunk_index: usize,
        chunk_count: usize,
    },
    #[error("chunk {chunk_id} has invalid byte span {start}..{end}")]
    InvalidByteSpan {
        chunk_id: String,
        start: usize,
        end: usize,
    },
    #[error("chunk {chunk_id} has {actual} content tokens; maximum is {maximum}")]
    TooManyTokens {
        chunk_id: String,
        actual: usize,
        maximum: usize,
    },
    #[error("chunk {chunk_id} has a {actual}-byte text segment; maximum is {maximum}")]
    TextSegmentTooLarge {
        chunk_id: String,
        actual: usize,
        maximum: usize,
    },
}

fn require_value(field: &'static str, value: &str) -> Result<(), ProtocolValidationError> {
    if value.trim().is_empty() {
        Err(ProtocolValidationError::EmptyValue(field))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> WorkerBatchRequestV1 {
        WorkerBatchRequestV1 {
            protocol_version: PROTOCOL_VERSION_V1,
            parent_request_id: "request-1".into(),
            batch_id: "batch-1".into(),
            attempt_id: "attempt-1".into(),
            tokenizer_fingerprint: "tokenizer-a".into(),
            model_fingerprint: "models-a".into(),
            config_fingerprint: "config-a".into(),
            resolved_policy: ResolvedExecutionPolicyV1 {
                max_level: "L3".into(),
                scoring_operating_point: "best_f1".into(),
                decision_threshold_point: "best_fpr_in_f1".into(),
                l3_strategy: "multi".into(),
            },
            pipelines: vec![ChunkPipelineRequestV1 {
                pipeline_id: "injection".into(),
                category: "injection".into(),
                model_id: "injection".into(),
                run_l3_on_promotion: true,
            }],
            chunks: vec![PreparedChunkV1 {
                chunk_id: "chunk-0".into(),
                chunk_index: 0,
                document_chunk_count: 1,
                byte_span: ByteSpanV1 { start: 0, end: 4 },
                pipeline_ids: vec!["injection".into()],
                input: PreparedChunkInputV1::Pretokenized {
                    token_ids: vec![10, 11],
                },
            }],
        }
    }

    #[test]
    fn request_json_round_trip_and_validation() {
        let expected = request();
        let encoded = serde_json::to_string(&expected).unwrap();
        let decoded: WorkerBatchRequestV1 = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded, expected);
        decoded.validate().unwrap();
    }

    #[test]
    fn rejects_unknown_version_duplicate_chunks_and_oversized_chunks() {
        let mut invalid = request();
        invalid.protocol_version = 2;
        assert_eq!(
            invalid.validate(),
            Err(ProtocolValidationError::UnsupportedVersion(2))
        );

        let mut invalid = request();
        invalid.chunks.push(invalid.chunks[0].clone());
        assert_eq!(
            invalid.validate(),
            Err(ProtocolValidationError::DuplicateChunkId("chunk-0".into()))
        );

        let mut invalid = request();
        invalid.chunks[0].input = PreparedChunkInputV1::Pretokenized {
            token_ids: vec![7; MAX_CONTENT_TOKENS + 1],
        };
        assert!(matches!(
            invalid.validate(),
            Err(ProtocolValidationError::TooManyTokens { .. })
        ));
    }

    #[test]
    fn serde_rejects_unknown_fields() {
        let mut json = serde_json::to_value(request()).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("future_field".into(), serde_json::json!(true));
        assert!(serde_json::from_value::<WorkerBatchRequestV1>(json).is_err());
    }

    #[test]
    fn config_fingerprint_is_stable_across_pipeline_order() {
        let request = request();
        let mut pipelines = request.pipelines.clone();
        pipelines.push(ChunkPipelineRequestV1 {
            pipeline_id: "threat".into(),
            category: "threat".into(),
            model_id: "threat".into(),
            run_l3_on_promotion: true,
        });
        let expected = config_fingerprint_v1(&request.resolved_policy, &pipelines);
        pipelines.reverse();
        assert_eq!(
            config_fingerprint_v1(&request.resolved_policy, &pipelines),
            expected
        );
    }

    #[test]
    fn scoring_and_decision_operating_points_are_independent() {
        let request = request();
        let original = config_fingerprint_v1(&request.resolved_policy, &request.pipelines);
        let mut decision_changed = request.resolved_policy.clone();
        decision_changed.decision_threshold_point = "best_fnr_in_f1".into();

        assert_eq!(request.resolved_policy.scoring_operating_point, "best_f1");
        assert_ne!(
            config_fingerprint_v1(&decision_changed, &request.pipelines),
            original
        );
        decision_changed.validate().unwrap();
    }

    #[test]
    fn response_validation_rejects_duplicate_chunk_results() {
        let result = ChunkInferenceResultV1 {
            chunk_id: "chunk-0".into(),
            chunk_index: 0,
            pipelines: vec![PipelineInferenceResultV1 {
                pipeline_id: "injection".into(),
                task: "binary".into(),
                labels: vec!["benign".into(), "injection".into()],
                l2: L2ChunkInferenceV1 {
                    class_probabilities: vec![0.9, 0.1],
                    promoted: false,
                    promote_score: Some(0.1),
                    promote_threshold: Some(0.8),
                    embedding: vec![0.0],
                    embedding_space: "encoder-a".into(),
                },
                l3: None,
            }],
        };
        let mut response = WorkerBatchResponseV1 {
            protocol_version: PROTOCOL_VERSION_V1,
            parent_request_id: "request-1".into(),
            batch_id: "batch-1".into(),
            attempt_id: "attempt-1".into(),
            timings: WorkerBatchTimingsV1::default(),
            results: vec![result.clone()],
            failures: Vec::new(),
        };
        response.validate().unwrap();
        response.results.push(result);
        assert_eq!(
            response.validate(),
            Err(ProtocolValidationError::DuplicateChunkId("chunk-0".into()))
        );
    }

    #[test]
    fn response_validation_rejects_invalid_worker_timings() {
        let mut response = WorkerBatchResponseV1 {
            protocol_version: PROTOCOL_VERSION_V1,
            parent_request_id: "request-1".into(),
            batch_id: "batch-1".into(),
            attempt_id: "attempt-1".into(),
            timings: WorkerBatchTimingsV1 {
                queue_ms: -1.0,
                processing_ms: 1.0,
            },
            results: Vec::new(),
            failures: Vec::new(),
        };
        assert_eq!(
            response.validate(),
            Err(ProtocolValidationError::InvalidTiming)
        );
        response.timings.queue_ms = f64::NAN;
        assert_eq!(
            response.validate(),
            Err(ProtocolValidationError::InvalidTiming)
        );
        response.timings.queue_ms = 0.0;
        response.timings.processing_ms = f64::INFINITY;
        assert_eq!(
            response.validate(),
            Err(ProtocolValidationError::InvalidTiming)
        );
    }

    #[test]
    fn response_validation_rejects_result_failure_overlap_and_invalid_scores() {
        let mut response = WorkerBatchResponseV1 {
            protocol_version: PROTOCOL_VERSION_V1,
            parent_request_id: "request-1".into(),
            batch_id: "batch-1".into(),
            attempt_id: "attempt-1".into(),
            timings: WorkerBatchTimingsV1::default(),
            results: vec![ChunkInferenceResultV1 {
                chunk_id: "chunk-0".into(),
                chunk_index: 0,
                pipelines: vec![PipelineInferenceResultV1 {
                    pipeline_id: "injection".into(),
                    task: "binary".into(),
                    labels: vec!["benign".into(), "injection".into()],
                    l2: L2ChunkInferenceV1 {
                        class_probabilities: vec![0.9, 0.1],
                        promoted: false,
                        promote_score: Some(0.1),
                        promote_threshold: Some(0.8),
                        embedding: vec![0.0],
                        embedding_space: "encoder-a".into(),
                    },
                    l3: None,
                }],
            }],
            failures: vec![ChunkFailureV1 {
                chunk_id: "chunk-0".into(),
                chunk_index: 0,
                pipeline_id: Some("injection".into()),
                code: "failed".into(),
                message: "failed".into(),
                retryable: false,
            }],
        };
        assert!(matches!(
            response.validate(),
            Err(ProtocolValidationError::ResultFailureOverlap { .. })
        ));
        response.failures.clear();
        response.results[0].pipelines[0].l2.class_probabilities[0] = f32::NAN;
        assert!(matches!(
            response.validate(),
            Err(ProtocolValidationError::InvalidNumericField { .. })
        ));
    }
}
