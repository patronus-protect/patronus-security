//! JSON wire types mirroring `docs/reference/result-schema.md`.
//!
//! `patronus_ark::SecurityScanResult` and friends intentionally do not derive
//! `Serialize` (see the Python bindings, which build dictionaries by hand for
//! the same reason). These DTOs are the API's one conversion point.

use std::collections::HashMap;

use patronus_ark::{
    DecisionEnvelope, EvidenceSpan, LabelScore, LayerResult, QueuedSecurityScanResult,
    SecurityFailure, SecurityRequestCompletion, SecurityScanResult,
};
use serde::Serialize;

#[derive(Serialize)]
pub struct ScanResultDto {
    pub category: String,
    pub class_name: String,
    pub confidence: f64,
    pub level: String,
    pub model: String,
    pub duration_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionEnvelope>,
    pub evidence_spans: Vec<EvidenceSpanDto>,
    pub label_scores: Vec<LabelScoreDto>,
    pub layers: Vec<LayerResultDto>,
}

#[derive(Serialize)]
pub struct LayerResultDto {
    pub level: String,
    pub layer_type: String,
    pub class_name: String,
    pub confidence: f64,
    pub matched: bool,
    pub duration_ms: f64,
    pub thresholds: HashMap<String, f64>,
    pub details: HashMap<String, serde_json::Value>,
}

#[derive(Serialize)]
pub struct LabelScoreDto {
    pub label: String,
    pub confidence: f64,
    pub matched: bool,
}

#[derive(Serialize)]
pub struct EvidenceSpanDto {
    pub label: String,
    pub text: String,
    pub score: f64,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_char: usize,
    pub end_char: usize,
}

#[derive(Serialize)]
pub struct QueuedScanResultDto {
    pub request_id: String,
    #[serde(flatten)]
    pub result: ScanResultDto,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum CompletionDto {
    Complete,
    Degraded { failures: Vec<FailureDto> },
    Failed { failures: Vec<FailureDto> },
}

#[derive(Serialize)]
pub struct FailureDto {
    pub stage: String,
    pub level: Option<String>,
    pub detector_id: Option<String>,
    pub kind: String,
    pub retryable: bool,
    pub message: String,
}

impl From<SecurityScanResult> for ScanResultDto {
    fn from(result: SecurityScanResult) -> Self {
        Self {
            category: result.category,
            class_name: result.class_name,
            confidence: result.confidence,
            level: result.level,
            model: result.model,
            duration_ms: result.duration_ms,
            decision: result.decision,
            evidence_spans: result.evidence_spans.into_iter().map(Into::into).collect(),
            label_scores: result.label_scores.into_iter().map(Into::into).collect(),
            layers: result.layers.into_iter().map(Into::into).collect(),
        }
    }
}

impl From<LayerResult> for LayerResultDto {
    fn from(layer: LayerResult) -> Self {
        Self {
            level: layer.level,
            layer_type: layer.layer_type,
            class_name: layer.class_name,
            confidence: layer.confidence,
            matched: layer.matched,
            duration_ms: layer.duration_ms,
            thresholds: layer.thresholds,
            details: layer.details,
        }
    }
}

impl From<LabelScore> for LabelScoreDto {
    fn from(score: LabelScore) -> Self {
        Self {
            label: score.label,
            confidence: score.confidence,
            matched: score.matched,
        }
    }
}

impl From<EvidenceSpan> for EvidenceSpanDto {
    fn from(span: EvidenceSpan) -> Self {
        Self {
            label: span.label,
            text: span.text,
            score: span.score,
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_char: span.start_char,
            end_char: span.end_char,
        }
    }
}

impl From<QueuedSecurityScanResult> for QueuedScanResultDto {
    fn from(queued: QueuedSecurityScanResult) -> Self {
        Self {
            request_id: queued.request_id,
            result: queued.result.into(),
        }
    }
}

impl From<SecurityRequestCompletion> for CompletionDto {
    fn from(completion: SecurityRequestCompletion) -> Self {
        match completion {
            SecurityRequestCompletion::Complete => Self::Complete,
            SecurityRequestCompletion::Degraded { failures } => Self::Degraded {
                failures: failures.into_iter().map(Into::into).collect(),
            },
            SecurityRequestCompletion::Failed { failures } => Self::Failed {
                failures: failures.into_iter().map(Into::into).collect(),
            },
        }
    }
}

impl From<SecurityFailure> for FailureDto {
    fn from(failure: SecurityFailure) -> Self {
        Self {
            stage: format!("{:?}", failure.stage),
            level: failure.level.map(|level| format!("{level:?}")),
            detector_id: failure.detector_id,
            kind: format!("{:?}", failure.kind),
            retryable: failure.retryable,
            message: failure.message,
        }
    }
}
