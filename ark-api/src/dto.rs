//! JSON wire types mirroring `docs/reference/result-schema.md`.
//!
//! `patronus_ark::SecurityScanResult` and friends intentionally do not derive
//! `Serialize` (see the Python bindings, which build dictionaries by hand for
//! the same reason). These DTOs are the API's one conversion point.

use std::collections::HashMap;

use patronus_ark::{
    QueuedSecurityScanResult, SecurityFailure, SecurityRequestCompletion, SecurityScanResult,
};

use patronus_ark_core::{cascade::Stage, DecisionEnvelope, EvidenceSpan, LabelScore, LayerResult};
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
    /// Stage that gave the category its final answer; absent while a later
    /// layer still answers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<Stage>,
    /// L1's answer when L1 decided the category under the cascade.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub l1_outcome: Option<patronus_ark_core::cascade::StageOutcome>,
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
        let SecurityScanResult {
            native: result,
            decided_by,
            l1_outcome,
            ..
        } = result;
        Self {
            category: result.category,
            class_name: result.class_name,
            confidence: result.confidence,
            level: result.level,
            model: result.model,
            duration_ms: result.duration_ms,
            decision: result.decision,
            decided_by,
            l1_outcome,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn result(decided_by: Option<Stage>) -> SecurityScanResult {
        SecurityScanResult {
            native: patronus_ark_core::NativeResult {
                category: "injection".into(),
                class_name: "safe".into(),
                confidence: 0.0,
                level: "L2".into(),
                model: "m".into(),
                duration_ms: 0.0,
                layers: Vec::new(),
                evidence_spans: Vec::new(),
                label_scores: Vec::new(),
                decision: None,
            },
            internal_l2_chunk_outputs: Vec::new(),
            decided_by,
            l1_outcome: None,
        }
    }

    #[test]
    fn decided_by_is_serialized_only_when_the_result_is_final() {
        let json = serde_json::to_value(ScanResultDto::from(result(Some(Stage::L2)))).unwrap();
        assert_eq!(json["decided_by"], "l2");
        let json = serde_json::to_value(ScanResultDto::from(result(None))).unwrap();
        assert!(json.get("decided_by").is_none());
    }
}
