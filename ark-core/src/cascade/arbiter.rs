//! Final-decision arbitration between a model layer pair: an accepted L3
//! answer wins, then a weighted L2/L3 union, then an accepted L2 answer, and
//! otherwise the pipeline's default (safe) class. Thresholds come from a
//! [`ThresholdTable`] the host supplies.
use std::collections::HashMap;

use super::SecurityLevel;
use crate::{
    DecisionCandidate, DecisionEnvelope, DecisionProvenance, DecisionRecommendation,
    DecisionResult, DecisionTerminality, EvaluationResult, LabelScore, LayerResult, NativeResult,
};

/// Weighted L2/L3 union policy for one class.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct UnionPolicy {
    pub threshold: f64,
    pub l2_weight: f64,
    pub l3_weight: f64,
}

/// Calibrated per-class acceptance thresholds of one operating point.
pub trait ThresholdTable {
    /// Name of the operating point, reported in the decision envelope.
    fn operating_point(&self) -> &str;

    /// The host's version, reported as `provenance.ark_version` of the
    /// decision envelope.
    fn ark_version(&self) -> &str;

    /// The pipeline's default (safe) class; it is never "accepted".
    fn default_class(&self, pipeline: &str) -> &str;

    /// Acceptance threshold of `class_name` at the model `layer` (L2 or L3).
    /// `None` means the class is never accepted at that layer.
    fn threshold(&self, pipeline: &str, layer: SecurityLevel, class_name: &str) -> Option<f64>;

    /// The union policies of the pipeline, one per risk class.
    fn union_policies(&self, pipeline: &str) -> Vec<(&str, UnionPolicy)>;

    /// Positive class of a binary pipeline, used to recover both class scores
    /// from a result that carries only its winning class and confidence.
    fn binary_positive_class(&self, _pipeline: &str) -> Option<&str> {
        None
    }
}

/// Access to the result fields arbitration reads and rewrites; implemented
/// by every scan-result type that carries layered evidence.
pub trait LayeredResult: Clone {
    /// The category (pipeline) the result answers.
    fn category(&self) -> &str;
    fn class_name(&self) -> &str;
    fn confidence(&self) -> f64;
    fn level(&self) -> &str;
    fn model(&self) -> &str;
    fn layers(&self) -> &[LayerResult];
    fn layers_mut(&mut self) -> &mut Vec<LayerResult>;
    fn label_scores(&self) -> &[LabelScore];
    fn decision(&self) -> Option<&DecisionEnvelope>;
    /// Whether the result carries evidence spans.
    fn has_evidence(&self) -> bool;
    /// Whether an evidence span covers exactly the bytes `start..end`.
    fn has_evidence_at(&self, start: usize, end: usize) -> bool;
    fn set_class(&mut self, class_name: String, confidence: f64);
    fn set_level(&mut self, level: &str);
    fn set_decision(&mut self, decision: DecisionEnvelope);
}

impl LayeredResult for NativeResult {
    fn category(&self) -> &str {
        &self.category
    }
    fn class_name(&self) -> &str {
        &self.class_name
    }
    fn confidence(&self) -> f64 {
        self.confidence
    }
    fn level(&self) -> &str {
        &self.level
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn layers(&self) -> &[LayerResult] {
        &self.layers
    }
    fn layers_mut(&mut self) -> &mut Vec<LayerResult> {
        &mut self.layers
    }
    fn label_scores(&self) -> &[LabelScore] {
        &self.label_scores
    }
    fn decision(&self) -> Option<&DecisionEnvelope> {
        self.decision.as_ref()
    }
    fn has_evidence(&self) -> bool {
        !self.evidence_spans.is_empty()
    }
    fn has_evidence_at(&self, start: usize, end: usize) -> bool {
        self.evidence_spans
            .iter()
            .any(|span| span.start_byte == start && span.end_byte == end)
    }
    fn set_class(&mut self, class_name: String, confidence: f64) {
        self.class_name = class_name;
        self.confidence = confidence;
    }
    fn set_level(&mut self, level: &str) {
        self.level = level.to_string();
    }
    fn set_decision(&mut self, decision: DecisionEnvelope) {
        self.decision = Some(decision);
    }
}

/// Which source owns the final decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayerDecision {
    L2,
    L3,
    Union,
    Default,
}

impl LayerDecision {
    /// The `final_arbitration` name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::L2 => "l2",
            Self::L3 => "l3",
            Self::Union => "union",
            Self::Default => "default",
        }
    }
}

/// The candidates an arbitration weighed, for the decision envelope.
#[derive(Debug)]
pub struct ArbitrationTrace {
    pub candidates: Vec<DecisionCandidate>,
    pub operating_point: String,
    /// The host version for the envelope's provenance.
    pub ark_version: String,
}

/// Arbitrate an optional L3 result against its L2 result.
///
/// `Err(l2_result)` means `l2_result` was a direct-L3 placeholder (level L3
/// without L2 evidence) and no L3 output arrived; the host degrades it.
pub fn arbitrate_l3_l2<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    l3_result: Option<R>,
    l2_result: R,
) -> Result<R, R> {
    // A direct L3 placeholder is not an L2 observation and must never enter Union.
    if l2_result.level() == "L3" && !l2_result.layers().iter().any(|layer| layer.level == "L2") {
        let Some(result) = l3_result else {
            return Err(l2_result);
        };
        let trace = ArbitrationTrace {
            candidates: decision_candidate_for_source(
                table,
                pipeline,
                SecurityLevel::L3,
                result.class_name(),
                result.confidence(),
            )
            .into_iter()
            .collect(),
            operating_point: table.operating_point().to_string(),
            ark_version: table.ark_version().to_string(),
        };
        return Ok(if accepts_result(table, pipeline, &result) {
            with_arbitration(result, LayerDecision::L3, Some(&trace))
        } else {
            let confidence = default_confidence(table, pipeline, &result);
            with_arbitration(
                with_default_result(table, result, pipeline, confidence),
                LayerDecision::Default,
                Some(&trace),
            )
        });
    }
    let trace = arbitration_trace(table, pipeline, l3_result.as_ref(), &l2_result);
    if let Some(l3_result) = l3_result.as_ref() {
        if accepts_result(table, pipeline, l3_result) {
            return Ok(with_arbitration(
                l3_result.clone(),
                LayerDecision::L3,
                Some(&trace),
            ));
        }
        if let Some(result) = union_result(table, pipeline, l3_result, &l2_result) {
            return Ok(with_arbitration(result, LayerDecision::Union, Some(&trace)));
        }
    }

    if let Some((class_name, confidence)) = accepted_l2_candidate(&trace) {
        let result = with_l2_final_result(l2_result, class_name, confidence);
        return Ok(with_arbitration(result, LayerDecision::L2, Some(&trace)));
    }

    let result = default_result_for_selected_candidate(
        table,
        pipeline,
        l3_result.as_ref(),
        l2_result,
        &trace,
    );
    Ok(with_arbitration(
        result,
        LayerDecision::Default,
        Some(&trace),
    ))
}

/// Arbitrate an L2 result alone: accepted L2 or the default class.
pub fn arbitrate_l2<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    l2_result: R,
) -> R {
    let trace = arbitration_trace(table, pipeline, None, &l2_result);
    if let Some((class_name, confidence)) = accepted_l2_candidate(&trace) {
        let result = with_l2_final_result(l2_result, class_name, confidence);
        return with_arbitration(result, LayerDecision::L2, Some(&trace));
    }

    let confidence = default_confidence(table, pipeline, &l2_result);
    let result = with_default_result(table, l2_result, pipeline, confidence);
    with_arbitration(result, LayerDecision::Default, Some(&trace))
}

/// Threshold one L2 classifier output: keep it when accepted, otherwise the
/// default class at confidence zero.
pub fn threshold_l2_result(
    table: &impl ThresholdTable,
    pipeline: &str,
    mut result: EvaluationResult,
) -> (EvaluationResult, LayerDecision) {
    if accepts_class(
        table,
        pipeline,
        SecurityLevel::L2,
        &result.class_name,
        result.confidence,
    ) {
        return (result, LayerDecision::L2);
    }

    result.class_name = table.default_class(pipeline).to_string();
    result.confidence = 0.0;
    (result, LayerDecision::Default)
}

/// Whether `class_name` at `confidence` passes its threshold at `layer`; the
/// default class never does.
pub fn accepts_class(
    table: &impl ThresholdTable,
    pipeline: &str,
    layer: SecurityLevel,
    class_name: &str,
    confidence: f64,
) -> bool {
    class_name != table.default_class(pipeline)
        && table
            .threshold(pipeline, layer, class_name)
            .is_some_and(|threshold| confidence >= threshold)
}

/// Mark every layer with the `final_arbitration` and attach the decision
/// envelope when a trace is given.
pub fn with_arbitration<R: LayeredResult>(
    mut result: R,
    decision: LayerDecision,
    trace: Option<&ArbitrationTrace>,
) -> R {
    let selected = decision.as_str();
    for layer in result.layers_mut() {
        layer
            .details
            .insert("final_arbitration".to_string(), serde_json::json!(selected));
    }
    if let Some(trace) = trace {
        let envelope = decision_envelope(&result, decision, trace);
        result.set_decision(envelope);
    }
    result
}

/// Copy the final class onto the layer of the result's level and onto any
/// pending-L3 placeholder layer.
pub fn sync_final_layers<R: LayeredResult>(result: &mut R) {
    let class_name = result.class_name().to_string();
    let confidence = result.confidence();
    let level = result.level().to_string();
    for layer in result.layers_mut() {
        if layer.layer_type == "l3_pending" {
            layer.class_name = class_name.clone();
            layer
                .details
                .insert("fallback_class".to_string(), serde_json::json!(class_name));
            layer.details.insert(
                "fallback_confidence".to_string(),
                serde_json::json!(confidence),
            );
        } else if layer.level == level {
            layer.class_name = class_name.clone();
            layer.confidence = confidence;
        }
    }
}

fn layer_of(level: &str) -> SecurityLevel {
    if level.eq_ignore_ascii_case("l3") {
        SecurityLevel::L3
    } else {
        SecurityLevel::L2
    }
}

fn accepted_l2_candidate(trace: &ArbitrationTrace) -> Option<(String, f64)> {
    trace
        .candidates
        .iter()
        .find(|candidate| candidate.source == "l2" && candidate.accepted)
        .map(|candidate| (candidate.class_name.clone(), candidate.confidence))
}

fn with_l2_final_result<R: LayeredResult>(mut result: R, class_name: String, confidence: f64) -> R {
    result.set_class(class_name, confidence.clamp(0.0, 1.0));
    sync_final_layers(&mut result);
    result
}

fn default_result_for_selected_candidate<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    l3_result: Option<&R>,
    l2_result: R,
    trace: &ArbitrationTrace,
) -> R {
    match selected_decision_candidate(LayerDecision::Default, &trace.candidates)
        .as_ref()
        .map(|candidate| candidate.source.as_str())
    {
        Some("l3") => {
            let result = l3_result.cloned().unwrap_or(l2_result);
            let confidence = default_confidence(table, pipeline, &result);
            with_default_result(table, result, pipeline, confidence)
        }
        Some("l2") => {
            let confidence = default_confidence(table, pipeline, &l2_result);
            with_default_result(table, l2_result, pipeline, confidence)
        }
        _ => with_default_result(
            table,
            l3_result.cloned().unwrap_or(l2_result),
            pipeline,
            0.0,
        ),
    }
}

fn with_default_result<R: LayeredResult>(
    table: &impl ThresholdTable,
    mut result: R,
    pipeline: &str,
    confidence: f64,
) -> R {
    result.set_class(table.default_class(pipeline).to_string(), confidence);
    sync_final_layers(&mut result);
    result
}

fn default_confidence<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    result: &R,
) -> f64 {
    let default = table.default_class(pipeline);
    result
        .label_scores()
        .iter()
        .find(|score| score.label == default)
        .map(|score| score.confidence.clamp(0.0, 1.0))
        .or_else(|| {
            table
                .binary_positive_class(pipeline)
                .and_then(|_| score_map(table, pipeline, result).get(default).copied())
        })
        .or_else(|| (result.class_name() == default).then_some(result.confidence().clamp(0.0, 1.0)))
        .unwrap_or(0.0)
}

fn decision_envelope<R: LayeredResult>(
    result: &R,
    decision: LayerDecision,
    trace: &ArbitrationTrace,
) -> DecisionEnvelope {
    let final_arbitration = decision.as_str().to_string();
    let decision_candidate = selected_decision_candidate(decision, &trace.candidates);
    let acceptance_threshold = decision_candidate
        .as_ref()
        .map(|candidate| candidate.acceptance_threshold);
    DecisionEnvelope {
        schema_version: "ark.decision.v1".to_string(),
        final_result: DecisionResult {
            class_name: result.class_name().to_string(),
            confidence: result.confidence(),
            source: final_arbitration.clone(),
        },
        decision_candidate,
        recommendation: DecisionRecommendation {
            accepted: decision != LayerDecision::Default,
            final_arbitration,
            operating_point: trace.operating_point.clone(),
            acceptance_threshold,
        },
        candidates: trace.candidates.clone(),
        terminality: DecisionTerminality {
            completion: "complete".to_string(),
            degraded: false,
            degradation_reason: None,
        },
        provenance: DecisionProvenance {
            ark_version: trace.ark_version.clone(),
            schema_version: "ark.decision.v1".to_string(),
            model: result.model().to_string(),
        },
    }
}

fn selected_decision_candidate(
    decision: LayerDecision,
    candidates: &[DecisionCandidate],
) -> Option<DecisionCandidate> {
    let source = match decision {
        LayerDecision::L2 => Some("l2"),
        LayerDecision::L3 => Some("l3"),
        LayerDecision::Union => Some("union"),
        LayerDecision::Default => None,
    };
    if let Some(source) = source {
        return candidates
            .iter()
            .find(|candidate| candidate.source == source)
            .cloned();
    }
    ["l3", "union", "l2"].iter().find_map(|source| {
        candidates
            .iter()
            .find(|candidate| candidate.source == *source)
            .cloned()
    })
}

fn arbitration_trace<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    l3_result: Option<&R>,
    l2_result: &R,
) -> ArbitrationTrace {
    let (l2_class_name, l2_confidence) = l2_raw_candidate(table, pipeline, l2_result);
    let mut candidates = Vec::new();
    candidates.extend(decision_candidate_for_source(
        table,
        pipeline,
        SecurityLevel::L2,
        &l2_class_name,
        l2_confidence,
    ));
    if let Some(l3_result) = l3_result {
        candidates.extend(decision_candidate_for_source(
            table,
            pipeline,
            SecurityLevel::L3,
            l3_result.class_name(),
            l3_result.confidence(),
        ));
        candidates.extend(union_decision_candidate(
            table, pipeline, l3_result, l2_result,
        ));
    }
    ArbitrationTrace {
        candidates,
        operating_point: table.operating_point().to_string(),
        ark_version: table.ark_version().to_string(),
    }
}

fn l2_raw_candidate<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    result: &R,
) -> (String, f64) {
    if let Some(candidate) = result.decision().and_then(|decision| {
        decision
            .candidates
            .iter()
            .find(|candidate| candidate.source == "l2")
    }) {
        return (candidate.class_name.clone(), candidate.confidence);
    }
    let default = table.default_class(pipeline);
    if let Some(score) = result
        .label_scores()
        .iter()
        .filter(|score| score.label != default)
        .max_by(|left, right| left.confidence.total_cmp(&right.confidence))
    {
        return (score.label.clone(), score.confidence);
    }
    (result.class_name().to_string(), result.confidence())
}

fn decision_candidate_for_source(
    table: &impl ThresholdTable,
    pipeline: &str,
    layer: SecurityLevel,
    class_name: &str,
    confidence: f64,
) -> Option<DecisionCandidate> {
    if class_name == table.default_class(pipeline) {
        return None;
    }
    let acceptance_threshold = table.threshold(pipeline, layer, class_name)?;
    Some(DecisionCandidate {
        source: layer.as_str().to_ascii_lowercase(),
        class_name: class_name.to_string(),
        confidence,
        acceptance_threshold,
        accepted: confidence >= acceptance_threshold,
        evidence: None,
        chunk_evidence: None,
    })
}

fn union_decision_candidate<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    l3_result: &R,
    l2_result: &R,
) -> Option<DecisionCandidate> {
    let (class_name, policy, confidence) =
        best_union_candidate(table, pipeline, l3_result, l2_result)?;
    let l2_scores = score_map(table, pipeline, l2_result);
    let l3_scores = score_map(table, pipeline, l3_result);
    let evidence = HashMap::from([
        ("l2_weight".to_string(), policy.l2_weight),
        ("l3_weight".to_string(), policy.l3_weight),
        (
            "l2_confidence".to_string(),
            *l2_scores.get(&class_name).unwrap_or(&0.0),
        ),
        (
            "l3_confidence".to_string(),
            *l3_scores.get(&class_name).unwrap_or(&0.0),
        ),
    ]);
    Some(DecisionCandidate {
        source: "union".to_string(),
        class_name,
        confidence: confidence.clamp(0.0, 1.0),
        acceptance_threshold: policy.threshold,
        accepted: confidence >= policy.threshold,
        evidence: Some(evidence),
        chunk_evidence: None,
    })
}

fn accepts_result<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    result: &R,
) -> bool {
    accepts_class(
        table,
        pipeline,
        layer_of(result.level()),
        result.class_name(),
        result.confidence(),
    )
}

fn union_result<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    l3_result: &R,
    l2_result: &R,
) -> Option<R> {
    let (class_name, policy, confidence) =
        best_union_candidate(table, pipeline, l3_result, l2_result)?;

    if confidence < policy.threshold {
        return None;
    }

    let mut result = l3_result.clone();
    result.set_class(class_name, confidence.clamp(0.0, 1.0));
    result.set_level("L3");
    for layer in result.layers_mut() {
        layer
            .thresholds
            .insert("union".to_string(), policy.threshold);
        layer.details.insert(
            "union_l2_weight".to_string(),
            serde_json::json!(policy.l2_weight),
        );
        layer.details.insert(
            "union_l3_weight".to_string(),
            serde_json::json!(policy.l3_weight),
        );
    }
    Some(result)
}

fn best_union_candidate<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    l3_result: &R,
    l2_result: &R,
) -> Option<(String, UnionPolicy, f64)> {
    let union = table.union_policies(pipeline);
    if union.is_empty() {
        return None;
    }

    let default = table.default_class(pipeline);
    let l2_scores = score_map(table, pipeline, l2_result);
    let l3_scores = score_map(table, pipeline, l3_result);
    union
        .into_iter()
        .filter(|(class_name, _)| *class_name != default)
        .filter_map(|(class_name, policy)| {
            let l2_score = l2_scores.get(class_name)?;
            let l3_score = l3_scores.get(class_name)?;
            let confidence = policy.l2_weight * l2_score + policy.l3_weight * l3_score;
            Some((class_name.to_string(), policy, confidence))
        })
        .max_by(|left, right| left.2.total_cmp(&right.2))
}

fn score_map<R: LayeredResult>(
    table: &impl ThresholdTable,
    pipeline: &str,
    result: &R,
) -> HashMap<String, f64> {
    if !result.label_scores().is_empty() {
        return result
            .label_scores()
            .iter()
            .map(|score| (score.label.clone(), score.confidence))
            .collect();
    }

    let mut scores = HashMap::new();
    if let Some(positive) = table.binary_positive_class(pipeline) {
        let probability = if result.class_name() == positive {
            result.confidence()
        } else {
            1.0 - result.confidence()
        }
        .clamp(0.0, 1.0);
        scores.insert(positive.to_string(), probability);
        scores.insert(table.default_class(pipeline).to_string(), 1.0 - probability);
        return scores;
    }

    scores.insert(
        result.class_name().to_string(),
        result.confidence().clamp(0.0, 1.0),
    );
    scores
}

#[cfg(test)]
mod tests;
