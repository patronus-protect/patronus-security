// SPDX-License-Identifier: GPL-3.0-only
use std::{collections::HashMap, sync::OnceLock};

use serde::Deserialize;

use crate::ml::ntdb_executor::{
    aggregate_probabilities, ByteSpan, JointV3CandidatePolicy, JointV3DecisionContext,
    L2ChunkOutput,
};
use crate::{
    DecisionCandidate, DecisionEnvelope, DecisionProvenance, DecisionRecommendation,
    DecisionResult, DecisionTerminality, EvaluationResult, NtdbOperatingPoint, SecurityScanResult,
};

#[derive(Debug, Clone)]
pub(crate) struct JointV3L3Chunk {
    pub span: ByteSpan,
    pub probabilities: Vec<f32>,
}

#[derive(Debug, Deserialize)]
struct ThresholdAsset {
    thresholds: HashMap<String, PipelineThresholds>,
}

type ClassThresholds = HashMap<String, HashMap<String, f64>>;

#[derive(Debug, Deserialize)]
struct PipelineThresholds {
    l2: ClassThresholds,
    l3: ClassThresholds,
    #[serde(default)]
    union: HashMap<String, HashMap<String, UnionThreshold>>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
struct UnionThreshold {
    threshold: f64,
    l2_weight: f64,
    l3_weight: f64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LayerDecision {
    L2,
    L3,
    Union,
    Default,
}

#[derive(Debug)]
struct ArbitrationTrace {
    candidates: Vec<DecisionCandidate>,
    operating_point: NtdbOperatingPoint,
}

static THRESHOLDS: OnceLock<ThresholdAsset> = OnceLock::new();

fn thresholds() -> &'static ThresholdAsset {
    THRESHOLDS.get_or_init(|| {
        serde_json::from_str(include_str!("decision_thresholds.json"))
            .expect("bundled decision threshold JSON must be valid")
    })
}

pub(crate) fn arbitrate_l3_l2(
    pipeline: &str,
    l3_result: Option<SecurityScanResult>,
    l2_result: SecurityScanResult,
    point: NtdbOperatingPoint,
) -> SecurityScanResult {
    let trace = arbitration_trace(pipeline, l3_result.as_ref(), &l2_result, point);
    if let Some(l3_result) = l3_result.as_ref() {
        if accepts_result(pipeline, &l3_result, point) {
            return with_arbitration(l3_result.clone(), LayerDecision::L3, Some(&trace));
        }
        if let Some(result) = union_result(pipeline, &l3_result, &l2_result, point) {
            return with_arbitration(result, LayerDecision::Union, Some(&trace));
        }
    }

    if let Some((class_name, confidence)) = accepted_l2_candidate(&trace) {
        let result = with_l2_final_result(l2_result, &class_name, confidence);
        return with_arbitration(result, LayerDecision::L2, Some(&trace));
    }

    let result =
        default_result_for_selected_candidate(pipeline, l3_result.as_ref(), l2_result, &trace);
    with_arbitration(result, LayerDecision::Default, Some(&trace))
}

pub(crate) fn arbitrate_l2(
    pipeline: &str,
    l2_result: SecurityScanResult,
    point: NtdbOperatingPoint,
) -> SecurityScanResult {
    if let Some(result) = arbitrate_joint_v3(pipeline, None, l2_result.clone(), &[], point) {
        return result;
    }
    let trace = arbitration_trace(pipeline, None, &l2_result, point);
    if let Some((class_name, confidence)) = accepted_l2_candidate(&trace) {
        let result = with_l2_final_result(l2_result, &class_name, confidence);
        return with_arbitration(result, LayerDecision::L2, Some(&trace));
    }

    let confidence = default_confidence(pipeline, &l2_result);
    let result = with_default_result(l2_result, pipeline, confidence);
    with_arbitration(result, LayerDecision::Default, Some(&trace))
}

/// Apply the Package-v4 document contract. L2-only and L3-only remain visible
/// candidates, while the export's default Union view owns the final decision.
pub(crate) fn arbitrate_joint_v3(
    _pipeline: &str,
    l3_result: Option<SecurityScanResult>,
    l2_result: SecurityScanResult,
    l3_chunks: &[JointV3L3Chunk],
    point: NtdbOperatingPoint,
) -> Option<SecurityScanResult> {
    let l2_chunks = l2_result.internal_l2_chunk_outputs.clone();
    let context = l2_chunks
        .iter()
        .find_map(|chunk| chunk.joint_v3_decision.clone())?;
    let mut l2 = joint_v3_view(&context, &context.l2, &l2_chunks)?;
    l2.candidate.source = "l2".to_string();
    let mut candidates = vec![l2.candidate.clone()];
    let mut l3 = (!l3_chunks.is_empty())
        .then(|| joint_v3_l3_view(&context, &context.l3, l3_chunks))
        .flatten();
    if let Some(view) = &mut l3 {
        view.candidate.source = "l3".to_string();
    }
    let rows = l2_chunks
        .iter()
        .map(|chunk| {
            l3_chunks
                .iter()
                .find(|l3| l3.span == chunk.span)
                .map(|l3| l3.probabilities.clone())
                .unwrap_or_else(|| chunk.class_probabilities.clone())
        })
        .collect::<Vec<_>>();
    let mut union = joint_v3_scores_view(&context, &context.union, &rows);
    if let Some(view) = &mut union {
        view.candidate.source = "union".to_string();
    }
    if let Some(view) = &l3 {
        candidates.push(view.candidate.clone());
    }
    if let Some(view) = &union {
        candidates.push(view.candidate.clone());
    }
    let trace = ArbitrationTrace {
        candidates,
        operating_point: point,
    };

    if let Some(view) = union.as_ref() {
        let base = l3_result.unwrap_or(l2_result);
        if view.candidate.accepted {
            let mut result = with_arbitration(
                apply_joint_v3_view(base, &context, view, false),
                LayerDecision::Union,
                Some(&trace),
            );
            attach_joint_v3_union_evidence(&mut result, &context, &l2_chunks, l3_chunks, view);
            return Some(result);
        }
        let mut result = with_arbitration(
            apply_joint_v3_view(base, &context, view, true),
            LayerDecision::Default,
            Some(&trace),
        );
        // v4's final document mode is Union. Keep that rejected Union as the
        // decision candidate without changing v2's Default candidate priority.
        if let Some(envelope) = &mut result.decision {
            envelope.decision_candidate = Some(view.candidate.clone());
            envelope.recommendation.acceptance_threshold =
                Some(view.candidate.acceptance_threshold);
        }
        attach_joint_v3_union_evidence(&mut result, &context, &l2_chunks, l3_chunks, view);
        return Some(result);
    }

    None
}

fn attach_joint_v3_union_evidence(
    result: &mut SecurityScanResult,
    context: &JointV3DecisionContext,
    l2_chunks: &[L2ChunkOutput],
    l3_chunks: &[JointV3L3Chunk],
    view: &JointV3View,
) {
    let Some(class_index) = context
        .labels
        .iter()
        .position(|label| label == &view.candidate.class_name)
    else {
        return;
    };
    let contributors = l2_chunks
        .iter()
        .enumerate()
        .map(|(chunk_id, l2)| {
            let l3 = l3_chunks.iter().find(|l3| l3.span == l2.span);
            let probabilities = l3
                .map(|chunk| &chunk.probabilities)
                .unwrap_or(&l2.class_probabilities);
            serde_json::json!({
                "chunk_id": chunk_id,
                "span": l2.span,
                "source": if l3.is_some() { "l3" } else { "l2" },
                "class_name": view.candidate.class_name,
                "confidence": probabilities.get(class_index).copied().unwrap_or_default(),
            })
        })
        .collect::<Vec<_>>();
    let decisive_chunks = contributors
        .iter()
        .max_by(|left, right| {
            left["confidence"]
                .as_f64()
                .unwrap_or_default()
                .total_cmp(&right["confidence"].as_f64().unwrap_or_default())
        })
        .cloned()
        .into_iter()
        .collect::<Vec<_>>();
    let evidence = serde_json::json!({
        "stage": "union",
        "aggregation": &context.union.aggregation,
        "contributors": contributors,
        "decisive_chunks": decisive_chunks,
    });
    if let Some(candidate) = result
        .decision
        .as_mut()
        .and_then(|envelope| envelope.decision_candidate.as_mut())
    {
        candidate.chunk_evidence = Some(evidence);
    }
}

struct JointV3View {
    scores: Vec<f32>,
    candidate: DecisionCandidate,
}

fn joint_v3_view(
    context: &JointV3DecisionContext,
    policy: &JointV3CandidatePolicy,
    chunks: &[L2ChunkOutput],
) -> Option<JointV3View> {
    let rows = chunks
        .iter()
        .map(|chunk| chunk.class_probabilities.clone())
        .collect::<Vec<_>>();
    joint_v3_scores_view(context, policy, &rows)
}

fn joint_v3_l3_view(
    context: &JointV3DecisionContext,
    policy: &JointV3CandidatePolicy,
    chunks: &[JointV3L3Chunk],
) -> Option<JointV3View> {
    let rows = chunks
        .iter()
        .map(|chunk| chunk.probabilities.clone())
        .collect::<Vec<_>>();
    joint_v3_scores_view(context, policy, &rows)
}

fn joint_v3_scores_view(
    context: &JointV3DecisionContext,
    policy: &JointV3CandidatePolicy,
    rows: &[Vec<f32>],
) -> Option<JointV3View> {
    let scores = aggregate_probabilities(rows, &policy.aggregation).ok()?;
    let (risk_index, risk_score) = scores
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| *index != context.default_class_index)
        .max_by(|left, right| left.1.total_cmp(&right.1))?;
    let default_score = *scores.get(context.default_class_index)?;
    let risk_margin = risk_score - default_score;
    Some(JointV3View {
        scores,
        candidate: DecisionCandidate {
            source: String::new(),
            class_name: context.labels.get(risk_index)?.clone(),
            confidence: f64::from(risk_score),
            acceptance_threshold: f64::from(policy.risk_margin_threshold),
            accepted: risk_margin >= policy.risk_margin_threshold,
            evidence: Some(HashMap::from([
                ("risk_margin".to_string(), f64::from(risk_margin)),
                ("default_confidence".to_string(), f64::from(default_score)),
            ])),
            chunk_evidence: None,
        },
    })
}

fn apply_joint_v3_view(
    mut result: SecurityScanResult,
    context: &JointV3DecisionContext,
    view: &JointV3View,
    use_default: bool,
) -> SecurityScanResult {
    let index = if use_default {
        context.default_class_index
    } else {
        context
            .labels
            .iter()
            .position(|label| label == &view.candidate.class_name)
            .unwrap_or(context.default_class_index)
    };
    result.class_name = context.labels[index].clone();
    result.confidence = f64::from(view.scores[index]).clamp(0.0, 1.0);
    result.label_scores = context
        .labels
        .iter()
        .zip(&view.scores)
        .map(|(label, score)| crate::LabelScore {
            label: label.clone(),
            confidence: f64::from(*score),
            matched: label == &result.class_name,
        })
        .collect();
    update_final_layer_result(&mut result);
    update_l3_pending_fallback(&mut result);
    result
}

pub(crate) fn threshold_l2_result(
    pipeline: &str,
    mut result: EvaluationResult,
    point: NtdbOperatingPoint,
) -> (EvaluationResult, LayerDecision) {
    if accepts_class(pipeline, "L2", &result.class_name, result.confidence, point) {
        return (result, LayerDecision::L2);
    }

    result.class_name = default_class(pipeline).to_string();
    result.confidence = 0.0;
    (result, LayerDecision::Default)
}

pub(crate) fn arbitration_name(decision: LayerDecision) -> &'static str {
    match decision {
        LayerDecision::L2 => "l2",
        LayerDecision::L3 => "l3",
        LayerDecision::Union => "union",
        LayerDecision::Default => "default",
    }
}

fn accepted_l2_candidate(trace: &ArbitrationTrace) -> Option<(String, f64)> {
    trace
        .candidates
        .iter()
        .find(|candidate| candidate.source == "l2" && candidate.accepted)
        .map(|candidate| (candidate.class_name.clone(), candidate.confidence))
}

fn with_l2_final_result(
    mut result: SecurityScanResult,
    class_name: &str,
    confidence: f64,
) -> SecurityScanResult {
    result.class_name = class_name.to_string();
    result.confidence = confidence.clamp(0.0, 1.0);
    update_final_layer_result(&mut result);
    update_l3_pending_fallback(&mut result);
    result
}

fn default_result_for_selected_candidate(
    pipeline: &str,
    l3_result: Option<&SecurityScanResult>,
    l2_result: SecurityScanResult,
    trace: &ArbitrationTrace,
) -> SecurityScanResult {
    match selected_decision_candidate(LayerDecision::Default, &trace.candidates)
        .as_ref()
        .map(|candidate| candidate.source.as_str())
    {
        Some("l3") => {
            let result = l3_result.cloned().unwrap_or(l2_result);
            let confidence = default_confidence(pipeline, &result);
            with_default_result(result, pipeline, confidence)
        }
        Some("l2") => {
            let confidence = default_confidence(pipeline, &l2_result);
            with_default_result(l2_result, pipeline, confidence)
        }
        _ => with_default_result(l3_result.cloned().unwrap_or(l2_result), pipeline, 0.0),
    }
}

fn with_default_result(
    mut result: SecurityScanResult,
    pipeline: &str,
    confidence: f64,
) -> SecurityScanResult {
    result.class_name = default_class(pipeline).to_string();
    result.confidence = confidence;
    update_final_layer_result(&mut result);
    update_l3_pending_fallback(&mut result);
    result
}

fn default_confidence(pipeline: &str, result: &SecurityScanResult) -> f64 {
    let default = default_class(pipeline);
    result
        .label_scores
        .iter()
        .find(|score| score.label == default)
        .map(|score| score.confidence.clamp(0.0, 1.0))
        .or_else(|| {
            (pipeline_key(pipeline) == "injection")
                .then(|| score_map("injection", result).get(default).copied())
                .flatten()
        })
        .or_else(|| (result.class_name == default).then_some(result.confidence.clamp(0.0, 1.0)))
        .unwrap_or(0.0)
}

fn update_final_layer_result(result: &mut SecurityScanResult) {
    for layer in &mut result.layers {
        if layer.level == result.level && layer.layer_type != "l3_pending" {
            layer.class_name = result.class_name.clone();
            layer.confidence = result.confidence;
        }
    }
}

fn update_l3_pending_fallback(result: &mut SecurityScanResult) {
    for layer in &mut result.layers {
        if layer.layer_type != "l3_pending" {
            continue;
        }
        layer.class_name = result.class_name.clone();
        layer.details.insert(
            "fallback_class".to_string(),
            serde_json::json!(result.class_name),
        );
        layer.details.insert(
            "fallback_confidence".to_string(),
            serde_json::json!(result.confidence),
        );
    }
}

fn with_arbitration(
    mut result: SecurityScanResult,
    decision: LayerDecision,
    trace: Option<&ArbitrationTrace>,
) -> SecurityScanResult {
    let selected = arbitration_name(decision);
    for layer in &mut result.layers {
        layer
            .details
            .insert("final_arbitration".to_string(), serde_json::json!(selected));
    }
    if let Some(trace) = trace {
        result.decision = Some(decision_envelope(&result, decision, trace));
    }
    result
}

fn decision_envelope(
    result: &SecurityScanResult,
    decision: LayerDecision,
    trace: &ArbitrationTrace,
) -> DecisionEnvelope {
    let final_arbitration = arbitration_name(decision).to_string();
    let decision_candidate = selected_decision_candidate(decision, &trace.candidates);
    let acceptance_threshold = decision_candidate
        .as_ref()
        .map(|candidate| candidate.acceptance_threshold);
    DecisionEnvelope {
        schema_version: "ark.decision.v1".to_string(),
        final_result: DecisionResult {
            class_name: result.class_name.clone(),
            confidence: result.confidence,
            source: final_arbitration.clone(),
        },
        decision_candidate: decision_candidate.clone(),
        recommendation: DecisionRecommendation {
            accepted: decision != LayerDecision::Default,
            final_arbitration,
            operating_point: profile_key(trace.operating_point).to_string(),
            acceptance_threshold,
        },
        candidates: trace.candidates.clone(),
        terminality: DecisionTerminality {
            completion: "complete".to_string(),
            degraded: false,
            degradation_reason: None,
        },
        provenance: DecisionProvenance {
            ark_version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: "ark.decision.v1".to_string(),
            model: result.model.clone(),
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

fn arbitration_trace(
    pipeline: &str,
    l3_result: Option<&SecurityScanResult>,
    l2_result: &SecurityScanResult,
    point: NtdbOperatingPoint,
) -> ArbitrationTrace {
    let (l2_raw_class_name, l2_raw_confidence) = l2_raw_candidate(pipeline, l2_result);
    let candidates = arbitration_candidates(
        pipeline,
        &l2_raw_class_name,
        l2_raw_confidence,
        l3_result,
        l2_result,
        point,
    );
    ArbitrationTrace {
        candidates,
        operating_point: point,
    }
}

fn l2_raw_candidate(pipeline: &str, result: &SecurityScanResult) -> (String, f64) {
    if let Some(candidate) = result.decision.as_ref().and_then(|decision| {
        decision
            .candidates
            .iter()
            .find(|candidate| candidate.source == "l2")
    }) {
        return (candidate.class_name.clone(), candidate.confidence);
    }
    let default = default_class(pipeline);
    if let Some(score) = result
        .label_scores
        .iter()
        .filter(|score| score.label != default)
        .max_by(|left, right| left.confidence.total_cmp(&right.confidence))
    {
        return (score.label.clone(), score.confidence);
    }
    (result.class_name.clone(), result.confidence)
}

fn arbitration_candidates(
    pipeline: &str,
    l2_class_name: &str,
    l2_confidence: f64,
    l3_result: Option<&SecurityScanResult>,
    l2_result: &SecurityScanResult,
    point: NtdbOperatingPoint,
) -> Vec<DecisionCandidate> {
    let mut candidates = Vec::new();
    if let Some(candidate) = decision_candidate_for_source(
        pipeline,
        "L2",
        "l2",
        l2_class_name,
        l2_confidence,
        point,
        None,
    ) {
        candidates.push(candidate);
    }
    if let Some(l3_result) = l3_result {
        if let Some(candidate) = decision_candidate_for_source(
            pipeline,
            "L3",
            "l3",
            &l3_result.class_name,
            l3_result.confidence,
            point,
            None,
        ) {
            candidates.push(candidate);
        }
        if let Some(candidate) = union_decision_candidate(pipeline, l3_result, l2_result, point) {
            candidates.push(candidate);
        }
    }
    candidates
}

fn decision_candidate_for_source(
    pipeline: &str,
    level: &str,
    source: &str,
    class_name: &str,
    confidence: f64,
    point: NtdbOperatingPoint,
    evidence: Option<HashMap<String, f64>>,
) -> Option<DecisionCandidate> {
    if class_name == default_class(pipeline) {
        return None;
    }
    let acceptance_threshold = threshold_for(pipeline, level, class_name, point)?;
    Some(DecisionCandidate {
        source: source.to_string(),
        class_name: class_name.to_string(),
        confidence,
        acceptance_threshold,
        accepted: confidence >= acceptance_threshold,
        evidence,
        chunk_evidence: None,
    })
}

fn union_decision_candidate(
    pipeline: &str,
    l3_result: &SecurityScanResult,
    l2_result: &SecurityScanResult,
    point: NtdbOperatingPoint,
) -> Option<DecisionCandidate> {
    let (class_name, policy, confidence) =
        best_union_candidate(pipeline, l3_result, l2_result, point)?;
    let key = pipeline_key(pipeline);
    let l2_scores = score_map(key, l2_result);
    let l3_scores = score_map(key, l3_result);
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

fn accepts_result(pipeline: &str, result: &SecurityScanResult, point: NtdbOperatingPoint) -> bool {
    accepts_class(
        pipeline,
        &result.level,
        &result.class_name,
        result.confidence,
        point,
    )
}

fn union_result(
    pipeline: &str,
    l3_result: &SecurityScanResult,
    l2_result: &SecurityScanResult,
    point: NtdbOperatingPoint,
) -> Option<SecurityScanResult> {
    let (class_name, policy, confidence) =
        best_union_candidate(pipeline, l3_result, l2_result, point)?;

    if confidence < policy.threshold {
        return None;
    }

    let mut result = l3_result.clone();
    result.class_name = class_name.clone();
    result.confidence = confidence.clamp(0.0, 1.0);
    result.level = "L3".to_string();
    for layer in &mut result.layers {
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

fn best_union_candidate(
    pipeline: &str,
    l3_result: &SecurityScanResult,
    l2_result: &SecurityScanResult,
    point: NtdbOperatingPoint,
) -> Option<(String, UnionThreshold, f64)> {
    let key = pipeline_key(pipeline);
    let profile = profile_key(point);
    let union = &thresholds().thresholds.get(key)?.union;
    if union.is_empty() {
        return None;
    }

    let l2_scores = score_map(key, l2_result);
    let l3_scores = score_map(key, l3_result);
    union
        .iter()
        .filter(|(class_name, _)| class_name.as_str() != default_class(pipeline))
        .filter_map(|(class_name, profiles)| {
            let policy = profiles.get(profile).or_else(|| profiles.get("best_f1"))?;
            let l2_score = l2_scores.get(class_name)?;
            let l3_score = l3_scores.get(class_name)?;
            let confidence = policy.l2_weight * l2_score + policy.l3_weight * l3_score;
            Some((class_name.clone(), *policy, confidence))
        })
        .max_by(|left, right| left.2.total_cmp(&right.2))
}

fn score_map(pipeline: &str, result: &SecurityScanResult) -> HashMap<String, f64> {
    if !result.label_scores.is_empty() {
        return result
            .label_scores
            .iter()
            .map(|score| (score.label.clone(), score.confidence))
            .collect();
    }

    let mut scores = HashMap::new();
    if pipeline == "injection" {
        let attack = if result.class_name == "attack" {
            result.confidence
        } else {
            1.0 - result.confidence
        }
        .clamp(0.0, 1.0);
        scores.insert("attack".to_string(), attack);
        scores.insert("benign".to_string(), 1.0 - attack);
        return scores;
    }

    scores.insert(result.class_name.clone(), result.confidence.clamp(0.0, 1.0));
    scores
}

pub(crate) fn accepts_class(
    pipeline: &str,
    level: &str,
    class_name: &str,
    confidence: f64,
    point: NtdbOperatingPoint,
) -> bool {
    if class_name == default_class(pipeline) {
        return false;
    }
    threshold_for(pipeline, level, class_name, point)
        .is_some_and(|threshold| confidence >= threshold)
}

pub(crate) fn default_class(pipeline: &str) -> &'static str {
    match pipeline_key(pipeline) {
        "injection" => "benign",
        "routing" => "benign_conv",
        "sensitive_docs" => "other",
        "threat" => "benign",
        "tool_action" | "tool_class" => "unknown",
        "tool_tags_sink_external" | "tool_tags_source_sensitive" | "tool_tags_source_untrusted" => {
            "absent"
        }
        _ => "unknown",
    }
}

fn threshold_for(
    pipeline: &str,
    level: &str,
    class_name: &str,
    point: NtdbOperatingPoint,
) -> Option<f64> {
    if class_name == default_class(pipeline) {
        return Some(0.0);
    }
    let asset = thresholds();
    let key = pipeline_key(pipeline);
    let level_key = level.to_ascii_lowercase();
    let profile = profile_key(point);
    asset
        .thresholds
        .get(key)
        .map(|pipeline| match level_key.as_str() {
            "l2" => &pipeline.l2,
            "l3" => &pipeline.l3,
            _ => &pipeline.l2,
        })
        .and_then(|classes| classes.get(class_name))
        .and_then(|profiles| {
            profiles
                .get(profile)
                .or_else(|| profiles.get("best_f1"))
                .copied()
        })
}

fn pipeline_key(pipeline: &str) -> &str {
    match pipeline {
        "sensitive_document" => "sensitive_docs",
        other => other,
    }
}

fn profile_key(point: NtdbOperatingPoint) -> &'static str {
    match point {
        NtdbOperatingPoint::BestF1 => "best_f1",
        NtdbOperatingPoint::BestFprInF1 => "best_fpr",
        NtdbOperatingPoint::BestFnrInF1 => "best_fnr",
        NtdbOperatingPoint::BestPromote => "best_promote",
        NtdbOperatingPoint::BestLatencyInF1 => "best_latency_in_f1",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LabelScore, LayerResult, SecurityScanResult};

    fn result(class_name: &str, confidence: f64, level: &str) -> SecurityScanResult {
        SecurityScanResult {
            category: "injection".to_string(),
            class_name: class_name.to_string(),
            confidence,
            level: level.to_string(),
            model: "test".to_string(),
            duration_ms: 0.0,
            layers: vec![LayerResult {
                level: level.to_string(),
                layer_type: "test".to_string(),
                class_name: class_name.to_string(),
                confidence,
                matched: true,
                duration_ms: 0.0,
                thresholds: HashMap::new(),
                details: HashMap::new(),
            }],
            internal_l2_chunk_outputs: Vec::new(),
            evidence_spans: Vec::new(),
            label_scores: Vec::new(),
            decision: None,
        }
    }

    fn l2_result_with_raw(
        pipeline: &str,
        class_name: &str,
        confidence: f64,
        raw_class_name: &str,
        raw_confidence: f64,
    ) -> SecurityScanResult {
        let mut result = result(class_name, confidence, "L2");
        result.layers[0].layer_type = "ntdb_l2".to_string();
        result.label_scores = vec![LabelScore {
            label: raw_class_name.to_string(),
            confidence: raw_confidence,
            matched: raw_class_name == class_name,
        }];
        result = arbitrate_l2(pipeline, result, NtdbOperatingPoint::BestF1);
        result
    }

    #[test]
    fn l3_accepted_wins_over_l2() {
        let selected = arbitrate_l3_l2(
            "injection",
            Some(result("attack", 0.90, "L3")),
            result("attack", 0.99, "L2"),
            NtdbOperatingPoint::BestF1,
        );

        assert_eq!(selected.level, "L3");
        assert_eq!(
            selected.layers[0].details.get("final_arbitration"),
            Some(&serde_json::json!("l3"))
        );
    }

    #[test]
    fn l3_rejected_falls_back_to_accepted_l2() {
        let selected = arbitrate_l3_l2(
            "injection",
            Some(result("attack", 0.70, "L3")),
            result("attack", 0.20, "L2"),
            NtdbOperatingPoint::BestF1,
        );

        assert_eq!(selected.level, "L2");
        assert_eq!(
            selected.layers[0].details.get("final_arbitration"),
            Some(&serde_json::json!("l2"))
        );
    }

    #[test]
    fn both_rejected_returns_default_class() {
        let selected = arbitrate_l3_l2(
            "injection",
            Some(result("attack", 0.70, "L3")),
            result("attack", 0.10, "L2"),
            NtdbOperatingPoint::BestF1,
        );

        assert_eq!(selected.class_name, "benign");
        assert!((selected.confidence - 0.3).abs() < f64::EPSILON);
        assert_eq!(
            selected.layers[0].details.get("final_arbitration"),
            Some(&serde_json::json!("default"))
        );
    }

    #[test]
    fn default_arbitration_uses_decision_candidates_not_detail_keys() {
        let selected = arbitrate_l3_l2(
            "injection",
            Some(result("attack", 0.70, "L3")),
            l2_result_with_raw("injection", "benign", 0.90, "attack", 0.10),
            NtdbOperatingPoint::BestF1,
        );

        assert_eq!(selected.class_name, "benign");
        assert!((selected.confidence - 0.3).abs() < f64::EPSILON);
        let details = &selected.layers[0].details;
        assert_eq!(
            details.get("final_arbitration"),
            Some(&serde_json::json!("default"))
        );
        assert!(!details.contains_key("arbitration_l2_raw_class_name"));
        assert!(!details.contains_key("arbitration_l2_raw_confidence"));
        assert!(!details.contains_key("arbitration_l3_raw_class_name"));
        assert!(!details.contains_key("arbitration_l3_raw_confidence"));
        assert!(!details.contains_key("arbitration_union_raw_class_name"));
        assert!(!details.contains_key("arbitration_union_raw_confidence"));

        let decision = selected
            .decision
            .expect("decision envelope should be present");
        assert_eq!(decision.candidates.len(), 3);
        assert_eq!(decision.candidates[0].source, "l2");
        assert_eq!(decision.candidates[0].class_name, "attack");
        assert_eq!(decision.candidates[0].confidence, 0.10);
        assert_eq!(decision.candidates[1].source, "l3");
        assert_eq!(decision.candidates[1].class_name, "attack");
        assert_eq!(decision.candidates[1].confidence, 0.70);
        assert_eq!(decision.candidates[2].source, "union");
        assert_eq!(decision.candidates[2].class_name, "attack");
        let union_confidence = decision.candidates[2].confidence;
        assert!((union_confidence - 0.202).abs() < f64::EPSILON);
        assert_eq!(
            decision.candidates[2]
                .evidence
                .as_ref()
                .and_then(|evidence| evidence.get("l2_weight"))
                .copied(),
            Some(0.83)
        );
        assert_eq!(
            decision.candidates[2]
                .evidence
                .as_ref()
                .and_then(|evidence| evidence.get("l3_weight"))
                .copied(),
            Some(0.17)
        );
        let candidate = decision
            .decision_candidate
            .expect("default should select highest-priority rejected candidate");
        assert_eq!(candidate.source, "l3");
        assert_eq!(candidate.class_name, "attack");
        assert_eq!(candidate.confidence, 0.70);
    }

    #[test]
    fn default_arbitration_sets_decision_envelope_to_rejected_policy_candidate() {
        let selected = arbitrate_l3_l2(
            "threat",
            None,
            l2_result_with_raw(
                "threat",
                "benign",
                0.0,
                "instruction_override",
                0.5640919208526611,
            ),
            NtdbOperatingPoint::BestF1,
        );

        let decision = selected
            .decision
            .expect("classifier result should carry decision envelope");
        let candidate = decision
            .decision_candidate
            .expect("default classifier result should keep rejected policy candidate");
        assert_eq!(decision.schema_version, "ark.decision.v1");
        assert_eq!(decision.final_result.class_name, "benign");
        assert_eq!(decision.final_result.confidence, 0.0);
        assert_eq!(decision.final_result.source, "default");
        assert_eq!(candidate.source, "l2");
        assert_eq!(candidate.class_name, "instruction_override");
        assert_eq!(candidate.confidence, 0.5640919208526611);
        assert_eq!(candidate.acceptance_threshold, 0.86471);
        assert!(!candidate.accepted);
        assert!(!decision.recommendation.accepted);
        assert_eq!(decision.recommendation.final_arbitration, "default");
        assert_eq!(decision.recommendation.operating_point, "best_f1");
        assert_eq!(decision.recommendation.acceptance_threshold, Some(0.86471));
    }

    #[test]
    fn l2_winner_sets_decision_candidate_to_l2_even_when_l3_rejected() {
        let selected = arbitrate_l3_l2(
            "threat",
            Some(result("instruction_override", 0.30, "L3")),
            l2_result_with_raw(
                "threat",
                "instruction_override",
                0.90,
                "instruction_override",
                0.90,
            ),
            NtdbOperatingPoint::BestF1,
        );

        let decision = selected
            .decision
            .expect("classifier result should carry decision envelope");
        let candidate = decision
            .decision_candidate
            .expect("accepted classifier result should carry winning policy candidate");
        assert_eq!(decision.recommendation.final_arbitration, "l2");
        assert!(decision.recommendation.accepted);
        assert_eq!(candidate.source, "l2");
        assert_eq!(candidate.class_name, "instruction_override");
        assert!(candidate.accepted);
        assert_eq!(decision.candidates.len(), 3);
        assert_eq!(decision.candidates[0].source, "l2");
        assert_eq!(decision.candidates[1].source, "l3");
        assert_eq!(decision.candidates[2].source, "union");
    }

    #[test]
    fn multiclass_argmax_below_threshold_returns_default() {
        let selected = arbitrate_l3_l2(
            "routing",
            Some(SecurityScanResult {
                category: "routing".to_string(),
                class_name: "tool_operation_request".to_string(),
                confidence: 0.40,
                level: "L3".to_string(),
                model: "test".to_string(),
                duration_ms: 0.0,
                layers: Vec::new(),
                internal_l2_chunk_outputs: Vec::new(),
                evidence_spans: Vec::new(),
                label_scores: Vec::new(),
                decision: None,
            }),
            SecurityScanResult {
                category: "routing".to_string(),
                class_name: "code_development_request".to_string(),
                confidence: 0.40,
                level: "L2".to_string(),
                model: "test".to_string(),
                duration_ms: 0.0,
                layers: Vec::new(),
                internal_l2_chunk_outputs: Vec::new(),
                evidence_spans: Vec::new(),
                label_scores: Vec::new(),
                decision: None,
            },
            NtdbOperatingPoint::BestF1,
        );

        assert_eq!(selected.class_name, "benign_conv");
    }

    #[test]
    fn unknown_non_default_class_without_threshold_is_rejected() {
        let selected = arbitrate_l3_l2(
            "injection",
            Some(result("unexpected_attack_label", 0.99, "L3")),
            result("unexpected_attack_label", 0.99, "L2"),
            NtdbOperatingPoint::BestF1,
        );

        assert_eq!(selected.class_name, "benign");
        assert_eq!(
            selected.layers[0].details.get("final_arbitration"),
            Some(&serde_json::json!("default"))
        );
    }

    fn v4_context(l2: f32, l3: f32, union: f32) -> std::sync::Arc<JointV3DecisionContext> {
        std::sync::Arc::new(JointV3DecisionContext {
            labels: vec!["benign".to_string(), "attack".to_string()],
            default_class_index: 0,
            l2: JointV3CandidatePolicy {
                aggregation: "max".to_string(),
                risk_margin_threshold: l2,
            },
            l3: JointV3CandidatePolicy {
                aggregation: "max".to_string(),
                risk_margin_threshold: l3,
            },
            union: JointV3CandidatePolicy {
                aggregation: "mean".to_string(),
                risk_margin_threshold: union,
            },
        })
    }

    fn v4_l2_result(
        rows: &[(ByteSpan, Vec<f32>, bool)],
        context: std::sync::Arc<JointV3DecisionContext>,
    ) -> SecurityScanResult {
        let mut scan = result("attack", 0.9, "L2");
        scan.internal_l2_chunk_outputs = rows
            .iter()
            .map(|(span, probabilities, promoted)| L2ChunkOutput {
                span: *span,
                class_name: "attack".to_string(),
                confidence: probabilities[1],
                promoted: *promoted,
                promote_score: Some(if *promoted { 0.9 } else { 0.1 }),
                promote_threshold: Some(0.5),
                source_pipeline: "injection".to_string(),
                source_model: "injection".to_string(),
                embedding: Vec::new(),
                embedding_space: String::new(),
                token_ids: Vec::new(),
                tokenizer_family: "mmbert".to_string(),
                class_probabilities: probabilities.clone(),
                joint_v3_decision: Some(context.clone()),
            })
            .collect();
        scan
    }

    #[test]
    fn v4_union_is_final_while_all_document_candidates_remain_visible() {
        let promoted = ByteSpan { start: 0, end: 10 };
        let other = ByteSpan { start: 10, end: 20 };
        let l2 = v4_l2_result(
            &[
                (promoted, vec![0.4, 0.6], true),
                (other, vec![0.1, 0.9], false),
            ],
            v4_context(0.1, 0.1, 0.1),
        );

        let selected = arbitrate_joint_v3(
            "injection",
            Some(result("attack", 0.9, "L3")),
            l2.clone(),
            &[JointV3L3Chunk {
                span: promoted,
                probabilities: vec![0.1, 0.9],
            }],
            NtdbOperatingPoint::BestF1,
        )
        .unwrap();
        let envelope = selected.decision.as_ref().unwrap();
        assert_eq!(envelope.recommendation.final_arbitration, "union");
        assert_eq!(
            envelope.decision_candidate.as_ref().unwrap().source,
            "union"
        );
        assert!(envelope
            .candidates
            .iter()
            .any(|candidate| candidate.source == "l3" && candidate.accepted));
        let chunk_evidence = selected
            .decision
            .as_ref()
            .unwrap()
            .decision_candidate
            .as_ref()
            .unwrap()
            .chunk_evidence
            .as_ref()
            .unwrap();
        assert_eq!(chunk_evidence["aggregation"], serde_json::json!("mean"));
        assert_eq!(chunk_evidence["contributors"].as_array().unwrap().len(), 2);

        let selected = arbitrate_joint_v3(
            "injection",
            Some(result("benign", 0.55, "L3")),
            l2,
            &[JointV3L3Chunk {
                span: promoted,
                probabilities: vec![0.55, 0.45],
            }],
            NtdbOperatingPoint::BestF1,
        )
        .unwrap();
        assert_eq!(
            selected
                .decision
                .as_ref()
                .unwrap()
                .recommendation
                .final_arbitration,
            "union"
        );
        assert_eq!(
            selected
                .decision
                .as_ref()
                .unwrap()
                .decision_candidate
                .as_ref()
                .unwrap()
                .source,
            "union"
        );
    }

    #[test]
    fn v4_union_candidate_identifies_the_injection_chunk() {
        let spans = [
            ByteSpan { start: 0, end: 10 },
            ByteSpan { start: 10, end: 20 },
            ByteSpan { start: 20, end: 30 },
            ByteSpan { start: 30, end: 40 },
        ];
        let l2 = v4_l2_result(
            &[
                (spans[0], vec![0.45, 0.55], false),
                (spans[1], vec![0.45, 0.55], false),
                (spans[2], vec![0.45, 0.55], false),
                (spans[3], vec![0.45, 0.55], true),
            ],
            v4_context(0.1, 0.1, 0.1),
        );
        let selected = arbitrate_joint_v3(
            "injection",
            Some(result("attack", 0.99, "L3")),
            l2,
            &[JointV3L3Chunk {
                span: spans[3],
                probabilities: vec![0.01, 0.99],
            }],
            NtdbOperatingPoint::BestF1,
        )
        .unwrap();
        let evidence = selected
            .decision
            .as_ref()
            .and_then(|envelope| envelope.decision_candidate.as_ref())
            .and_then(|candidate| candidate.chunk_evidence.as_ref())
            .expect("union candidate should expose chunk evidence");
        assert_eq!(evidence["decisive_chunks"][0]["chunk_id"], 3);
        assert_eq!(evidence["decisive_chunks"][0]["source"], "l3");
        assert_eq!(
            evidence["decisive_chunks"][0]["span"],
            serde_json::json!(spans[3])
        );
    }

    #[test]
    fn v4_rejected_union_returns_default_without_l2_override() {
        let promoted = ByteSpan { start: 0, end: 10 };
        let other = ByteSpan { start: 10, end: 20 };
        let rows = [
            (promoted, vec![0.9, 0.1], true),
            (other, vec![0.1, 0.9], false),
        ];
        let selected = arbitrate_joint_v3(
            "injection",
            Some(result("benign", 0.9, "L3")),
            v4_l2_result(&rows, v4_context(0.0, 0.1, 0.2)),
            &[JointV3L3Chunk {
                span: promoted,
                probabilities: vec![0.9, 0.1],
            }],
            NtdbOperatingPoint::BestF1,
        )
        .unwrap();
        let envelope = selected.decision.as_ref().unwrap();
        assert_eq!(selected.class_name, "benign");
        assert_eq!(envelope.recommendation.final_arbitration, "default");
        assert_eq!(
            envelope.decision_candidate.as_ref().unwrap().source,
            "union"
        );

        let selected = arbitrate_joint_v3(
            "injection",
            Some(result("benign", 0.9, "L3")),
            v4_l2_result(&rows, v4_context(0.1, 0.1, 0.2)),
            &[JointV3L3Chunk {
                span: promoted,
                probabilities: vec![0.9, 0.1],
            }],
            NtdbOperatingPoint::BestF1,
        )
        .unwrap();
        let envelope = selected.decision.unwrap();
        assert_eq!(selected.class_name, "benign");
        assert_eq!(envelope.recommendation.final_arbitration, "default");
        assert_eq!(envelope.decision_candidate.unwrap().source, "union");
        assert!(!envelope.recommendation.accepted);
    }

    #[test]
    fn v4_without_promoted_chunks_still_uses_exported_default_union_mode() {
        let selected = arbitrate_l2(
            "injection",
            v4_l2_result(
                &[(ByteSpan { start: 0, end: 10 }, vec![0.2, 0.8], false)],
                v4_context(0.3, 0.1, 0.1),
            ),
            NtdbOperatingPoint::BestF1,
        );
        let envelope = selected.decision.unwrap();
        assert_eq!(envelope.recommendation.final_arbitration, "union");
        assert_eq!(
            envelope.decision_candidate.as_ref().unwrap().source,
            "union"
        );
        assert!((envelope.decision_candidate.unwrap().acceptance_threshold - 0.1).abs() < 1e-6);
    }
}
