// SPDX-License-Identifier: GPL-3.0-only
//! Ark's calibrated NTDB decision thresholds (`decision_thresholds.json`) as a
//! Core [`ThresholdTable`], and the Package-v4 joint arbitration.
use std::{collections::HashMap, sync::OnceLock};

use patronus_ark_core::cascade::{
    sync_final_layers, with_arbitration, ArbitrationTrace, LayerDecision, LayeredResult,
    ThresholdTable, UnionPolicy,
};
use serde::Deserialize;

use crate::ml::ntdb_executor::{
    aggregate_probabilities, ByteSpan, JointV3CandidatePolicy, JointV3DecisionContext,
    L2ChunkOutput,
};
use crate::{
    DecisionCandidate, DecisionEnvelope, LabelScore, LayerResult, NtdbOperatingPoint,
    SecurityLevel, SecurityScanResult,
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

static THRESHOLDS: OnceLock<ThresholdAsset> = OnceLock::new();

fn thresholds() -> &'static ThresholdAsset {
    THRESHOLDS.get_or_init(|| {
        serde_json::from_str(include_str!("decision_thresholds.json"))
            .expect("bundled decision threshold JSON must be valid")
    })
}

/// The bundled thresholds at one NTDB operating point; a class without a
/// value at the point falls back to its `best_f1` value.
pub(crate) struct NtdbThresholds {
    profile: &'static str,
}

impl NtdbThresholds {
    pub(crate) fn new(point: NtdbOperatingPoint) -> Self {
        let profile = match point {
            NtdbOperatingPoint::BestF1 => "best_f1",
            NtdbOperatingPoint::BestFprInF1 => "best_fpr",
            NtdbOperatingPoint::BestFnrInF1 => "best_fnr",
            NtdbOperatingPoint::BestPromote => "best_promote",
            NtdbOperatingPoint::ArkApiShortInjectionUtility => "best_promote",
            NtdbOperatingPoint::BestLatencyInF1 => "best_latency_in_f1",
        };
        Self { profile }
    }

    fn at_profile<T: Copy>(&self, profiles: &HashMap<String, T>) -> Option<T> {
        profiles
            .get(self.profile)
            .or_else(|| profiles.get("best_f1"))
            .copied()
    }
}

fn pipeline_key(pipeline: &str) -> &str {
    match pipeline {
        "sensitive_document" => "sensitive_docs",
        // The unified threat head reports under `unsafe_action`.
        "unsafe_action" => "threat",
        other => other,
    }
}

impl ThresholdTable for NtdbThresholds {
    fn operating_point(&self) -> &str {
        self.profile
    }

    fn ark_version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn default_class(&self, pipeline: &str) -> &str {
        match pipeline_key(pipeline) {
            "injection" => "benign",
            "routing" => "benign_conv",
            "sensitive_docs" => "other",
            "threat" => "benign",
            "tool_action" | "tool_class" => "unknown",
            "tool_tags_sink_external"
            | "tool_tags_source_sensitive"
            | "tool_tags_source_untrusted" => "absent",
            _ => "unknown",
        }
    }

    fn threshold(&self, pipeline: &str, layer: SecurityLevel, class_name: &str) -> Option<f64> {
        let pipeline = thresholds().thresholds.get(pipeline_key(pipeline))?;
        let classes = match layer {
            SecurityLevel::L3 => &pipeline.l3,
            _ => &pipeline.l2,
        };
        self.at_profile(classes.get(class_name)?)
    }

    fn union_policies(&self, pipeline: &str) -> Vec<(&str, UnionPolicy)> {
        thresholds()
            .thresholds
            .get(pipeline_key(pipeline))
            .map(|pipeline| {
                pipeline
                    .union
                    .iter()
                    .filter_map(|(class_name, profiles)| {
                        let policy = self.at_profile(profiles)?;
                        Some((
                            class_name.as_str(),
                            UnionPolicy {
                                threshold: policy.threshold,
                                l2_weight: policy.l2_weight,
                                l3_weight: policy.l3_weight,
                            },
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn binary_positive_class(&self, pipeline: &str) -> Option<&str> {
        (pipeline_key(pipeline) == "injection").then_some("attack")
    }
}

impl LayeredResult for SecurityScanResult {
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

/// Core arbitration under the NTDB thresholds; a direct-L3 placeholder
/// without L3 output degrades.
pub(crate) fn arbitrate_l3_l2(
    pipeline: &str,
    l3_result: Option<SecurityScanResult>,
    l2_result: SecurityScanResult,
    point: NtdbOperatingPoint,
) -> SecurityScanResult {
    patronus_ark_core::cascade::arbitrate_l3_l2(
        &NtdbThresholds::new(point),
        pipeline,
        l3_result,
        l2_result,
    )
    .unwrap_or_else(|placeholder| {
        crate::pipeline::degraded_error_result(
            placeholder,
            0.0,
            0,
            1.0,
            "L3 produced no classifier output".to_string(),
        )
    })
}

/// The Package-v4 joint decision when the L2 chunks carry one, otherwise
/// Core L2 arbitration under the NTDB thresholds.
pub(crate) fn arbitrate_l2(
    pipeline: &str,
    l2_result: SecurityScanResult,
    point: NtdbOperatingPoint,
) -> SecurityScanResult {
    if let Some(result) = arbitrate_joint_v3(pipeline, None, l2_result.clone(), &[], point) {
        return result;
    }
    patronus_ark_core::cascade::arbitrate_l2(&NtdbThresholds::new(point), pipeline, l2_result)
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
    let table = NtdbThresholds::new(point);
    let trace = ArbitrationTrace {
        candidates,
        operating_point: table.operating_point().to_string(),
        ark_version: table.ark_version().to_string(),
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
    sync_final_layers(&mut result);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LabelScore, LayerResult, SecurityScanResult};

    fn result(class_name: &str, confidence: f64, level: &str) -> SecurityScanResult {
        SecurityScanResult {
            native: patronus_ark_core::NativeResult {
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
                evidence_spans: Vec::new(),
                label_scores: Vec::new(),
                decision: None,
            },
            internal_l2_chunk_outputs: Vec::new(),
            module_decision: None,
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
    fn direct_l3_never_treats_pending_as_l2_evidence() {
        for (class, confidence, expected) in [
            ("benign", 0.99, "benign"),
            ("attack", 0.70, "benign"),
            ("attack", 0.99, "attack"),
        ] {
            let selected = arbitrate_l3_l2(
                "injection",
                Some(result(class, confidence, "L3")),
                result("pending", 0.0, "L3"),
                NtdbOperatingPoint::BestF1,
            );
            assert_eq!(selected.class_name, expected);
            assert_eq!(selected.level, "L3");
            assert!(selected
                .native
                .decision
                .unwrap()
                .candidates
                .iter()
                .all(|candidate| candidate.source == "l3"));
        }
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
            .native
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
            .native
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
            .native
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
                native: patronus_ark_core::NativeResult {
                    category: "routing".to_string(),
                    class_name: "tool_operation_request".to_string(),
                    confidence: 0.40,
                    level: "L3".to_string(),
                    model: "test".to_string(),
                    duration_ms: 0.0,
                    layers: Vec::new(),
                    evidence_spans: Vec::new(),
                    label_scores: Vec::new(),
                    decision: None,
                },
                internal_l2_chunk_outputs: Vec::new(),
                module_decision: None,
            }),
            SecurityScanResult {
                native: patronus_ark_core::NativeResult {
                    category: "routing".to_string(),
                    class_name: "code_development_request".to_string(),
                    confidence: 0.40,
                    level: "L2".to_string(),
                    model: "test".to_string(),
                    duration_ms: 0.0,
                    layers: Vec::new(),
                    evidence_spans: Vec::new(),
                    label_scores: Vec::new(),
                    decision: None,
                },
                internal_l2_chunk_outputs: Vec::new(),
                module_decision: None,
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
        let envelope = selected.decision.clone().unwrap();
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
        let envelope = selected.decision.clone().unwrap();
        assert_eq!(envelope.recommendation.final_arbitration, "union");
        assert_eq!(
            envelope.decision_candidate.as_ref().unwrap().source,
            "union"
        );
        assert!((envelope.decision_candidate.unwrap().acceptance_threshold - 0.1).abs() < 1e-6);
    }
}
