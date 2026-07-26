// SPDX-License-Identifier: GPL-3.0-only
use std::{collections::HashMap, sync::OnceLock};

use serde::Deserialize;

use crate::{EvaluationResult, NtdbOperatingPoint, SecurityScanResult};

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
    if let Some(l3_result) = l3_result {
        if accepts_result(pipeline, &l3_result, point) {
            return with_arbitration(l3_result, LayerDecision::L3);
        }
        if let Some(result) = union_result(pipeline, &l3_result, &l2_result, point) {
            return with_arbitration(result, LayerDecision::Union);
        }
    }

    if accepts_result(pipeline, &l2_result, point) {
        return with_arbitration(l2_result, LayerDecision::L2);
    }

    let mut result = l2_result;
    result.class_name = default_class(pipeline).to_string();
    result.confidence = 0.0;
    with_arbitration(result, LayerDecision::Default)
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

fn with_arbitration(mut result: SecurityScanResult, decision: LayerDecision) -> SecurityScanResult {
    let selected = arbitration_name(decision);
    for layer in &mut result.layers {
        layer
            .details
            .insert("final_arbitration".to_string(), serde_json::json!(selected));
    }
    result
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
    let key = pipeline_key(pipeline);
    let profile = profile_key(point);
    let union = &thresholds().thresholds.get(key)?.union;
    if union.is_empty() {
        return None;
    }

    let l2_scores = score_map(key, l2_result);
    let l3_scores = score_map(key, l3_result);
    let (class_name, policy, confidence) = union
        .iter()
        .filter(|(class_name, _)| class_name.as_str() != default_class(pipeline))
        .filter_map(|(class_name, profiles)| {
            let policy = profiles.get(profile).or_else(|| profiles.get("best_f1"))?;
            let l2_score = l2_scores.get(class_name)?;
            let l3_score = l3_scores.get(class_name)?;
            let confidence = policy.l2_weight * l2_score + policy.l3_weight * l3_score;
            Some((class_name, policy, confidence))
        })
        .max_by(|left, right| left.2.total_cmp(&right.2))?;

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
    use crate::{LayerResult, SecurityScanResult};

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
            evidence_spans: Vec::new(),
            label_scores: Vec::new(),
        }
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
        assert_eq!(selected.confidence, 0.0);
        assert_eq!(
            selected.layers[0].details.get("final_arbitration"),
            Some(&serde_json::json!("default"))
        );
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
                evidence_spans: Vec::new(),
                label_scores: Vec::new(),
            }),
            SecurityScanResult {
                category: "routing".to_string(),
                class_name: "code_development_request".to_string(),
                confidence: 0.40,
                level: "L2".to_string(),
                model: "test".to_string(),
                duration_ms: 0.0,
                layers: Vec::new(),
                evidence_spans: Vec::new(),
                label_scores: Vec::new(),
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
}
