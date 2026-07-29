// SPDX-License-Identifier: GPL-3.0-only
//! NTDB v2 L2 model configuration and result mapping for the gateway.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::{
    ml::ntdb_executor::{manifest::PackageManifest, NtdbDecision, NtdbPackageSpec},
    pipeline::decision_thresholds::{arbitrate_l2, arbitration_name, threshold_l2_result},
    pipeline::l3_pending_layer,
    EvaluationResult, LabelScore, LayerResult, ScanExecution, SecurityCategory, SecurityLevel,
    SecurityScanResult,
};

use super::scan_result;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NtdbL2ModelConfig {
    pub category: SecurityCategory,
    pub model_id: &'static str,
    pub public_model: &'static str,
    pub env_key: &'static str,
    pub package_name: &'static str,
    pub has_l3: bool,
}

pub fn ntdb_l2_model_configs_for_category(
    execution: &ScanExecution,
    category: SecurityCategory,
) -> Vec<NtdbL2ModelConfig> {
    if !execution.allows_level(SecurityLevel::L2) {
        return Vec::new();
    }

    match category {
        SecurityCategory::Injection => {
            if execution.allows_model("injection") && execution.allows_model("wolf-defender-small")
            {
                vec![NtdbL2ModelConfig {
                    category,
                    model_id: "injection",
                    public_model: "wolf-defender-small",
                    env_key: "PATRONUS_NTDB_INJECTION_DIR",
                    package_name: "injection_current",
                    has_l3: true,
                }]
            } else {
                Vec::new()
            }
        }
        SecurityCategory::SensitiveDocument => {
            if execution.allows_model("sensitive_document")
                && execution.allows_model("orca-sonar-document-classifier")
            {
                vec![NtdbL2ModelConfig {
                    category,
                    model_id: "sensitive_document",
                    public_model: "orca-sonar-document-classifier",
                    env_key: "PATRONUS_NTDB_SENSITIVE_DOCUMENTS_DIR",
                    package_name: "sensitive_document_current",
                    has_l3: true,
                }]
            } else {
                Vec::new()
            }
        }
        SecurityCategory::ToolClass => model_config(
            execution,
            category,
            "unified-v3-tool-class",
            "PATRONUS_NTDB_TOOL_CLASS_DIR",
            "tool_class_current",
        ),
        SecurityCategory::ToolAction => model_config(
            execution,
            category,
            "unified-v3-tool-action",
            "PATRONUS_NTDB_TOOL_ACTION_DIR",
            "tool_action_current",
        ),
        SecurityCategory::ToolTags => model_config(
            execution,
            category,
            "unified-v3-tool-tags",
            "PATRONUS_NTDB_TOOL_TAGS_DIR",
            "tool_tags_current",
        ),
        SecurityCategory::Routing => model_config(
            execution,
            category,
            "unified-v3-routing",
            "PATRONUS_NTDB_ROUTING_DIR",
            "routing_current",
        ),
        SecurityCategory::Threat => model_config(
            execution,
            category,
            "unified-v3-threat",
            "PATRONUS_NTDB_THREAT_DIR",
            "threat_current",
        ),
        SecurityCategory::Dlp | SecurityCategory::Pii | SecurityCategory::DynamicPii => Vec::new(),
    }
}

fn model_config(
    execution: &ScanExecution,
    category: SecurityCategory,
    public_model: &'static str,
    env_key: &'static str,
    package_name: &'static str,
) -> Vec<NtdbL2ModelConfig> {
    if !execution.allows_model(category.as_str()) || !execution.allows_model(public_model) {
        return Vec::new();
    }
    vec![NtdbL2ModelConfig {
        category,
        model_id: category.as_str(),
        public_model,
        env_key,
        package_name,
        has_l3: true,
    }]
}

#[cfg(feature = "test-util")]
pub fn ntdb_l2_model_config_for_id(model_id: &str) -> Option<NtdbL2ModelConfig> {
    let execution = ScanExecution::new(SecurityLevel::L2);
    [
        SecurityCategory::Injection,
        SecurityCategory::SensitiveDocument,
        SecurityCategory::ToolClass,
        SecurityCategory::ToolAction,
        SecurityCategory::ToolTags,
        SecurityCategory::Routing,
        SecurityCategory::Threat,
    ]
    .into_iter()
    .flat_map(|category| ntdb_l2_model_configs_for_category(&execution, category))
    .find(|config| config.model_id == model_id)
}

#[cfg(feature = "test-util")]
pub fn ntdb_l2_enabled_for_category(execution: &ScanExecution, category: SecurityCategory) -> bool {
    !ntdb_l2_model_configs_for_category(execution, category).is_empty()
}

pub(super) fn ntdb_l2_package_dir(
    config: NtdbL2ModelConfig,
    category_dir: &std::path::Path,
) -> PathBuf {
    if let Some(path) = std::env::var_os(config.env_key).map(PathBuf::from) {
        return path;
    }

    category_dir.join("l2_ntdb").join(config.package_name)
}

pub(super) fn ntdb_l2_cache_namespace(model_id: &str, aggregator_id: &str) -> String {
    format!("ntdb_l2:{model_id}:{aggregator_id}")
}

pub(super) fn ntdb_l2_error_scan_result(
    config: NtdbL2ModelConfig,
    error: impl Into<String>,
) -> SecurityScanResult {
    let result = EvaluationResult {
        class_name: "error".to_string(),
        confidence: 0.0,
        level: "L2".to_string(),
    };
    let layer = LayerResult {
        level: result.level.clone(),
        layer_type: "ntdb_error".to_string(),
        class_name: result.class_name.clone(),
        confidence: result.confidence,
        matched: true,
        duration_ms: 0.0,
        thresholds: HashMap::new(),
        details: HashMap::from([
            (
                "ntdb_model_id".to_string(),
                serde_json::json!(config.model_id),
            ),
            ("error".to_string(), serde_json::json!(error.into())),
        ]),
    };
    scan_result(config.category, config.public_model, result, vec![layer])
}

pub(super) fn ntdb_l2_result_parts(
    decision: &NtdbDecision,
    execution: &ScanExecution,
    duration_ms: f64,
    allow_l3: bool,
    source_pipeline: &str,
) -> (EvaluationResult, Vec<LayerResult>) {
    let raw_result = EvaluationResult {
        class_name: decision.fallback_label.clone(),
        confidence: decision.fallback_confidence,
        level: "L2".to_string(),
    };
    let l3_pending = allow_l3
        && decision.route_to_l3
        && execution.defer_l3()
        && execution.allows_level(SecurityLevel::L3)
        && execution.l3_policy().enabled;
    let (result, final_arbitration) = threshold_l2_result(
        source_pipeline,
        raw_result.clone(),
        execution.ntdb_decision_threshold_point(),
    );
    let mut thresholds = HashMap::new();
    if let Some(threshold) = decision.promote_threshold {
        thresholds.insert("promote".to_string(), threshold);
    }
    let mut l3_candidates = decision.l3_candidates.clone();
    for candidate in &mut l3_candidates {
        candidate.source_pipeline = source_pipeline.to_string();
    }
    let mut l2_chunk_outputs = decision.l2_chunk_outputs.clone();
    for chunk in &mut l2_chunk_outputs {
        chunk.source_pipeline = source_pipeline.to_string();
    }
    let mut details = HashMap::from([
        (
            "ntdb_model_id".to_string(),
            serde_json::json!(decision.model_id),
        ),
        (
            "aggregator_id".to_string(),
            serde_json::json!(decision.aggregator_id),
        ),
        ("task".to_string(), serde_json::json!(decision.task)),
        (
            "route_to_l3".to_string(),
            serde_json::json!(decision.route_to_l3),
        ),
        ("chunks".to_string(), serde_json::json!(decision.chunks)),
        (
            "chunk_promote_scores".to_string(),
            serde_json::json!(decision.chunk_promote_scores),
        ),
        (
            "l3_candidates".to_string(),
            serde_json::json!(l3_candidates),
        ),
        (
            "l2_chunk_outputs".to_string(),
            serde_json::json!(l2_chunk_outputs),
        ),
        (
            "class_scores".to_string(),
            serde_json::json!(decision.class_scores),
        ),
        (
            "class_logits".to_string(),
            serde_json::json!(decision.class_logits),
        ),
        (
            "final_arbitration".to_string(),
            serde_json::json!(arbitration_name(final_arbitration)),
        ),
    ]);
    if let Some(score) = decision.promote_score {
        details.insert("promote_score".to_string(), serde_json::json!(score));
    }
    if let Some(threshold) = decision.promote_threshold {
        details.insert(
            "promote_threshold".to_string(),
            serde_json::json!(threshold),
        );
    }

    let mut layers = vec![LayerResult {
        level: result.level.clone(),
        layer_type: "ntdb_l2".to_string(),
        class_name: result.class_name.clone(),
        confidence: result.confidence,
        matched: true,
        duration_ms,
        thresholds,
        details,
    }];

    if l3_pending {
        layers.push(l3_pending_layer(&result, execution));
    }

    (result, layers)
}

pub fn ntdb_l2_scan_result(
    config: NtdbL2ModelConfig,
    decision: &NtdbDecision,
    execution: &ScanExecution,
    duration_ms: f64,
) -> SecurityScanResult {
    let allow_l3 = config.has_l3
        && (execution.l3_strategy() == crate::L3Strategy::Dedicated
            || execution.allows_model(crate::ml::unified_onnx::UNIFIED_MODEL));
    let (result, layers) = ntdb_l2_result_parts(
        decision,
        execution,
        duration_ms,
        allow_l3,
        config.category.as_str(),
    );
    let mut scan = scan_result(config.category, config.public_model, result, layers);
    scan.label_scores = decision
        .labels
        .iter()
        .zip(decision.class_scores.iter())
        .filter(|(label, _)| label.as_str() != "promote")
        .map(|(label, confidence)| LabelScore {
            label: label.clone(),
            confidence: f64::from(confidence.clamp(0.0, 1.0)),
            matched: label == &decision.fallback_label,
        })
        .collect();
    let has_l3_pending = crate::pipeline::has_l3_pending(&scan);
    scan = arbitrate_l2(
        config.category.as_str(),
        scan,
        execution.ntdb_decision_threshold_point(),
    );
    if has_l3_pending {
        scan.decision = None;
    }
    scan
}

pub(super) fn validate_ntdb_l2_package(
    config: NtdbL2ModelConfig,
    package_dir: PathBuf,
) -> Result<(NtdbPackageSpec, PackageManifest), Box<dyn std::error::Error>> {
    let manifest_path = package_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Err(format!(
            "missing NTDB v2 L2 export for {}/{} at {}",
            config.category.as_str(),
            config.public_model,
            manifest_path.display()
        )
        .into());
    }
    let manifest: PackageManifest =
        serde_json::from_str(&std::fs::read_to_string(&manifest_path)?)?;
    manifest.validate().map_err(|err| {
        format!(
            "invalid NTDB v2 L2 export for {}/{}: {err}",
            config.category.as_str(),
            config.public_model
        )
    })?;
    Ok((NtdbPackageSpec::new(config.model_id, package_dir), manifest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ml::ntdb_executor::NtdbDecision, NtdbOperatingPoint};

    #[test]
    fn promoted_l2_fallback_still_obeys_decision_thresholds() {
        let decision = NtdbDecision {
            model_id: "threat".to_string(),
            aggregator_id: "test".to_string(),
            task: "multiclass".to_string(),
            labels: vec![
                "benign".to_string(),
                "instruction_override".to_string(),
                "promote".to_string(),
            ],
            fallback_label: "instruction_override".to_string(),
            fallback_confidence: 0.5640919208526611,
            route_to_l3: true,
            promote_score: Some(0.9),
            promote_threshold: Some(0.8),
            class_scores: vec![0.1, 0.5640919, 0.9],
            class_logits: Vec::new(),
            chunks: 1,
            chunk_promote_scores: vec![Some(0.9)],
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        };
        let mut execution = ScanExecution::new(SecurityLevel::L3);
        execution.set_defer_l3(true);
        execution.set_ntdb_decision_threshold_point(NtdbOperatingPoint::BestF1);

        let (result, layers) = ntdb_l2_result_parts(&decision, &execution, 1.0, true, "threat");

        assert_eq!(result.class_name, "benign");
        assert_eq!(result.confidence, 0.0);
        assert!(layers.iter().any(|layer| {
            layer.layer_type == "ntdb_l2"
                && layer.details.get("final_arbitration") == Some(&serde_json::json!("default"))
                && !layer.details.contains_key("arbitration_l2_raw_class_name")
                && !layer.details.contains_key("arbitration_l2_raw_confidence")
        }));
        assert!(layers.iter().any(|layer| {
            layer.level == "L3"
                && layer.layer_type == "l3_pending"
                && layer.details.get("fallback_class") == Some(&serde_json::json!("benign"))
        }));
    }

    #[test]
    fn l2_pending_result_has_no_authoritative_decision() {
        let decision = NtdbDecision {
            model_id: "threat".to_string(),
            aggregator_id: "test".to_string(),
            task: "multiclass".to_string(),
            labels: vec![
                "benign".to_string(),
                "instruction_override".to_string(),
                "promote".to_string(),
            ],
            fallback_label: "instruction_override".to_string(),
            fallback_confidence: 0.91,
            route_to_l3: true,
            promote_score: Some(0.9),
            promote_threshold: Some(0.8),
            class_scores: vec![0.1, 0.91, 0.9],
            class_logits: Vec::new(),
            chunks: 1,
            chunk_promote_scores: vec![Some(0.9)],
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        };
        let mut execution = ScanExecution::new(SecurityLevel::L3);
        execution.set_defer_l3(true);

        let result = ntdb_l2_scan_result(
            NtdbL2ModelConfig {
                category: SecurityCategory::Threat,
                model_id: "threat",
                public_model: "unified-v3-threat",
                env_key: "TEST",
                package_name: "test",
                has_l3: true,
            },
            &decision,
            &execution,
            1.0,
        );

        assert!(result
            .layers
            .iter()
            .any(|layer| layer.layer_type == "l3_pending"));
        assert!(result.decision.is_none());
    }

    #[test]
    fn ntdb_l2_default_result_uses_decision_envelope_not_raw_detail_keys() {
        let decision = NtdbDecision {
            model_id: "threat".to_string(),
            aggregator_id: "test".to_string(),
            task: "multiclass".to_string(),
            labels: vec![
                "benign".to_string(),
                "instruction_override".to_string(),
                "promote".to_string(),
            ],
            fallback_label: "instruction_override".to_string(),
            fallback_confidence: 0.5640919208526611,
            route_to_l3: false,
            promote_score: Some(0.1),
            promote_threshold: Some(0.8),
            class_scores: vec![0.1, 0.5640919, 0.1],
            class_logits: Vec::new(),
            chunks: 1,
            chunk_promote_scores: vec![Some(0.1)],
            l3_candidate_spans: Vec::new(),
            l3_candidates: Vec::new(),
            l2_chunk_outputs: Vec::new(),
        };
        let execution = ScanExecution::new(SecurityLevel::L2);
        let result = ntdb_l2_scan_result(
            NtdbL2ModelConfig {
                category: SecurityCategory::Threat,
                model_id: "threat",
                public_model: "unified-v3-threat",
                env_key: "TEST",
                package_name: "test",
                has_l3: true,
            },
            &decision,
            &execution,
            1.0,
        );

        let envelope = result
            .decision
            .expect("NTDB L2 result should carry decision envelope");
        let candidate = envelope
            .decision_candidate
            .expect("default NTDB L2 result should carry rejected candidate");
        assert_eq!(candidate.source, "l2");
        assert_eq!(candidate.class_name, "instruction_override");
        assert_eq!(candidate.acceptance_threshold, 0.86471);
        assert!(!candidate.accepted);
        assert!(!result.layers[0]
            .details
            .contains_key("arbitration_l2_raw_class_name"));
        assert!(!result.layers[0]
            .details
            .contains_key("arbitration_l2_raw_confidence"));
    }
}
