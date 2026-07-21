// SPDX-License-Identifier: GPL-3.0-only
//! NTDB v2 L2 model configuration and result mapping for the gateway.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::{
    ml::ntdb_executor::{manifest::PackageManifest, NtdbDecision, NtdbPackageSpec},
    pipeline::l3_pending_layer,
    EvaluationResult, LayerResult, ScanExecution, SecurityCategory, SecurityLevel,
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
) -> (EvaluationResult, Vec<LayerResult>) {
    let result = EvaluationResult {
        class_name: decision.fallback_label.clone(),
        confidence: decision.fallback_confidence,
        level: "L2".to_string(),
    };
    let mut thresholds = HashMap::new();
    if let Some(threshold) = decision.promote_threshold {
        thresholds.insert("promote".to_string(), threshold);
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
            "l3_candidate_spans".to_string(),
            serde_json::json!(decision.l3_candidate_spans),
        ),
        (
            "class_scores".to_string(),
            serde_json::json!(decision.class_scores),
        ),
        (
            "class_logits".to_string(),
            serde_json::json!(decision.class_logits),
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

    if allow_l3
        && decision.route_to_l3
        && execution.defer_l3()
        && execution.allows_level(SecurityLevel::L3)
        && execution.l3_policy().enabled
    {
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
    let (result, layers) = ntdb_l2_result_parts(decision, execution, duration_ms, allow_l3);
    scan_result(config.category, config.public_model, result, layers)
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
