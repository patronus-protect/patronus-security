// SPDX-License-Identifier: AGPL-3.0-only
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

pub const TOOL_PROMPTS_MODEL: &str = "tool-prompts-model";
pub const TOOL_EXECUTIONS_MODEL: &str = "tool-executions-model";
pub const TOOL_CLASSIFIER_DESCRIPTIONS_MODEL: &str = "tool-classifier-descriptions-model";
pub const NTDB_TOOL_PROMPTS_MODEL_ID: &str = "tool_prompts";
pub const NTDB_TOOL_EXECUTIONS_MODEL_ID: &str = "tool_executions";
pub const NTDB_TOOL_DESCRIPTIONS_MODEL_ID: &str = "tool_descriptions";
const TOOL_CLASS_NAMES: &[&str] = &[
    "tool_class.file.read",
    "tool_class.file.search",
    "tool_class.file.list",
    "tool_class.file.write",
    "tool_class.file.delete",
    "tool_class.shell.execute",
    "tool_class.web.search",
    "tool_class.web.fetch",
    "tool_class.browser.action",
    "tool_class.api.read",
    "tool_class.api.write",
    "tool_class.database.read",
    "tool_class.database.write",
    "tool_class.vcs.read",
    "tool_class.vcs.write",
    "tool_class.memory.read",
    "tool_class.memory.write",
    "tool_class.messaging.send",
    "tool_class.unknown",
];

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct NtdbL2ModelConfig {
    pub category: SecurityCategory,
    pub model_id: &'static str,
    pub public_model: &'static str,
    pub env_key: &'static str,
    pub package_name: &'static str,
    pub has_l3: bool,
}

pub(super) fn tool_classifier_area_enabled(
    execution: &ScanExecution,
    model: &str,
    aliases: &[&str],
) -> bool {
    execution.allows_model("tool_classifier")
        && execution.allows_model(model)
        && aliases.iter().all(|alias| execution.allows_model(alias))
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
        SecurityCategory::SensitiveDocuments => {
            if execution.allows_model("sensitive_documents")
                && execution.allows_model("orca-sonar-document-classifier")
            {
                vec![NtdbL2ModelConfig {
                    category,
                    model_id: "sensitive_documents",
                    public_model: "orca-sonar-document-classifier",
                    env_key: "PATRONUS_NTDB_SENSITIVE_DOCUMENTS_DIR",
                    package_name: "sensitive_documents_current",
                    has_l3: true,
                }]
            } else {
                Vec::new()
            }
        }
        SecurityCategory::ToolClassifier => {
            let mut configs = Vec::new();
            if tool_classifier_area_enabled(
                execution,
                TOOL_PROMPTS_MODEL,
                &[
                    "tool_classifier.prompt",
                    "tool_classifier.prompts",
                    "tool_classifier_prompt",
                    "tool_classifier_prompts",
                ],
            ) {
                configs.push(NtdbL2ModelConfig {
                    category,
                    model_id: NTDB_TOOL_PROMPTS_MODEL_ID,
                    public_model: TOOL_PROMPTS_MODEL,
                    env_key: "PATRONUS_NTDB_TOOL_PROMPTS_DIR",
                    package_name: "tool_prompts_current",
                    has_l3: false,
                });
            }
            if tool_classifier_area_enabled(
                execution,
                TOOL_EXECUTIONS_MODEL,
                &[
                    "tool_classifier.execution",
                    "tool_classifier.executions",
                    "tool_classifier_execution",
                    "tool_classifier_executions",
                ],
            ) {
                configs.push(NtdbL2ModelConfig {
                    category,
                    model_id: NTDB_TOOL_EXECUTIONS_MODEL_ID,
                    public_model: TOOL_EXECUTIONS_MODEL,
                    env_key: "PATRONUS_NTDB_TOOL_EXECUTIONS_DIR",
                    package_name: "tool_executions_current",
                    has_l3: false,
                });
            }
            if tool_classifier_area_enabled(
                execution,
                TOOL_CLASSIFIER_DESCRIPTIONS_MODEL,
                &[
                    "tool_classifier.description",
                    "tool_classifier.descriptions",
                    "tool_classifier_description",
                    "tool_classifier_descriptions",
                ],
            ) {
                configs.push(NtdbL2ModelConfig {
                    category,
                    model_id: NTDB_TOOL_DESCRIPTIONS_MODEL_ID,
                    public_model: TOOL_CLASSIFIER_DESCRIPTIONS_MODEL,
                    env_key: "PATRONUS_NTDB_TOOL_DESCRIPTIONS_DIR",
                    package_name: "tool_descriptions_current",
                    has_l3: false,
                });
            }
            configs
        }
        SecurityCategory::Dlp
        | SecurityCategory::Pii
        | SecurityCategory::DynamicPii
        | SecurityCategory::UserIntent => Vec::new(),
    }
}

#[cfg(feature = "test-util")]
pub fn ntdb_l2_model_config_for_id(model_id: &str) -> Option<NtdbL2ModelConfig> {
    let execution = ScanExecution::new(SecurityLevel::L2);
    [
        SecurityCategory::Injection,
        SecurityCategory::SensitiveDocuments,
        SecurityCategory::ToolClassifier,
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
    let (result, layers) = ntdb_l2_result_parts(decision, execution, duration_ms, config.has_l3);
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
    validate_ntdb_l2_label_contract(config, &manifest)?;
    Ok((NtdbPackageSpec::new(config.model_id, package_dir), manifest))
}

fn validate_ntdb_l2_label_contract(
    config: NtdbL2ModelConfig,
    manifest: &PackageManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    if config.category != SecurityCategory::ToolClassifier {
        return Ok(());
    }

    validate_tool_class_labels(config, "task", &manifest.task.labels)?;
    for aggregator in &manifest.aggregators {
        validate_tool_class_labels(config, &aggregator.id, &aggregator.task.labels)?;
    }
    Ok(())
}

fn validate_tool_class_labels(
    config: NtdbL2ModelConfig,
    scope: &str,
    labels: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if labels.is_empty() {
        return Err(format!(
            "invalid NTDB v2 L2 export for {}/{}: empty tool labels in {}",
            config.category.as_str(),
            config.public_model,
            scope
        )
        .into());
    }
    let unknown = labels
        .iter()
        .filter(|label| !TOOL_CLASS_NAMES.contains(&label.as_str()))
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(format!(
            "invalid NTDB v2 L2 export for {}/{}: unknown tool label(s) in {}: {}",
            config.category.as_str(),
            config.public_model,
            scope,
            unknown
                .into_iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(",")
        )
        .into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool_config() -> NtdbL2ModelConfig {
        NtdbL2ModelConfig {
            category: SecurityCategory::ToolClassifier,
            model_id: NTDB_TOOL_PROMPTS_MODEL_ID,
            public_model: TOOL_PROMPTS_MODEL,
            env_key: "PATRONUS_NTDB_TOOL_PROMPTS_DIR",
            package_name: "tool_prompts_current",
            has_l3: false,
        }
    }

    #[test]
    fn tool_class_label_contract_accepts_known_labels() {
        let labels = vec![
            "tool_class.file.read".to_string(),
            "tool_class.messaging.send".to_string(),
            "tool_class.unknown".to_string(),
        ];

        validate_tool_class_labels(tool_config(), "task", &labels).unwrap();
    }

    #[test]
    fn tool_class_label_contract_rejects_unknown_labels() {
        let labels = vec!["17".to_string(), "tool_class.file.read".to_string()];

        let err = validate_tool_class_labels(tool_config(), "task", &labels)
            .unwrap_err()
            .to_string();

        assert!(err.contains("unknown tool label"));
        assert!(err.contains("17"));
    }
}
