// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;

use serde::Deserialize;
use serde_json::Value;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestScanConfig {
    #[serde(default)]
    categories: Option<Vec<String>>,
    #[serde(default)]
    max_level: Option<SecurityLevel>,
    #[serde(default)]
    gates: Option<RawGates>,
    #[serde(default = "empty_metadata")]
    metadata: Value,
    #[serde(default)]
    ntdb_operating_point: Option<String>,
    #[serde(default)]
    chunk_overlap_tokens: Option<i64>,
    #[serde(default)]
    dynamic_pii: Option<DynamicPiiRequest>,
}

/// Mirror of the worker's `DynamicPiiRequestConfig`, so that an invalid block is
/// rejected before the job is accepted.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DynamicPiiRequest {
    labels: Vec<String>,
    #[serde(default)]
    threshold: Option<f32>,
    #[serde(default)]
    label_thresholds: HashMap<String, f32>,
    #[serde(default)]
    execution_gate: Option<DynamicPiiGate>,
    #[serde(default)]
    conditional_labels: Vec<DynamicPiiConditionalLabels>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum DynamicPiiGate {
    Always,
    IfResultIn {
        pipeline: String,
        results: Vec<String>,
    },
    IfNoResult {
        pipeline: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DynamicPiiConditionalLabels {
    labels: Vec<String>,
    when: DynamicPiiCondition,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DynamicPiiCondition {
    pipeline: String,
    results: Vec<String>,
}

/// The worker's `SecurityLevel`: every name its `str::parse` accepts.
#[derive(Debug, PartialEq, Eq)]
enum SecurityLevel {
    L1,
    L2,
    L3,
}

impl<'de> Deserialize<'de> for SecurityLevel {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        match name.to_lowercase().as_str() {
            "1" | "l1" => Ok(Self::L1),
            "2" | "l2" => Ok(Self::L2),
            "3" | "l3" => Ok(Self::L3),
            _ => Err(serde::de::Error::custom(format!(
                "Unknown security level: {name}"
            ))),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ScoreMode {
    Strict,
    Balanced,
    Recall,
}

/// Mirror of the worker's `ScanGateMatrix` gate schema.
#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawGates {
    explain: bool,
    l1: Option<bool>,
    l2: Option<bool>,
    l3: Option<bool>,
    models: HashMap<String, bool>,
    rules: HashMap<String, bool>,
    pii_mode: Option<ScoreMode>,
    dlp_mode: Option<ScoreMode>,
    injection_mode: Option<ScoreMode>,
    jailbreak_mode: Option<ScoreMode>,
    prompt_extraction_mode: Option<ScoreMode>,
    tool_poisoning_mode: Option<ScoreMode>,
    agent_config_tampering_mode: Option<ScoreMode>,
    memory_poisoning_mode: Option<ScoreMode>,
    exfiltration_mode: Option<ScoreMode>,
    unsafe_action_mode: Option<ScoreMode>,
    resource_exhaustion_mode: Option<ScoreMode>,
    resource_exhaustion_count_threshold: Option<std::num::NonZeroU64>,
    harmful_content_mode: Option<ScoreMode>,
    toxic_language_mode: Option<ScoreMode>,
    conditional: Vec<ConditionalGate>,
    l3_policy: Option<RawL3Policy>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConditionalGate {
    level: SecurityLevel,
    #[serde(default)]
    pipeline: Option<String>,
    when: GateExpression,
    #[serde(default)]
    l3_policy: Option<L3PipelinePolicy>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum GateExpression {
    All(Vec<GateExpression>),
    Any(Vec<GateExpression>),
    Not(Box<GateExpression>),
    Metadata(MetadataCondition),
    Result(ResultCondition),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataCondition {
    path: String,
    #[serde(default)]
    equals: Option<Value>,
    #[serde(default, rename = "in")]
    in_values: Option<Vec<Value>>,
    #[serde(default)]
    exists: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultCondition {
    pipeline: String,
    #[serde(default)]
    classes: Vec<String>,
    #[serde(default)]
    min_confidence: Option<f64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RawL3Policy {
    enabled: Option<bool>,
    priority: Option<Vec<String>>,
    ttl_ms: Option<HashMap<String, u64>>,
    estimated_cost_ms: Option<HashMap<String, u64>>,
    fairness_quantum_ms: Option<u64>,
    max_wait_ms: Option<u64>,
    degraded_factor: Option<f64>,
    early_exit: Option<L3EarlyExitMode>,
    progress: Option<L3ProgressMode>,
    clustering: Option<L3ClusteringStrategy>,
    representatives_per_cluster: Option<usize>,
    verify_representatives_per_cluster: Option<usize>,
    min_cluster_similarity: Option<f64>,
    max_cluster_size: Option<usize>,
    pipelines: Option<HashMap<String, L3PipelinePolicy>>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum L3EarlyExitMode {
    Disabled,
    ClassStable,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum L3ProgressMode {
    Disabled,
    Progress,
    Provisional,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum L3ClusteringStrategy {
    Disabled,
    RankOnly,
    Representative,
    VerifyRepresentative,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct L3PipelinePolicy {
    #[serde(default)]
    clustering: Option<L3ClusteringStrategy>,
    #[serde(default)]
    representatives_per_cluster: Option<usize>,
    #[serde(default)]
    verify_representatives_per_cluster: Option<usize>,
    #[serde(default)]
    min_cluster_similarity: Option<f64>,
    #[serde(default)]
    max_cluster_size: Option<usize>,
    #[serde(default)]
    aggregation: Option<L3AggregationStrategy>,
    #[serde(default)]
    early_exit: Option<L3PipelineEarlyExit>,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum L3AggregationStrategy {
    AnyPositiveOrHighest {
        positive_class: String,
        threshold: f64,
    },
    HighestRiskAboveThresholdOrConfidence {
        threshold: f64,
    },
    MajorityVoteOrHighest,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum L3PipelineEarlyExit {
    Disabled,
    HeadStable,
    RequestWidePositive,
}

fn empty_metadata() -> Value {
    serde_json::json!({})
}

impl RequestScanConfig {
    pub fn validate(&self) -> Result<(), String> {
        let _ = &self.max_level;
        if !self.metadata.is_object() {
            return Err("config.metadata must be a JSON object".into());
        }
        if let Some(categories) = &self.categories {
            if categories.is_empty() {
                return Err("config.categories must not be empty".into());
            }
            for category in categories {
                if !known_category(category) {
                    return Err(format!("unknown category '{category}'"));
                }
            }
        }
        if let Some(point) = &self.ntdb_operating_point {
            let normalized = point.to_lowercase().replace('-', "_");
            if !matches!(
                normalized.as_str(),
                "best_f1"
                    | "best_promote"
                    | "ark_api_short_injection_utility"
                    | "best_fpr_in_f1"
                    | "best_fnr_in_f1"
                    | "best_latency_in_f1"
            ) {
                return Err(format!("unknown NTDB operating point '{point}'"));
            }
        }
        if self
            .chunk_overlap_tokens
            .is_some_and(|tokens| !(0..=64).contains(&tokens))
        {
            return Err("config.chunk_overlap_tokens must be between 0 and 64".into());
        }
        if let Some(gates) = &self.gates {
            gates.validate()?;
        }
        if let Some(dynamic_pii) = &self.dynamic_pii {
            if self.categories.as_ref().is_some_and(|categories| {
                !categories
                    .iter()
                    .any(|category| category_key(category) == "dynamic_pii")
            }) {
                return Err(
                    "config.dynamic_pii requires the 'dynamic-pii' category in this request".into(),
                );
            }
            dynamic_pii
                .validate()
                .map_err(|error| format!("config.dynamic_pii: {error}"))?;
        }
        Ok(())
    }
}

fn category_key(value: &str) -> String {
    value.trim().to_lowercase().replace('-', "_")
}

/// Same limits as the worker: at most 30 unique labels of up to 64 bytes.
const MAX_DYNAMIC_PII_LABELS: usize = 30;
const MAX_DYNAMIC_PII_LABEL_BYTES: usize = 64;

impl DynamicPiiRequest {
    fn validate(&self) -> Result<(), String> {
        let mut labels = std::collections::HashSet::new();
        let mut gliner_names = HashMap::new();
        for label in self
            .labels
            .iter()
            .chain(self.conditional_labels.iter().flat_map(|rule| &rule.labels))
        {
            let label = label.trim();
            if label.is_empty() {
                return Err("labels must not contain empty values".into());
            }
            if label.len() > MAX_DYNAMIC_PII_LABEL_BYTES {
                return Err(format!(
                    "label {label:?} is longer than {MAX_DYNAMIC_PII_LABEL_BYTES} bytes"
                ));
            }
            // The worker sends labels to GLiNER with `_` as a space.
            if labels.insert(label) {
                if let Some(other) = gliner_names.insert(label.replace('_', " "), label) {
                    return Err(format!(
                        "labels {other:?} and {label:?} map to the same GLiNER label"
                    ));
                }
            }
        }
        if labels.is_empty() || labels.len() > MAX_DYNAMIC_PII_LABELS {
            return Err(format!(
                "between 1 and {MAX_DYNAMIC_PII_LABELS} unique labels are required"
            ));
        }
        let thresholds = self.threshold.iter().chain(self.label_thresholds.values());
        if thresholds
            .into_iter()
            .any(|value| !(0.0..=1.0).contains(value))
        {
            return Err("thresholds must be between 0 and 1".into());
        }
        if let Some(label) = self
            .label_thresholds
            .keys()
            .find(|label| !labels.contains(label.trim()))
        {
            return Err(format!(
                "threshold override references unknown label {label:?}"
            ));
        }
        let sources = match &self.execution_gate {
            Some(DynamicPiiGate::IfResultIn { pipeline, results }) => {
                vec![(pipeline, Some(results))]
            }
            Some(DynamicPiiGate::IfNoResult { pipeline }) => vec![(pipeline, None)],
            Some(DynamicPiiGate::Always) | None => Vec::new(),
        };
        for (pipeline, results) in sources.into_iter().chain(
            self.conditional_labels
                .iter()
                .map(|rule| (&rule.when.pipeline, Some(&rule.when.results))),
        ) {
            if !known_category(pipeline) || category_key(pipeline) == "dynamic_pii" {
                return Err(format!("unsupported source pipeline {pipeline:?}"));
            }
            if results.is_some_and(|results| {
                results.is_empty() || results.iter().any(|result| result.trim().is_empty())
            }) {
                return Err(format!("results for {pipeline:?} must be non-empty"));
            }
        }
        Ok(())
    }
}

fn known_category(value: &str) -> bool {
    matches!(
        value.to_lowercase().as_str(),
        "injection"
            | "dlp"
            | "pii"
            | "dynamic-pii"
            | "dynamic_pii"
            | "sensitive_document"
            | "tool_class"
            | "tool_action"
            | "tool_tags"
            | "routing"
            | "jailbreak"
            | "prompt_extraction"
            | "tool_poisoning"
            | "agent_config_tampering"
            | "memory_poisoning"
            | "exfiltration"
            | "unsafe_action"
            | "resource_exhaustion"
            | "harmful_content"
            | "toxic_language"
            | "shell_command"
            | "shell-command"
    )
}

impl RawGates {
    fn validate(&self) -> Result<(), String> {
        let _ = (
            self.explain,
            self.l1,
            self.l2,
            self.l3,
            &self.models,
            &self.rules,
            &self.pii_mode,
            &self.dlp_mode,
            &self.injection_mode,
            &self.jailbreak_mode,
            &self.prompt_extraction_mode,
            &self.tool_poisoning_mode,
            &self.agent_config_tampering_mode,
            &self.memory_poisoning_mode,
            &self.exfiltration_mode,
            &self.unsafe_action_mode,
            &self.resource_exhaustion_mode,
            &self.resource_exhaustion_count_threshold,
            &self.harmful_content_mode,
            &self.toxic_language_mode,
        );
        for gate in &self.conditional {
            gate.validate()?;
        }
        if let Some(policy) = &self.l3_policy {
            policy.validate()?;
        }
        Ok(())
    }
}

impl ConditionalGate {
    fn validate(&self) -> Result<(), String> {
        if self.level == SecurityLevel::L1 {
            return Err("conditional gates may only target L2 or L3".into());
        }
        if self
            .pipeline
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err("conditional gate pipeline must not be empty".into());
        }
        if self.l3_policy.is_some() && (self.level != SecurityLevel::L3 || self.pipeline.is_none())
        {
            return Err("conditional l3_policy overrides require level L3 and a pipeline".into());
        }
        self.when.validate()?;
        if let Some(policy) = &self.l3_policy {
            policy.validate()?;
        }
        Ok(())
    }
}

impl GateExpression {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::All(items) | Self::Any(items) => {
                if items.is_empty() {
                    return Err("conditional gate all/any must not be empty".into());
                }
                for item in items {
                    item.validate()?;
                }
                Ok(())
            }
            Self::Not(item) => item.validate(),
            Self::Metadata(condition) => condition.validate(),
            Self::Result(condition) => condition.validate(),
        }
    }
}

impl MetadataCondition {
    fn validate(&self) -> Result<(), String> {
        if self.path.trim().is_empty() {
            return Err("metadata gate path must not be empty".into());
        }
        let predicates = usize::from(self.equals.is_some())
            + usize::from(self.in_values.is_some())
            + usize::from(self.exists.is_some());
        if predicates != 1 {
            return Err("metadata gate must configure exactly one predicate".into());
        }
        if self.in_values.as_ref().is_some_and(Vec::is_empty) {
            return Err("metadata gate in list must not be empty".into());
        }
        Ok(())
    }
}

impl ResultCondition {
    fn validate(&self) -> Result<(), String> {
        let _ = &self.classes;
        if self.pipeline.trim().is_empty() {
            return Err("result gate pipeline must not be empty".into());
        }
        validate_fraction(self.min_confidence, "result gate min_confidence")
    }
}

impl RawL3Policy {
    fn validate(&self) -> Result<(), String> {
        let _ = (
            self.enabled,
            &self.priority,
            &self.ttl_ms,
            self.max_wait_ms,
            &self.early_exit,
            &self.progress,
            &self.clustering,
        );
        if [
            self.fairness_quantum_ms.map(|value| value == 0),
            self.representatives_per_cluster.map(|value| value == 0),
            self.verify_representatives_per_cluster
                .map(|value| value == 0),
            self.max_cluster_size.map(|value| value == 0),
        ]
        .contains(&Some(true))
            || self
                .estimated_cost_ms
                .as_ref()
                .is_some_and(|costs| costs.values().any(|&cost| cost == 0))
        {
            return Err(
                "gates.l3_policy counts, costs and fairness_quantum_ms must be positive".into(),
            );
        }
        validate_fraction(self.degraded_factor, "gates.l3_policy degraded_factor")?;
        validate_fraction(
            self.min_cluster_similarity,
            "gates.l3_policy min_cluster_similarity",
        )?;
        if let Some(pipelines) = &self.pipelines {
            for (name, policy) in pipelines {
                if name.trim().is_empty() {
                    return Err("gates.l3_policy pipelines keys must not be empty".into());
                }
                policy.validate()?;
            }
        }
        Ok(())
    }
}

impl L3PipelinePolicy {
    fn validate(&self) -> Result<(), String> {
        let _ = (&self.clustering, &self.early_exit);
        if [
            self.representatives_per_cluster,
            self.verify_representatives_per_cluster,
            self.max_cluster_size,
        ]
        .contains(&Some(0))
        {
            return Err("gates pipeline cluster counts must be positive".into());
        }
        validate_fraction(
            self.min_cluster_similarity,
            "gates pipeline min_cluster_similarity",
        )?;
        if let Some(aggregation) = &self.aggregation {
            aggregation.validate()?;
        }
        Ok(())
    }
}

impl L3AggregationStrategy {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::AnyPositiveOrHighest {
                positive_class,
                threshold,
            } => {
                if positive_class.trim().is_empty() {
                    return Err("aggregation positive_class must not be empty".into());
                }
                validate_fraction(Some(*threshold), "aggregation threshold")
            }
            Self::HighestRiskAboveThresholdOrConfidence { threshold } => {
                validate_fraction(Some(*threshold), "aggregation threshold")
            }
            Self::MajorityVoteOrHighest => Ok(()),
        }
    }
}

fn validate_fraction(value: Option<f64>, field: &str) -> Result<(), String> {
    if value.is_some_and(|value| !value.is_finite() || !(0.0..=1.0).contains(&value)) {
        Err(format!("{field} must be between 0 and 1"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_fields_categories_and_invalid_policy_bounds() {
        assert!(
            serde_json::from_value::<RequestScanConfig>(serde_json::json!({"extra":true})).is_err()
        );
        let unknown: RequestScanConfig =
            serde_json::from_value(serde_json::json!({"categories":["unknown"]})).unwrap();
        assert!(unknown.validate().is_err());
        let shell: RequestScanConfig =
            serde_json::from_value(serde_json::json!({"categories":["shell_command"]})).unwrap();
        assert!(shell.validate().is_ok());
        let bad_policy: RequestScanConfig = serde_json::from_value(serde_json::json!({
            "gates":{"l3_policy":{"degraded_factor":1.1}}
        }))
        .unwrap();
        assert!(bad_policy.validate().is_err());
    }

    /// ark-api checks the same fixture (`routes::scan` tests).
    #[test]
    fn request_configs_match_the_shared_fixture() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../ark-api/tests/fixtures/scan_request_configs.json"
        ))
        .unwrap();
        let check = |request: &Value| {
            serde_json::from_value::<RequestScanConfig>(request.clone())
                .map_err(|error| error.to_string())
                .and_then(|request| request.validate())
        };
        for request in fixture["accepted"].as_array().unwrap() {
            assert_eq!(check(request), Ok(()), "{request}");
        }
        for request in fixture["refused"].as_array().unwrap() {
            assert!(check(request).is_err(), "{request} must be refused");
        }
    }

    #[test]
    fn dynamic_pii_block_is_validated_like_the_worker() {
        let check = |value: Value| {
            serde_json::from_value::<RequestScanConfig>(value)
                .map_err(|error| error.to_string())
                .and_then(|config| config.validate())
        };
        assert!(check(serde_json::json!({
            "categories": ["dynamic-pii"],
            "dynamic_pii": {
                "labels": ["street_address", "person"],
                "label_thresholds": {"street_address": 0.4},
                "execution_gate": {"type": "if_result_in", "pipeline": "dlp", "results": ["safe"]}
            }
        }))
        .is_ok());
        assert!(check(serde_json::json!({"dynamic_pii": {"labels": ["person"]}})).is_ok());

        let too_many = (0..31)
            .map(|index| format!("label_{index}"))
            .collect::<Vec<_>>();
        for invalid in [
            serde_json::json!({"categories": ["pii"], "dynamic_pii": {"labels": ["person"]}}),
            serde_json::json!({"dynamic_pii": {"labels": []}}),
            serde_json::json!({"dynamic_pii": {"labels": ["person"], "timeout_ms": 1}}),
            serde_json::json!({"dynamic_pii": {"labels": ["person"], "threshold": 1.5}}),
            serde_json::json!({"dynamic_pii": {"labels": ["person"], "label_thresholds": {"city": 0.4}}}),
            serde_json::json!({"dynamic_pii": {"labels": too_many}}),
            serde_json::json!({"dynamic_pii": {"labels": ["x".repeat(65)]}}),
            serde_json::json!({"dynamic_pii": {"labels": ["first_name", "first name"]}}),
            serde_json::json!({"dynamic_pii": {
                "labels": ["person"],
                "execution_gate": {"type": "if_no_result", "pipeline": "dynamic-pii"}
            }}),
            serde_json::json!({"dynamic_pii": ["street_address"]}),
        ] {
            assert!(
                check(invalid.clone()).is_err(),
                "{invalid} must be rejected"
            );
        }
    }
}
