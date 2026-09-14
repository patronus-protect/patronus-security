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
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
enum SecurityLevel {
    L1,
    L2,
    L3,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGates {
    #[serde(default)]
    explain: bool,
    #[serde(default)]
    l1: Option<bool>,
    #[serde(default)]
    l2: Option<bool>,
    #[serde(default)]
    l3: Option<bool>,
    #[serde(default)]
    models: HashMap<String, bool>,
    #[serde(default)]
    rules: HashMap<String, bool>,
    #[serde(default)]
    conditional: Vec<ConditionalGate>,
    #[serde(default)]
    policy: Option<RawL3Policy>,
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
#[serde(deny_unknown_fields)]
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
    #[serde(alias = "execution")]
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
    #[serde(default, alias = "execution")]
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
        if let Some(gates) = &self.gates {
            gates.validate()?;
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
            | "threat"
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
        );
        for gate in &self.conditional {
            gate.validate()?;
        }
        if let Some(policy) = &self.policy {
            policy.validate()?;
        }
        Ok(())
    }
}

impl ConditionalGate {
    fn validate(&self) -> Result<(), String> {
        if matches!(self.level, SecurityLevel::L1) {
            return Err("conditional gates may only target L2 or L3".into());
        }
        if self
            .pipeline
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err("conditional gate pipeline must not be empty".into());
        }
        if self.l3_policy.is_some()
            && (!matches!(self.level, SecurityLevel::L3) || self.pipeline.is_none())
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
            &self.estimated_cost_ms,
            self.max_wait_ms,
            &self.early_exit,
            &self.progress,
            &self.clustering,
            self.representatives_per_cluster,
            self.verify_representatives_per_cluster,
        );
        if self.fairness_quantum_ms == Some(0) || self.max_cluster_size == Some(0) {
            return Err(
                "gates.policy fairness_quantum_ms and max_cluster_size must be positive".into(),
            );
        }
        validate_fraction(self.degraded_factor, "gates.policy degraded_factor")?;
        validate_fraction(
            self.min_cluster_similarity,
            "gates.policy min_cluster_similarity",
        )?;
        if let Some(pipelines) = &self.pipelines {
            for policy in pipelines.values() {
                policy.validate()?;
            }
        }
        Ok(())
    }
}

impl L3PipelinePolicy {
    fn validate(&self) -> Result<(), String> {
        let _ = (
            &self.clustering,
            self.representatives_per_cluster,
            self.verify_representatives_per_cluster,
            &self.early_exit,
        );
        if self.max_cluster_size == Some(0) {
            return Err("gates pipeline max_cluster_size must be positive".into());
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
        let bad_policy: RequestScanConfig = serde_json::from_value(serde_json::json!({
            "gates":{"policy":{"degraded_factor":1.1}}
        }))
        .unwrap();
        assert!(bad_policy.validate().is_err());
    }
}
