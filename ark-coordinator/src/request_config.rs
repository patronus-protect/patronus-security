// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;

use patronus_ark_core::cascade::{ScanGateMatrix, SecurityLevel};
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
    gates: Option<ScanGateMatrix>,
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

fn empty_metadata() -> Value {
    serde_json::json!({})
}

impl RequestScanConfig {
    pub fn validate(&self) -> Result<(), String> {
        // The worker's gate schema validates `max_level` and `gates` while parsing.
        let _ = (&self.max_level, &self.gates);
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
        // The gate schema refuses an out-of-range policy while parsing.
        assert!(
            serde_json::from_value::<RequestScanConfig>(serde_json::json!({
                "gates":{"l3_policy":{"degraded_factor":1.1}}
            }))
            .is_err()
        );
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
