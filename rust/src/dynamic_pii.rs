// SPDX-License-Identifier: AGPL-3.0-only
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::SecurityCategory;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
/// Request-local condition controlling whether `dynamic-pii` runs.
pub enum DynamicPiiExecutionGate {
    /// Run whenever the category and L3 model are enabled.
    Always,
    /// Run when a source pipeline returns one of the configured results.
    IfResultIn {
        pipeline: String,
        results: Vec<String>,
    },
    /// Run only after a source pipeline finishes without a usable result.
    IfNoResult { pipeline: String },
}

impl Default for DynamicPiiExecutionGate {
    fn default() -> Self {
        Self::Always
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Positive source-result condition used by a conditional label rule.
pub struct DynamicPiiResultCondition {
    pub pipeline: String,
    pub results: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Labels activated when another pipeline returns a configured result.
pub struct DynamicPiiConditionalLabels {
    pub labels: Vec<String>,
    pub when: DynamicPiiResultCondition,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
/// Pipeline-specific configuration for the L3-only `dynamic-pii` scanner.
pub struct DynamicPiiConfig {
    /// Canonical entity labels; GLiNER receives underscores as spaces in this order.
    pub labels: Vec<String>,
    /// Default entity score threshold.
    pub threshold: f32,
    /// Optional threshold overrides keyed by entity label.
    #[serde(default)]
    pub label_thresholds: HashMap<String, f32>,
    /// Request-local gate deciding whether this pipeline runs.
    #[serde(default)]
    pub execution_gate: DynamicPiiExecutionGate,
    /// Additional labels activated by final source-pipeline results.
    #[serde(default)]
    pub conditional_labels: Vec<DynamicPiiConditionalLabels>,
    /// Maximum accepted UTF-8 input size.
    pub max_text_bytes: usize,
    /// Maximum whitespace-token count per GLiNER chunk.
    pub chunk_size_words: usize,
    /// Repeated whitespace-token count between neighboring chunks.
    pub chunk_overlap_words: usize,
    /// End-to-end queue and inference deadline for one L3 job.
    pub timeout_ms: u64,
}

impl Default for DynamicPiiConfig {
    fn default() -> Self {
        Self {
            labels: ["organization", "location", "date"]
                .map(String::from)
                .to_vec(),
            threshold: 0.5,
            label_thresholds: HashMap::new(),
            execution_gate: DynamicPiiExecutionGate::Always,
            conditional_labels: Vec::new(),
            max_text_bytes: 1024 * 1024,
            chunk_size_words: 256,
            chunk_overlap_words: 32,
            timeout_ms: 5_000,
        }
    }
}

impl DynamicPiiConfig {
    /// Validate and normalize this configuration.
    pub fn validated(mut self) -> Result<Self, String> {
        normalize_labels(&mut self.labels, "labels")?;
        normalize_execution_gate(&mut self.execution_gate)?;
        for (index, rule) in self.conditional_labels.iter_mut().enumerate() {
            normalize_labels(
                &mut rule.labels,
                &format!("conditional_labels[{index}].labels"),
            )?;
            normalize_pipeline(
                &mut rule.when.pipeline,
                &format!("conditional_labels[{index}].when.pipeline"),
            )?;
            normalize_results(
                &mut rule.when.results,
                &format!("conditional_labels[{index}].when.results"),
            )?;
        }
        let possible_labels = self.possible_labels();
        if possible_labels.is_empty() {
            return Err("dynamic-pii must configure at least one possible label".to_string());
        }
        if possible_labels.len() > 30 {
            return Err(format!(
                "dynamic-pii supports at most 30 possible unique labels, got {}",
                possible_labels.len()
            ));
        }
        let mut inference_labels = HashMap::new();
        for label in &possible_labels {
            let inference_label = gliner_inference_label(label);
            if let Some(existing) = inference_labels.insert(inference_label.clone(), label) {
                return Err(format!(
                    "dynamic-pii labels {existing:?} and {label:?} both map to GLiNER label {inference_label:?}"
                ));
            }
        }
        validate_threshold("threshold", self.threshold)?;
        for (label, threshold) in &self.label_thresholds {
            if !possible_labels.contains(label) {
                return Err(format!(
                    "dynamic-pii threshold override references unknown label {label:?}"
                ));
            }
            validate_threshold(&format!("label_thresholds.{label}"), *threshold)?;
        }
        if self.max_text_bytes == 0 {
            return Err("dynamic-pii max_text_bytes must be greater than zero".to_string());
        }
        if !(1..=768).contains(&self.chunk_size_words) {
            return Err("dynamic-pii chunk_size_words must be between 1 and 768".to_string());
        }
        if self.chunk_overlap_words >= self.chunk_size_words {
            return Err(
                "dynamic-pii chunk_overlap_words must be smaller than chunk_size_words".to_string(),
            );
        }
        if self.timeout_ms == 0 {
            return Err("dynamic-pii timeout_ms must be greater than zero".to_string());
        }
        Ok(self)
    }

    pub(crate) fn referenced_pipelines(&self) -> HashSet<&str> {
        let mut pipelines = HashSet::new();
        match &self.execution_gate {
            DynamicPiiExecutionGate::Always => {}
            DynamicPiiExecutionGate::IfResultIn { pipeline, .. }
            | DynamicPiiExecutionGate::IfNoResult { pipeline } => {
                pipelines.insert(pipeline.as_str());
            }
        }
        pipelines.extend(
            self.conditional_labels
                .iter()
                .map(|rule| rule.when.pipeline.as_str()),
        );
        pipelines
    }

    pub(crate) fn resolve(
        &self,
        pipeline_results: &HashMap<String, Vec<String>>,
    ) -> Option<DynamicPiiResolution> {
        if !execution_gate_matches(&self.execution_gate, pipeline_results) {
            return None;
        }
        let mut labels = self.labels.clone();
        let mut seen = labels.iter().cloned().collect::<HashSet<_>>();
        let mut activated_conditional_rules = Vec::new();
        for (index, rule) in self.conditional_labels.iter().enumerate() {
            if result_condition_matches(&rule.when, pipeline_results) {
                activated_conditional_rules.push(index);
                for label in &rule.labels {
                    if seen.insert(label.clone()) {
                        labels.push(label.clone());
                    }
                }
            }
        }
        if labels.is_empty() {
            return None;
        }
        let mut config = self.clone();
        config.labels = labels;
        config
            .label_thresholds
            .retain(|label, _| config.labels.contains(label));
        Some(DynamicPiiResolution {
            config,
            activated_conditional_rules,
        })
    }

    fn possible_labels(&self) -> Vec<String> {
        let mut labels = Vec::new();
        let mut seen = HashSet::new();
        for label in self.labels.iter().chain(
            self.conditional_labels
                .iter()
                .flat_map(|rule| rule.labels.iter()),
        ) {
            if seen.insert(label.clone()) {
                labels.push(label.clone());
            }
        }
        labels
    }

    pub(crate) fn possible_inference_labels(&self) -> Vec<String> {
        self.possible_labels()
            .iter()
            .map(|label| gliner_inference_label(label))
            .collect()
    }

    pub(crate) fn inference_threshold(&self) -> f32 {
        self.label_thresholds
            .values()
            .copied()
            .fold(self.threshold, f32::min)
    }

    pub(crate) fn threshold_for(&self, label: &str) -> f32 {
        self.label_thresholds
            .get(label)
            .copied()
            .unwrap_or(self.threshold)
    }

    pub(crate) fn inference_labels(&self) -> Vec<String> {
        self.labels
            .iter()
            .map(|label| gliner_inference_label(label))
            .collect()
    }

    pub(crate) fn canonical_label_for(&self, inference_label: &str) -> Option<&str> {
        self.labels
            .iter()
            .find(|label| gliner_inference_label(label) == inference_label)
            .map(String::as_str)
    }
}

fn gliner_inference_label(label: &str) -> String {
    label.replace('_', " ")
}

pub(crate) struct DynamicPiiResolution {
    pub config: DynamicPiiConfig,
    pub activated_conditional_rules: Vec<usize>,
}

fn normalize_execution_gate(gate: &mut DynamicPiiExecutionGate) -> Result<(), String> {
    match gate {
        DynamicPiiExecutionGate::Always => Ok(()),
        DynamicPiiExecutionGate::IfResultIn { pipeline, results } => {
            normalize_pipeline(pipeline, "execution_gate.pipeline")?;
            normalize_results(results, "execution_gate.results")
        }
        DynamicPiiExecutionGate::IfNoResult { pipeline } => {
            normalize_pipeline(pipeline, "execution_gate.pipeline")
        }
    }
}

fn normalize_pipeline(pipeline: &mut String, name: &str) -> Result<(), String> {
    let category = pipeline.trim().parse::<SecurityCategory>()?;
    if category == SecurityCategory::DynamicPii {
        return Err(format!("dynamic-pii {name} must not reference dynamic-pii"));
    }
    *pipeline = category.as_str().to_string();
    Ok(())
}

fn normalize_labels(labels: &mut Vec<String>, name: &str) -> Result<(), String> {
    for label in labels.iter_mut() {
        *label = label.trim().to_string();
    }
    if labels.iter().any(String::is_empty) {
        return Err(format!("dynamic-pii {name} must not contain empty values"));
    }
    let mut seen = HashSet::new();
    labels.retain(|label| seen.insert(label.clone()));
    Ok(())
}

fn normalize_results(results: &mut Vec<String>, name: &str) -> Result<(), String> {
    for result in results.iter_mut() {
        *result = result.trim().to_string();
    }
    if results.is_empty() || results.iter().any(String::is_empty) {
        return Err(format!("dynamic-pii {name} must contain non-empty values"));
    }
    let mut seen = HashSet::new();
    results.retain(|result| seen.insert(result.clone()));
    Ok(())
}

fn execution_gate_matches(
    gate: &DynamicPiiExecutionGate,
    pipeline_results: &HashMap<String, Vec<String>>,
) -> bool {
    match gate {
        DynamicPiiExecutionGate::Always => true,
        DynamicPiiExecutionGate::IfResultIn { pipeline, results } => pipeline_results
            .get(pipeline)
            .is_some_and(|actual| actual.iter().any(|value| results.contains(value))),
        DynamicPiiExecutionGate::IfNoResult { pipeline } => pipeline_results
            .get(pipeline)
            .is_none_or(|actual| actual.is_empty()),
    }
}

fn result_condition_matches(
    condition: &DynamicPiiResultCondition,
    pipeline_results: &HashMap<String, Vec<String>>,
) -> bool {
    pipeline_results
        .get(&condition.pipeline)
        .is_some_and(|actual| actual.iter().any(|value| condition.results.contains(value)))
}

fn validate_threshold(name: &str, threshold: f32) -> Result<(), String> {
    if threshold.is_finite() && (0.0..=1.0).contains(&threshold) {
        Ok(())
    } else {
        Err(format!("dynamic-pii {name} must be between 0 and 1"))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Exact evidence span returned by an entity-producing pipeline.
pub struct EvidenceSpan {
    pub label: String,
    pub text: String,
    pub score: f64,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_char: usize,
    pub end_char: usize,
}

#[cfg(test)]
mod tests {
    use super::DynamicPiiConfig;

    #[test]
    fn snake_case_labels_use_natural_language_for_inference() {
        let config = DynamicPiiConfig {
            labels: ["medical_condition", "passport_number"]
                .map(String::from)
                .to_vec(),
            ..DynamicPiiConfig::default()
        }
        .validated()
        .unwrap();

        assert_eq!(
            config.inference_labels(),
            ["medical condition", "passport number"].map(String::from)
        );
        assert_eq!(
            config.canonical_label_for("medical condition"),
            Some("medical_condition")
        );
        assert_eq!(
            config.canonical_label_for("passport number"),
            Some("passport_number")
        );
    }
}
