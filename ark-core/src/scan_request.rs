//! Request-local scan options: chunk overlap, the NTDB operating point and
//! `dynamic-pii` labels. Core's tokenizer chunks with [`ChunkOverlapTokens`];
//! Ark and the model-free distributed coordinator parse and validate the other
//! options with these types.
use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::SecurityCategory;

/// Largest overlap, in tokens, between neighbouring model chunks.
pub const MAX_CHUNK_OVERLAP_TOKENS: usize = 64;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// Token overlap between neighbouring model chunks, at most
/// [`MAX_CHUNK_OVERLAP_TOKENS`].
pub struct ChunkOverlapTokens(usize);

impl ChunkOverlapTokens {
    pub const ZERO: Self = Self(0);

    pub fn get(self) -> usize {
        self.0
    }
}

impl TryFrom<i64> for ChunkOverlapTokens {
    type Error = String;

    fn try_from(overlap: i64) -> Result<Self, Self::Error> {
        if !(0..=MAX_CHUNK_OVERLAP_TOKENS as i64).contains(&overlap) {
            return Err(chunk_overlap_error());
        }
        Ok(Self(overlap as usize))
    }
}

impl TryFrom<usize> for ChunkOverlapTokens {
    type Error = String;

    fn try_from(overlap: usize) -> Result<Self, Self::Error> {
        if overlap > MAX_CHUNK_OVERLAP_TOKENS {
            return Err(chunk_overlap_error());
        }
        Ok(Self(overlap))
    }
}

fn chunk_overlap_error() -> String {
    format!("chunk_overlap_tokens must be between 0 and {MAX_CHUNK_OVERLAP_TOKENS}")
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
/// Calibrated NTDB operating point selected from each package manifest.
pub enum NtdbOperatingPoint {
    BestF1,
    #[default]
    BestPromote,
    /// Internal Ark API routing profile: use utility promotion only for an
    /// Injection document with at most two normal chunks.
    ArkApiShortInjectionUtility,
    BestFprInF1,
    BestFnrInF1,
    BestLatencyInF1,
}

impl NtdbOperatingPoint {
    /// Return the manifest key for this operating point.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BestF1 => "best_f1",
            Self::BestPromote => "best_promote",
            Self::ArkApiShortInjectionUtility => "ark_api_short_injection_utility",
            Self::BestFprInF1 => "best_fpr_in_f1",
            Self::BestFnrInF1 => "best_fnr_in_f1",
            Self::BestLatencyInF1 => "best_latency_in_f1",
        }
    }
}

/// Deserializes every name [`str::parse`] accepts.
impl<'de> serde::Deserialize<'de> for NtdbOperatingPoint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for NtdbOperatingPoint {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "best_f1" => Ok(Self::BestF1),
            "best_promote" => Ok(Self::BestPromote),
            "ark_api_short_injection_utility" => Ok(Self::ArkApiShortInjectionUtility),
            "best_fpr_in_f1" => Ok(Self::BestFprInF1),
            "best_fnr_in_f1" => Ok(Self::BestFnrInF1),
            "best_latency_in_f1" => Ok(Self::BestLatencyInF1),
            _ => Err(format!("Unknown NTDB operating point: {s}")),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
/// Request-local condition controlling whether `dynamic-pii` runs.
pub enum DynamicPiiExecutionGate {
    /// Run whenever the category and L3 model are enabled.
    #[default]
    Always,
    /// Run when a source pipeline returns one of the configured results.
    IfResultIn {
        pipeline: String,
        results: Vec<String>,
    },
    /// Run only after a source pipeline finishes without a usable result.
    IfNoResult { pipeline: String },
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
/// Extra label group activated on chunks with a matching final source result.
pub struct DynamicPiiConditionalLabels {
    pub labels: Vec<String>,
    pub when: DynamicPiiResultCondition,
}

/// Longest label, in bytes, that a request-local configuration may name.
pub const MAX_REQUEST_LABEL_BYTES: usize = 64;

/// Most unique labels (base and conditional) one `dynamic-pii` configuration may name.
const MAX_POSSIBLE_LABELS: usize = 30;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Request-local labels, thresholds and gates for `dynamic-pii`.
///
/// For one request it replaces the entity fields of the gateway's
/// `DynamicPiiConfig`: `labels`, `label_thresholds`, `execution_gate` and
/// `conditional_labels`, and `threshold` when given. Input limits, chunking and
/// timeouts stay those of the gateway.
pub struct DynamicPiiRequestConfig {
    /// Canonical entity labels of the base GLiNER group.
    pub labels: Vec<String>,
    /// Default entity score threshold; the gateway's threshold when absent.
    #[serde(default)]
    pub threshold: Option<f32>,
    /// Optional threshold overrides keyed by entity label.
    #[serde(default)]
    pub label_thresholds: HashMap<String, f32>,
    /// Gate deciding whether this pipeline runs.
    #[serde(default)]
    pub execution_gate: DynamicPiiExecutionGate,
    /// Additional labels activated by final source-pipeline results.
    #[serde(default)]
    pub conditional_labels: Vec<DynamicPiiConditionalLabels>,
}

impl DynamicPiiRequestConfig {
    /// Normalize and validate the entity fields: labels, thresholds, the
    /// execution gate and conditional label rules. The gateway's
    /// `DynamicPiiConfig` validates its entity fields with this as well.
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
        if possible_labels.len() > MAX_POSSIBLE_LABELS {
            return Err(format!(
                "dynamic-pii supports at most {MAX_POSSIBLE_LABELS} possible unique labels, got {}",
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
        if let Some(threshold) = self.threshold {
            validate_threshold("threshold", threshold)?;
        }
        for (label, threshold) in &self.label_thresholds {
            if !possible_labels.contains(label) {
                return Err(format!(
                    "dynamic-pii threshold override references unknown label {label:?}"
                ));
            }
            validate_threshold(&format!("label_thresholds.{label}"), *threshold)?;
        }
        Ok(self)
    }

    /// [`Self::validated`] plus the request-only limit of
    /// [`MAX_REQUEST_LABEL_BYTES`] per label.
    pub fn validated_request(self) -> Result<Self, String> {
        let config = self.validated()?;
        if let Some(label) = config
            .possible_labels()
            .into_iter()
            .find(|label| label.len() > MAX_REQUEST_LABEL_BYTES)
        {
            return Err(format!(
                "dynamic-pii label {label:?} is longer than {MAX_REQUEST_LABEL_BYTES} bytes"
            ));
        }
        Ok(config)
    }

    /// Unique base and conditional labels in first-seen order.
    fn possible_labels(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.labels
            .iter()
            .chain(self.conditional_labels.iter().flat_map(|rule| &rule.labels))
            .filter(|label| seen.insert(label.as_str()))
            .cloned()
            .collect()
    }
}

/// GLiNER receives a canonical label with underscores as spaces.
pub fn gliner_inference_label(label: &str) -> String {
    label.replace('_', " ")
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

fn validate_threshold(name: &str, threshold: f32) -> Result<(), String> {
    if threshold.is_finite() && (0.0..=1.0).contains(&threshold) {
        Ok(())
    } else {
        Err(format!("dynamic-pii {name} must be between 0 and 1"))
    }
}
