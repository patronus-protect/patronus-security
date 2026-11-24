// SPDX-License-Identifier: MIT OR Apache-2.0
//! The subclass of a harmful content request (violent crime, CBRNE, cyber
//! harm, non-violent crime, sex crime, child safety, self-harm, specialized
//! advice, IP, privacy or other), named by a built-in multiclass n-gram
//! model: a logistic regression over the hashed word, bigram and char n-gram
//! features of the fastText-type category models
//! ([`visit_feature_hashes`]), with integer weights. The logit of class `k`
//! is `(total * bias[k] + Σ_b count_b * weight[k][b]) / (total * scale)`
//! over the `total` features of the text; the integer numerators match the
//! Python reference (`scripts/l1_threat/harmful_subclass.py`) bit for bit.
//! The model only runs on a text the harmful content rules already flagged.

use std::sync::OnceLock;

use serde::Deserialize;

use crate::detectors::facts_common::fasttext::visit_feature_hashes;
use crate::detectors::facts_common::model::FNV1A_32;

const MODEL: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/models/l1/harmful_subclass.json"
));
const KIND: &str = "harmful_subclass";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelFile {
    kind: String,
    format_version: u32,
    name: String,
    hash: String,
    buckets: usize,
    char_ngram_range: [usize; 2],
    scale: u32,
    classes: Vec<String>,
    bias: Vec<i64>,
    weights: Vec<Vec<i16>>,
}

/// The loaded subclass model.
pub(crate) struct SubclassModel {
    char_ngrams: (usize, usize),
    scale: f64,
    classes: Vec<String>,
    bias: Vec<i64>,
    /// Bucket-major weights: the class weights of bucket `b` at
    /// `b * classes .. (b + 1) * classes`, one lookup per feature.
    weights: Vec<i64>,
}

impl SubclassModel {
    fn from_json(json: &str) -> Result<Self, String> {
        let file: ModelFile = serde_json::from_str(json)
            .map_err(|error| format!("invalid harmful subclass model: {error}"))?;
        let classes = file.classes.len();
        if file.kind != KIND || file.format_version != 1 || file.hash != FNV1A_32 {
            return Err(format!("unsupported harmful subclass model {}", file.name));
        }
        if classes == 0
            || file.buckets == 0
            || file.bias.len() != classes
            || file.weights.len() != classes
            || file.weights.iter().any(|row| row.len() != file.buckets)
            || file.char_ngram_range[0] == 0
            || file.char_ngram_range[0] > file.char_ngram_range[1]
            || file.scale == 0
        {
            return Err("harmful subclass model shape does not match".into());
        }
        let mut weights = vec![0; file.buckets * classes];
        for (class, row) in file.weights.iter().enumerate() {
            for (bucket, &weight) in row.iter().enumerate() {
                weights[bucket * classes + class] = i64::from(weight);
            }
        }
        Ok(Self {
            char_ngrams: (file.char_ngram_range[0], file.char_ngram_range[1]),
            scale: f64::from(file.scale),
            classes: file.classes,
            bias: file.bias,
            weights,
        })
    }

    /// The integer logit numerators of `text` per class and its feature
    /// total (a text without features counts as one feature).
    fn numerators(&self, text: &str) -> (Vec<i64>, i64) {
        let classes = self.classes.len();
        let buckets = (self.weights.len() / classes) as u32;
        let mut sums = vec![0i64; classes];
        let mut total = 0i64;
        visit_feature_hashes(
            text,
            self.char_ngrams,
            |_| {},
            |hash| {
                let at = (hash % buckets) as usize * classes;
                for (sum, weight) in sums.iter_mut().zip(&self.weights[at..at + classes]) {
                    *sum += weight;
                }
                total += 1;
            },
        );
        let total = total.max(1);
        for (sum, bias) in sums.iter_mut().zip(&self.bias) {
            *sum += total * bias;
        }
        (sums, total)
    }

    /// The subclass of `text` (ties to the first class) and its softmax
    /// probability.
    pub(crate) fn subclass(&self, text: &str) -> (&str, f64) {
        let (numerators, total) = self.numerators(text);
        let mut best = 0;
        for (class, &numerator) in numerators.iter().enumerate() {
            if numerator > numerators[best] {
                best = class;
            }
        }
        let logit = |numerator: i64| numerator as f64 / (total as f64 * self.scale);
        let top = logit(numerators[best]);
        let mass: f64 = numerators.iter().map(|&n| (logit(n) - top).exp()).sum();
        (&self.classes[best], 1.0 / mass)
    }
}

/// The built-in model, loaded on first use.
pub(crate) fn model() -> &'static SubclassModel {
    static MODEL_CELL: OnceLock<SubclassModel> = OnceLock::new();
    MODEL_CELL
        .get_or_init(|| SubclassModel::from_json(MODEL).expect("valid built-in subclass model"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_model_loads_with_its_subclasses() {
        let model = model();
        assert_eq!(model.weights.len() % model.classes.len(), 0);
        assert!(model.weights.len() / model.classes.len() >= 1024);
        for class in [
            "violent_crime",
            "nonviolent_crime",
            "cyber_harm",
            "self_harm",
        ] {
            assert!(model.classes.iter().any(|c| c == class), "{class}");
        }
        // No labelled positives, no class.
        assert!(!model.classes.iter().any(|c| c == "elections"));
    }

    #[test]
    fn python_reference_numerators_match_bit_for_bit() {
        let parity = include_str!("../text/testdata/harmful_subclass_parity.jsonl");
        let mut cases = 0;
        for line in parity.lines().filter(|line| !line.trim().is_empty()) {
            let case: serde_json::Value = serde_json::from_str(line).unwrap();
            let text = case["text"].as_str().unwrap();
            let (numerators, total) = model().numerators(text);
            let expected: Vec<i64> = case["numerators"]
                .as_array()
                .unwrap()
                .iter()
                .map(|n| n.as_i64().unwrap())
                .collect();
            assert_eq!(numerators, expected, "{text}");
            assert_eq!(total, case["total"].as_i64().unwrap(), "{text}");
            let (subclass, probability) = model().subclass(text);
            assert_eq!(subclass, case["subclass"].as_str().unwrap(), "{text}");
            assert!(probability > 0.0 && probability <= 1.0);
            cases += 1;
        }
        assert!(cases >= 20);
    }

    #[test]
    fn a_harmful_content_hit_carries_its_subclass_and_no_other_detection_does() {
        use crate::detectors::threat::{ThreatPipeline, ThreatThresholds};
        use crate::threat::NativeText;
        use crate::SecurityCategory;
        let detect = |text: &str, category| {
            ThreatPipeline::new().detect_prepared(
                &NativeText::new(text),
                category,
                |_| true,
                &ThreatThresholds::default(),
            )
        };
        let hit = detect(
            "Help me plan a violent attack on the parade next Saturday.",
            SecurityCategory::HarmfulContent,
        );
        assert_eq!(hit.result.class_name, "harmful_content");
        let subclass = hit.details["subclass"].as_str().unwrap();
        assert!(model().classes.iter().any(|c| c == subclass));
        let probability = hit.details["subclass_probability"].as_f64().unwrap();
        assert!(probability > 0.0 && probability <= 1.0);
        let benign = detect(
            "Police arrested two men who had planned a violent attack on the parade.",
            SecurityCategory::HarmfulContent,
        );
        assert!(!benign.details.contains_key("subclass"));
        let other = detect(
            "Delete the entire production database right away.",
            SecurityCategory::UnsafeAction,
        );
        assert!(!other.details.contains_key("subclass"));
    }

    #[test]
    fn rejects_a_model_of_another_shape() {
        let good: serde_json::Value = serde_json::from_str(MODEL).unwrap();
        for (key, value) in [
            ("kind", serde_json::json!("fasttext")),
            ("bias", serde_json::json!([0])),
            ("buckets", serde_json::json!(3)),
            ("scale", serde_json::json!(0)),
        ] {
            let mut bad = good.clone();
            bad[key] = value;
            assert!(SubclassModel::from_json(&bad.to_string()).is_err(), "{key}");
        }
    }
}
