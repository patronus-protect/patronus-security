// SPDX-License-Identifier: MIT OR Apache-2.0
//! The fastText-type model form: supervised fastText (Joulin et al., "Bag of
//! Tricks for Efficient Text Classification") over hashed features.
//!
//! Features of a text, in order: per word of Python's `str.split()`
//! (lowercased) `w:<word>`, `b:<previous> <word>` from the second word on and
//! the char n-grams `c:<gram>` of `<word>` by start offset, then length; then
//! the fact tokens of the analyzer as they are (its word tokens repeat the
//! `w:` features). A feature's bucket is the 32-bit FNV-1a hash of its UTF-8 bytes
//! modulo `buckets`; a text's vector is the average of its buckets'
//! embeddings, followed by a linear softmax over (negative, positive).
//!
//! The output layer folds into one value per bucket at load time,
//! `Σ_j E[b][j] * (W[1][j] - W[0][j])`, so a score is one lookup per feature:
//! `Σ_b count_b * value_b` in bucket order, divided by the feature count,
//! plus `bias[1] - bias[0]` — the positive minus the negative logit. Training
//! and the Python reference live in `scripts/l1_threat/category_model.py`;
//! the order of every operation matches it bit for bit.

use std::collections::BTreeMap;

use rustc_hash::FxHashMap;
use serde::Deserialize;

use crate::detectors::facts_common::model::{
    fnv1a_32_extend, for_each_word, ModelForm, TopFeature, FNV1A_32, TOP_FEATURES,
};
use crate::detectors::facts_common::pyjson::py_round;
use crate::detectors::facts_common::thresholds::L1Thresholds;

const KIND: &str = "fasttext";
const FNV1A_32_OFFSET: u32 = 0x811c_9dc5;

/// A `kind: fasttext` `model.json`.
#[derive(Deserialize)]
struct ModelFile {
    kind: String,
    format_version: u32,
    name: String,
    analyzer_func: String,
    hash: String,
    buckets: usize,
    dim: usize,
    char_ngram_range: [usize; 2],
    embeddings: Vec<f64>,
    output: Vec<f64>,
    bias: [f64; 2],
    thresholds: BTreeMap<String, f64>,
    decision_rule: String,
}

/// A loaded fastText-type model with the output layer folded into one value
/// per bucket.
pub struct FastTextModel {
    name: String,
    char_ngrams: (usize, usize),
    values: Vec<f64>,
    bias: f64,
    thresholds: L1Thresholds,
}

/// Whether a `model.json` document is of the fastText-type form.
pub fn is_fasttext(document: &serde_json::Value) -> bool {
    document.get("kind").and_then(serde_json::Value::as_str) == Some(KIND)
}

impl FastTextModel {
    /// Parse and validate a `kind: fasttext` `model.json` of the given form.
    pub fn from_json_slice(bytes: &[u8], form: ModelForm) -> Result<Self, String> {
        let label = form.label;
        let file: ModelFile = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid {label} fastText model JSON: {error}"))?;
        if file.kind != KIND || file.format_version != 1 {
            return Err(format!(
                "unsupported {label} fastText model kind {} format_version {}",
                file.kind, file.format_version
            ));
        }
        if file.analyzer_func != form.analyzer {
            return Err(format!(
                "{label} fastText model must use the {} analyzer",
                form.analyzer
            ));
        }
        if file.hash != FNV1A_32 || file.decision_rule != "score > threshold" {
            return Err(format!(
                "unsupported {label} fastText hash or decision_rule"
            ));
        }
        let [min_n, max_n] = file.char_ngram_range;
        let (buckets, dim) = (file.buckets, file.dim);
        if min_n == 0
            || min_n > max_n
            || buckets == 0
            || buckets > u32::MAX as usize
            || dim == 0
            || Some(file.embeddings.len()) != buckets.checked_mul(dim)
            || file.output.len() != 2 * dim
        {
            return Err(format!(
                "{label} fastText model shape does not match buckets x dim"
            ));
        }
        let delta: Vec<f64> = (0..dim)
            .map(|j| file.output[dim + j] - file.output[j])
            .collect();
        let values = file
            .embeddings
            .chunks_exact(dim)
            .map(|row| row.iter().zip(&delta).fold(0.0, |sum, (e, d)| sum + e * d))
            .collect();
        Ok(Self {
            thresholds: L1Thresholds::from_model(
                &file.thresholds,
                form,
                &format!("{label} fastText model"),
            )?,
            name: file.name,
            char_ngrams: (min_n, max_n),
            values,
            bias: file.bias[1] - file.bias[0],
        })
    }

    /// Model name recorded in `model.json`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The detect and clear cuts on the decision score.
    pub fn thresholds(&self) -> L1Thresholds {
        self.thresholds
    }

    /// Number of embedding buckets.
    pub fn buckets(&self) -> usize {
        self.values.len()
    }

    /// Decision score of `text` given its analyzer tokens (passed to the
    /// visitor): the bucket values summed in feature order from zero, divided
    /// by the feature count, plus the bias difference. One lookup per
    /// feature, no allocation beyond the reused word buffers.
    pub fn logit(&self, text: &str, tokens: impl FnOnce(&mut dyn FnMut(&str))) -> f64 {
        let (mut dot, mut total) = (0.0, 0u64);
        if self.values.len().is_power_of_two() {
            let mask = self.values.len() as u32 - 1;
            visit_feature_hashes(text, self.char_ngrams, tokens, |hash| {
                dot += self.values[(hash & mask) as usize];
                total += 1;
            });
        } else {
            let buckets = self.values.len() as u32;
            visit_feature_hashes(text, self.char_ngrams, tokens, |hash| {
                dot += self.values[(hash % buckets) as usize];
                total += 1;
            });
        }
        if total == 0 {
            return self.bias;
        }
        dot / total as f64 + self.bias
    }

    /// [`Self::logit`] and the top positive bucket contributions
    /// (`#<bucket>`: count x value over the feature count).
    pub fn score(
        &self,
        text: &str,
        tokens: impl FnOnce(&mut dyn FnMut(&str)),
    ) -> (f64, Vec<TopFeature>) {
        let mut seen = Vec::new();
        let counts = self.counts(text, |emit| {
            tokens(&mut |token| {
                seen.push(token.to_string());
                emit(token)
            })
        });
        let logit = self.logit(text, |emit| seen.iter().for_each(|t| emit(t)));
        let total = counts.values().map(|&count| f64::from(count)).sum::<f64>();
        let mut buckets: Vec<(u32, u32)> = counts.into_iter().collect();
        buckets.sort_unstable_by_key(|(bucket, _)| *bucket);
        // Strongest first; equal contributions in feature-name order.
        let mut top: Vec<TopFeature> = buckets
            .into_iter()
            .map(|(bucket, count)| TopFeature {
                feature: format!("#{bucket}"),
                weight: f64::from(count) * self.values[bucket as usize] / total,
            })
            .filter(|feature| feature.weight > 0.0)
            .collect();
        top.sort_by(|a, b| {
            b.weight
                .total_cmp(&a.weight)
                .then_with(|| a.feature.cmp(&b.feature))
        });
        top.truncate(TOP_FEATURES);
        for feature in &mut top {
            feature.weight = py_round(feature.weight, 4);
        }
        (logit, top)
    }

    /// Bucket counts of every feature of `text` and its tokens.
    fn counts(&self, text: &str, tokens: impl FnOnce(&mut dyn FnMut(&str))) -> FxHashMap<u32, u32> {
        let buckets = self.values.len() as u32;
        let mut counts = FxHashMap::<u32, u32>::default();
        visit_feature_hashes(text, self.char_ngrams, tokens, |hash| {
            *counts.entry(hash % buckets).or_default() += 1
        });
        counts
    }
}

/// Visit the FNV-1a hash of every feature of `text` and its tokens, in order;
/// features are hashed in parts, so no feature string is built.
fn visit_feature_hashes(
    text: &str,
    (min_n, max_n): (usize, usize),
    tokens: impl FnOnce(&mut dyn FnMut(&str)),
    mut visit: impl FnMut(u32),
) {
    let prefixed = |prefix: &[u8]| fnv1a_32_extend(FNV1A_32_OFFSET, prefix);
    let mut previous = String::new();
    let mut lowered = String::new();
    let mut padded = String::new();
    let mut bounds = Vec::new();
    let mut first = true;
    for_each_word(text, |_, word| {
        lowered.clear();
        if word.is_ascii() {
            lowered.extend(word.bytes().map(|b| char::from(b.to_ascii_lowercase())));
        } else {
            lowered.push_str(&word.to_lowercase());
        }
        visit(fnv1a_32_extend(prefixed(b"w:"), lowered.as_bytes()));
        if !first {
            let hash = fnv1a_32_extend(prefixed(b"b:"), previous.as_bytes());
            let hash = fnv1a_32_extend(hash, b" ");
            visit(fnv1a_32_extend(hash, lowered.as_bytes()));
        }
        first = false;
        padded.clear();
        padded.push('<');
        padded.push_str(&lowered);
        padded.push('>');
        bounds.clear();
        bounds.extend(padded.char_indices().map(|(index, _)| index));
        bounds.push(padded.len());
        let chars = bounds.len() - 1;
        let bytes = padded.as_bytes();
        let grams = prefixed(b"c:");
        if chars < min_n {
            visit(fnv1a_32_extend(grams, bytes));
        } else {
            // The n-grams from one offset extend each other: hash the shortest,
            // then one more character per length.
            for offset in 0..=chars - min_n {
                let longest = max_n.min(chars - offset);
                let mut hash =
                    fnv1a_32_extend(grams, &bytes[bounds[offset]..bounds[offset + min_n - 1]]);
                for end in offset + min_n..=offset + longest {
                    hash = fnv1a_32_extend(hash, &bytes[bounds[end - 1]..bounds[end]]);
                    visit(hash);
                }
            }
        }
        std::mem::swap(&mut previous, &mut lowered);
    });
    tokens(&mut |token| visit(fnv1a_32_extend(FNV1A_32_OFFSET, token.as_bytes())));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detectors::facts_common::model::fnv1a_32;

    const FORM: ModelForm = ModelForm {
        label: "test",
        analyzer: "tf1",
        ask_threshold: "ask",
        block_threshold: "block",
    };

    /// Two buckets, `dim` 1: bucket 0 pushes towards the positive class.
    fn model(buckets: usize) -> FastTextModel {
        let embeddings: Vec<f64> = (0..buckets)
            .map(|b| if b == 0 { 1.0 } else { -1.0 })
            .collect();
        let document = serde_json::json!({
            "kind": "fasttext", "format_version": 1, "name": "toy", "analyzer_func": "tf1",
            "hash": "fnv1a_32", "buckets": buckets, "dim": 1, "char_ngram_range": [3, 4],
            "embeddings": embeddings, "output": [0.0, 2.0], "bias": [0.25, 0.5],
            "thresholds": {"ask": 0.0, "block": 1.0}, "decision_rule": "score > threshold",
        });
        FastTextModel::from_json_slice(document.to_string().as_bytes(), FORM).unwrap()
    }

    fn hashes(text: &str, ngrams: (usize, usize), token: &str) -> Vec<u32> {
        let mut out = Vec::new();
        visit_feature_hashes(text, ngrams, |emit| emit(token), |hash| out.push(hash));
        out
    }

    fn expected(features: &[&str]) -> Vec<u32> {
        features.iter().map(|f| fnv1a_32(f.as_bytes())).collect()
    }

    #[test]
    fn features_follow_the_python_order_and_names() {
        assert_eq!(
            hashes("Ab  ÄB", (3, 4), "F:X=1"),
            expected(&[
                "w:ab", "c:<ab", "c:<ab>", "c:ab>", "w:äb", "b:ab äb", "c:<äb", "c:<äb>", "c:äb>",
                "F:X=1",
            ])
        );
        // A padded word shorter than the smallest n counts once, whole.
        assert_eq!(hashes("é", (4, 5), "T"), expected(&["w:é", "c:<é>", "T"]));
    }

    #[test]
    fn score_is_the_logit_difference_of_the_averaged_embedding() {
        let model = model(1);
        // Every feature in bucket 0 with value 2: average 2 plus bias 0.25.
        let (score, top) = model.score("hello world", |_| {});
        assert_eq!(score, 2.25);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].feature, "#0");
        // No feature: the bias difference alone.
        assert_eq!(model.score("", |_| {}), (0.25, Vec::new()));
        assert_eq!(
            model.thresholds(),
            L1Thresholds {
                detect_threshold: 1.0,
                clear_threshold: Some(0.0)
            }
        );
    }

    #[test]
    fn rejects_mismatched_shapes_and_forms() {
        let bad = serde_json::json!({
            "kind": "fasttext", "format_version": 1, "name": "toy", "analyzer_func": "kf1",
            "hash": "fnv1a_32", "buckets": 2, "dim": 1, "char_ngram_range": [3, 4],
            "embeddings": [0.0, 0.0], "output": [0.0, 1.0], "bias": [0.0, 0.0],
            "thresholds": {"ask": 0.0, "block": 1.0}, "decision_rule": "score > threshold",
        });
        assert!(FastTextModel::from_json_slice(bad.to_string().as_bytes(), FORM).is_err());
        let mut shape = bad.clone();
        shape["analyzer_func"] = "tf1".into();
        shape["embeddings"] = serde_json::json!([0.0]);
        assert!(FastTextModel::from_json_slice(shape.to_string().as_bytes(), FORM).is_err());
        assert!(is_fasttext(&bad));
        assert!(!is_fasttext(&serde_json::json!({"format_version": 2})));
    }
}
