// SPDX-License-Identifier: MIT OR Apache-2.0
//! The K26 shell-risk model: two L2-normalized scikit-learn TF-IDF blocks,
//! concatenated before a binary logistic regression.
//!
//! - `char_wb`: `TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
//!   lowercase=True, sublinear_tf=True)`.
//! - `tokens`: the [`kf1`](super::kf1) analyzer (shell tokens, legacy markers
//!   and `patronus.facts/1` tokens).
//!
//! Scores match scikit-learn's float32 pipeline and scipy's summation order.
//! The text is never executed.

use std::collections::{BTreeMap, HashMap};

use rustc_hash::FxHashMap;

use serde::Deserialize;

use super::pyre::is_py_space;
use crate::detectors::facts_common::pyjson::py_round;
use crate::EvidenceSpan;

/// Class name of a flagged command and its evidence spans.
pub const SHELL_RISK_CLASS: &str = "shell_risk";
/// Threshold of the `ask` decision: 1 % FPR on external agent commands.
pub const ASK_THRESHOLD: &str = "external_commands_1pct_fpr";
/// Threshold of the `block` decision: 0.1 % FPR.
pub const BLOCK_THRESHOLD: &str = "block_0_1pct_fpr";
const MAX_EVIDENCE_SPANS: usize = 3;
const EVIDENCE_FEATURES: usize = 8;
const TOP_FEATURES: usize = 5;

/// A `format_version: 2` `model.json`.
#[derive(Deserialize)]
struct ModelFile {
    format_version: u32,
    name: String,
    blocks: Vec<RawBlock>,
    weights: Vec<f64>,
    intercept: f64,
    thresholds: BTreeMap<String, f64>,
    decision_rule: String,
}

#[derive(Deserialize)]
struct RawBlock {
    kind: String,
    #[serde(default)]
    analyzer_func: Option<String>,
    vectorizer: BlockVectorizer,
    feature_dtype: String,
    idf_dtype: String,
    vocabulary: HashMap<String, u32>,
    idf: Vec<f64>,
}

/// A block's vectorizer config, where scikit-learn defaults (`norm="l2"`,
/// `use_idf=True`, `lowercase=True`) may be omitted.
#[derive(Deserialize, Default)]
struct BlockVectorizer {
    #[serde(default)]
    analyzer: Option<String>,
    #[serde(default)]
    ngram_range: Option<[usize; 2]>,
    #[serde(default)]
    lowercase: Option<bool>,
    #[serde(default)]
    strip_accents: Option<String>,
    #[serde(default)]
    sublinear_tf: Option<bool>,
    #[serde(default)]
    norm: Option<String>,
    #[serde(default)]
    use_idf: Option<bool>,
}

/// One TF-IDF feature block with its own vocabulary, idf and weight offset in
/// the concatenated feature space.
struct Block {
    vocabulary: FxHashMap<Box<str>, u32>,
    /// Feature name of each vocabulary index (for the verdict's top features).
    names: Vec<Box<str>>,
    idf: Vec<f32>,
    weight_offset: usize,
}

impl Block {
    fn load(raw: RawBlock, weight_offset: usize) -> Result<Self, String> {
        if raw.feature_dtype != "float32"
            || !matches!(raw.idf_dtype.as_str(), "float32" | "float64")
        {
            return Err("shell risk blocks use float32 features and float32/64 idf".to_string());
        }
        let cfg = &raw.vectorizer;
        if cfg.sublinear_tf != Some(true)
            || !matches!(cfg.norm.as_deref(), None | Some("l2"))
            || !matches!(cfg.use_idf, None | Some(true))
        {
            return Err(format!(
                "unsupported shell risk {} block configuration",
                raw.kind
            ));
        }
        validate_vocabulary(&raw.vocabulary, raw.idf.len())?;
        let (vocabulary, names) = into_vocabulary(raw.vocabulary);
        Ok(Self {
            vocabulary,
            names,
            idf: into_f32(raw.idf),
            weight_offset,
        })
    }

    fn count(&self, counts: &mut FxHashMap<u32, u32>, feature: &str) {
        if let Some(&index) = self.vocabulary.get(feature) {
            *counts.entry(index).or_default() += 1;
        }
    }

    /// L2-normalized sublinear TF-IDF features from feature counts, sorted by
    /// vocabulary index.
    ///
    /// Mirrors scikit-learn's float32 pipeline: `1 + ln(tf)` and the idf
    /// product are rounded to float32, while the row norm accumulates in double
    /// precision and the normalized values are stored back as float32.
    fn tfidf(&self, counts: FxHashMap<u32, u32>) -> Vec<(u32, f32)> {
        let mut values = counts
            .into_iter()
            .map(|(index, tf)| (index, ((tf as f32).ln() + 1.0) * self.idf[index as usize]))
            .collect::<Vec<_>>();
        values.sort_unstable_by_key(|(index, _)| *index);
        let squared = values
            .iter()
            .map(|(_, value)| f64::from(value * value))
            .sum::<f64>();
        if squared > 0.0 {
            let norm = squared.sqrt();
            for (_, value) in &mut values {
                *value = (f64::from(*value) / norm) as f32;
            }
        }
        values
    }
}

/// A feature that pushed the model towards the risk class, with its
/// contribution rounded to four decimals.
#[derive(Clone, Debug, PartialEq)]
pub struct TopFeature {
    pub feature: String,
    pub weight: f64,
}

/// The loaded K26 model: a `char_wb` block plus the `kf1` token block.
pub struct ShellRiskModel {
    name: String,
    char_wb: Block,
    char_ngrams: (usize, usize),
    tokens: Block,
    weights: Vec<f64>,
    intercept: f64,
    ask_cut: f64,
    block_cut: f64,
}

impl ShellRiskModel {
    /// Parse and validate a `format_version: 2` `model.json` document with
    /// the `ask` and `block` cuts.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, String> {
        let file: ModelFile = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid shell risk model JSON: {error}"))?;
        if file.format_version != 2 {
            return Err(format!(
                "unsupported shell risk model format_version {}",
                file.format_version
            ));
        }
        if file.decision_rule != "score > threshold" {
            return Err(format!(
                "unsupported shell risk decision_rule {}",
                file.decision_rule
            ));
        }
        let [char_wb, tokens]: [RawBlock; 2] = file
            .blocks
            .try_into()
            .map_err(|_| "shell risk model expects a char_wb and a kf1 block".to_string())?;
        let cfg = &char_wb.vectorizer;
        let Some([min_n, max_n]) = cfg.ngram_range else {
            return Err("shell risk char_wb block is missing ngram_range".to_string());
        };
        if char_wb.kind != "char_wb"
            || cfg.analyzer.as_deref() != Some("char_wb")
            || !cfg.lowercase.unwrap_or(true)
            || cfg.strip_accents.is_some()
            || min_n == 0
            || min_n > max_n
        {
            return Err("unsupported shell risk char_wb block configuration".to_string());
        }
        if tokens.kind != "tokens"
            || tokens.analyzer_func.as_deref() != Some("kf1")
            || tokens.vectorizer.analyzer.is_some()
        {
            return Err("shell risk token block must use the kf1 analyzer".to_string());
        }
        let total = char_wb.vocabulary.len() + tokens.vocabulary.len();
        if file.weights.len() != total {
            return Err(format!(
                "shell risk model has {total} block features and {} weights",
                file.weights.len()
            ));
        }
        let cut = |name: &str| {
            file.thresholds
                .get(name)
                .copied()
                .ok_or_else(|| format!("shell risk model has no {name} threshold"))
        };
        let char_features = char_wb.vocabulary.len();
        Ok(Self {
            name: file.name,
            char_wb: Block::load(char_wb, 0)?,
            char_ngrams: (min_n, max_n),
            tokens: Block::load(tokens, char_features)?,
            weights: file.weights,
            intercept: file.intercept,
            ask_cut: cut(ASK_THRESHOLD)?,
            block_cut: cut(BLOCK_THRESHOLD)?,
        })
    }

    /// Model name recorded in `model.json`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The `ask` and `block` cuts on the decision score.
    pub fn cuts(&self) -> (f64, f64) {
        (self.ask_cut, self.block_cut)
    }

    /// Nonzero features over the concatenated feature space, in index order:
    /// (global index, L2-normalized TF-IDF value).
    fn row(&self, text: &str, kf1: impl FnOnce(&mut dyn FnMut(&str))) -> Vec<(usize, f32)> {
        let chars = self.char_wb.tfidf(self.char_counts(text));
        let mut counts = FxHashMap::default();
        kf1(&mut |token| self.tokens.count(&mut counts, token));
        let tokens = self.tokens.tfidf(counts);
        chars
            .into_iter()
            .map(|(index, value)| (index as usize, value))
            .chain(
                tokens
                    .into_iter()
                    .map(|(index, value)| (self.tokens.weight_offset + index as usize, value)),
            )
            .collect()
    }

    /// Decision score of `text` (an uncalibrated logit) given its `kf1`
    /// tokens (passed to the visitor), and the top positive feature contributions. `x @ weights +
    /// intercept` in scipy's order: the dot product from zero in index order,
    /// then the intercept.
    pub(crate) fn score(
        &self,
        text: &str,
        kf1: impl FnOnce(&mut dyn FnMut(&str)),
    ) -> (f64, Vec<TopFeature>) {
        let row = self.row(text, kf1);
        let mut dot = 0.0;
        let mut contributions = Vec::with_capacity(row.len());
        for &(index, value) in &row {
            let contribution = f64::from(value) * self.weights[index];
            dot += contribution;
            contributions.push((index, contribution));
        }
        // Strongest first; equal contributions in feature-name order.
        contributions.retain(|(_, c)| *c > 0.0);
        let mut top: Vec<TopFeature> = contributions
            .into_iter()
            .map(|(index, contribution)| TopFeature {
                feature: self.feature_name(index),
                weight: contribution,
            })
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
        (dot + self.intercept, top)
    }

    fn char_counts(&self, text: &str) -> FxHashMap<u32, u32> {
        let mut counts = FxHashMap::default();
        let (min_n, max_n) = self.char_ngrams;
        visit_char_wb_ngrams(text, min_n, max_n, false, |gram, _| {
            self.char_wb.count(&mut counts, gram)
        });
        counts
    }

    fn feature_name(&self, index: usize) -> String {
        if index < self.tokens.weight_offset {
            format!("char:{}", self.char_wb.names[index])
        } else {
            format!(
                "tok:{}",
                self.tokens.names[index - self.tokens.weight_offset]
            )
        }
    }

    /// Evidence spans for the `char_wb` n-grams that push `text` towards the
    /// risk class. When no n-gram does (the token block or a policy alone
    /// flags the command), the trimmed command is the one span.
    pub(crate) fn evidence(&self, text: &str) -> Vec<EvidenceSpan> {
        let block = &self.char_wb;
        let (min_n, max_n) = self.char_ngrams;
        let mut contributions = block
            .tfidf(self.char_counts(text))
            .into_iter()
            .map(|(index, value)| (index, self.weights[index as usize] * f64::from(value)))
            .filter(|(_, contribution)| *contribution > 0.0)
            .collect::<Vec<_>>();
        let total = contributions.iter().map(|(_, value)| value).sum::<f64>();
        if total <= 0.0 {
            let start = text.len() - text.trim_start().len();
            let end = text.trim_end().len().max(start);
            return vec![evidence_span(text, start..end, 1.0)];
        }
        contributions.sort_unstable_by(|left, right| right.1.total_cmp(&left.1));
        contributions.truncate(EVIDENCE_FEATURES);
        let selected = contributions.into_iter().collect::<HashMap<_, _>>();

        let mut occurrences = Vec::<(u32, std::ops::Range<usize>)>::new();
        visit_char_wb_ngrams(text, min_n, max_n, true, |ngram, range| {
            if let Some(&index) = block.vocabulary.get(ngram) {
                if selected.contains_key(&index) && !range.is_empty() {
                    occurrences.push((index, range));
                }
            }
        });
        let mut counts = HashMap::<u32, usize>::new();
        for (index, _) in &occurrences {
            *counts.entry(*index).or_default() += 1;
        }
        occurrences.sort_unstable_by_key(|(_, range)| (range.start, range.end));

        let mut regions = Vec::<(std::ops::Range<usize>, f64)>::new();
        for (index, range) in occurrences {
            let share = selected[&index] / counts[&index] as f64;
            match regions.last_mut() {
                Some((region, score)) if range.start <= region.end => {
                    region.end = region.end.max(range.end);
                    *score += share;
                }
                _ => regions.push((range, share)),
            }
        }
        regions.sort_unstable_by(|left, right| right.1.total_cmp(&left.1));
        regions.truncate(MAX_EVIDENCE_SPANS);
        regions.sort_unstable_by_key(|(range, _)| range.start);
        regions
            .into_iter()
            .map(|(range, score)| evidence_span(text, range, score / total))
            .collect()
    }
}

fn evidence_span(source: &str, range: std::ops::Range<usize>, score: f64) -> EvidenceSpan {
    EvidenceSpan {
        label: SHELL_RISK_CLASS.to_string(),
        text: source[range.clone()].to_string(),
        score: score.clamp(0.0, 1.0),
        start_byte: range.start,
        end_byte: range.end,
        start_char: source[..range.start].chars().count(),
        end_char: source[..range.end].chars().count(),
    }
}

/// Visit every `char_wb` n-gram of `text`, with the byte range of the source
/// characters it covers when `with_ranges` (else an empty range, for counting).
fn visit_char_wb_ngrams(
    text: &str,
    min_n: usize,
    max_n: usize,
    with_ranges: bool,
    mut visit: impl FnMut(&str, std::ops::Range<usize>),
) {
    let mut padded = String::new();
    let mut bounds = Vec::new();
    let no_source = SourceMap::none();
    for_each_word(text, |word_start, word| {
        padded.clear();
        padded.push(' ');
        if word.is_ascii() {
            padded.extend(word.bytes().map(|b| char::from(b.to_ascii_lowercase())));
        } else {
            padded.push_str(&word.to_lowercase());
        }
        padded.push(' ');
        bounds.clear();
        bounds.extend(padded.char_indices().map(|(index, _)| index));
        bounds.push(padded.len());
        let padded_len = bounds.len() - 1;
        let owned;
        let source = if with_ranges {
            owned = SourceMap::new(word_start, word, padded_len - 2);
            &owned
        } else {
            &no_source
        };
        for n in min_n..=max_n {
            let mut offset = 0;
            visit(
                &padded[bounds[0]..bounds[n.min(padded_len)]],
                source.range(0, n),
            );
            while offset + n < padded_len {
                offset += 1;
                visit(
                    &padded[bounds[offset]..bounds[offset + n]],
                    source.range(offset, n),
                );
            }
            // Python counts a word shorter than `n` only once.
            if offset == 0 {
                break;
            }
        }
    });
}

/// Build a block vocabulary into the owned representation, with the feature
/// name of each index. Indices are validated to be a permutation.
fn into_vocabulary(vocabulary: HashMap<String, u32>) -> (FxHashMap<Box<str>, u32>, Vec<Box<str>>) {
    let mut names = vec![Box::<str>::from(""); vocabulary.len()];
    let vocabulary = vocabulary
        .into_iter()
        .map(|(term, index)| {
            let term = term.into_boxed_str();
            names[index as usize] = term.clone();
            (term, index)
        })
        .collect();
    (vocabulary, names)
}

/// scikit-learn's float32 feature matrix; the stored idf is narrowed to f32.
fn into_f32(idf: Vec<f64>) -> Vec<f32> {
    idf.into_iter().map(|value| value as f32).collect()
}

/// Check idf length and that vocabulary indices are a permutation of
/// `0..vocabulary.len()`.
fn validate_vocabulary(vocabulary: &HashMap<String, u32>, idf_len: usize) -> Result<(), String> {
    let features = vocabulary.len();
    if idf_len != features {
        return Err(format!(
            "shell risk block has {features} vocabulary entries and {idf_len} idf values"
        ));
    }
    let mut seen = vec![false; features];
    for &index in vocabulary.values() {
        let slot = seen
            .get_mut(index as usize)
            .ok_or_else(|| format!("shell risk vocabulary index {index} is out of range"))?;
        if std::mem::replace(slot, true) {
            return Err(format!("shell risk vocabulary index {index} is duplicated"));
        }
    }
    Ok(())
}

/// Maps padded n-gram character offsets back to the source word.
struct SourceMap {
    /// Byte offset of every source character plus the word end, when
    /// lowercasing kept the character count; otherwise only the word bounds.
    bounds: Vec<usize>,
    exact: bool,
}

impl SourceMap {
    /// No source positions: every range is empty.
    fn none() -> Self {
        Self {
            bounds: vec![0, 0],
            exact: false,
        }
    }

    fn new(word_start: usize, word: &str, lowered_chars: usize) -> Self {
        let mut bounds = word
            .char_indices()
            .map(|(index, _)| word_start + index)
            .collect::<Vec<_>>();
        bounds.push(word_start + word.len());
        let exact = bounds.len() - 1 == lowered_chars;
        if !exact {
            bounds = vec![word_start, word_start + word.len()];
        }
        Self { bounds, exact }
    }

    /// Source range for the padded characters `offset..offset + n`.
    fn range(&self, offset: usize, n: usize) -> std::ops::Range<usize> {
        let chars = self.bounds.len() - 1;
        if !self.exact {
            return self.bounds[0]..self.bounds[chars];
        }
        // Padded index 0 and `chars + 1` are the synthetic spaces.
        let start = offset.max(1) - 1;
        let end = (offset + n).min(chars + 1).saturating_sub(1).max(start);
        self.bounds[start.min(chars)]..self.bounds[end.min(chars)]
    }
}

/// Split like Python `str.split()` and report each word's byte offset.
fn for_each_word(text: &str, mut visit: impl FnMut(usize, &str)) {
    let mut start = None;
    for (index, c) in text.char_indices() {
        if is_py_space(c) {
            if let Some(word_start) = start.take() {
                visit(word_start, &text[word_start..index]);
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if let Some(word_start) = start {
        visit(word_start, &text[word_start..]);
    }
}
