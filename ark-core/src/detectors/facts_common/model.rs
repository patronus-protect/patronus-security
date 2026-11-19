// SPDX-License-Identifier: MIT OR Apache-2.0
//! The K26 model form shared by the shell-risk model and the text category
//! models: two L2-normalized scikit-learn TF-IDF blocks, concatenated before a
//! binary logistic regression.
//!
//! - `char_wb`: `TfidfVectorizer(analyzer="char_wb", ngram_range=(min, max),
//!   lowercase=True, sublinear_tf=True)`.
//! - `tokens`: a named token analyzer of the [`ModelForm`] (`kf1` for shell
//!   commands, `tf1` for texts).
//!
//! A block either has a vocabulary (feature -> index, as scikit-learn's
//! `TfidfVectorizer` stores it) or is hashed: `n_features` buckets, a
//! feature's bucket is the 32-bit FNV-1a hash of its UTF-8 bytes modulo
//! `n_features`, and its name in the top features is `#<bucket>`.
//!
//! Scores match scikit-learn's float32 pipeline and scipy's summation order.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::hash::BuildHasher;

use hashbrown::hash_table::{Entry, HashTable};
use rustc_hash::{FxBuildHasher, FxHashMap};
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, Visitor};
use serde::Deserialize;

use crate::detectors::facts_common::pyjson::py_round;
use crate::detectors::facts_common::thresholds::L1Thresholds;
use crate::detectors::shell::pyre::is_py_space;
use crate::EvidenceSpan;

const MAX_EVIDENCE_SPANS: usize = 3;
const EVIDENCE_FEATURES: usize = 8;
pub(crate) const TOP_FEATURES: usize = 5;

/// What a model of one detector must look like: the token analyzer its
/// `tokens` block was trained with, the names of its `ask` and `block`
/// thresholds and the name used in load errors.
#[derive(Clone, Copy, Debug)]
pub struct ModelForm {
    pub label: &'static str,
    pub analyzer: &'static str,
    pub ask_threshold: &'static str,
    pub block_threshold: &'static str,
}

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
    #[serde(default)]
    vocabulary: RawVocabulary,
    idf: Vec<f64>,
}

/// A block's `vocabulary` (feature -> index) as read: every feature name
/// appended to one string, with its index and byte range there. Reading
/// allocates no string per feature.
#[derive(Default)]
struct RawVocabulary {
    text: String,
    /// (index, start, end) of each feature, in file order.
    entries: Vec<(u32, u32, u32)>,
}

impl<'de> Deserialize<'de> for RawVocabulary {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(RawVocabularyVisitor)
    }
}

struct RawVocabularyVisitor;

impl<'de> Visitor<'de> for RawVocabularyVisitor {
    type Value = RawVocabulary;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a map of feature names to indices")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<RawVocabulary, A::Error> {
        let mut raw = RawVocabulary::default();
        raw.entries.reserve(map.size_hint().unwrap_or(0));
        loop {
            let start = raw.text.len();
            if map.next_key_seed(AppendStr(&mut raw.text))?.is_none() {
                break;
            }
            let index: u32 = map.next_value()?;
            let end = u32::try_from(raw.text.len())
                .map_err(|_| de::Error::custom("vocabulary names exceed 4 GiB"))?;
            raw.entries.push((index, start as u32, end));
        }
        Ok(raw)
    }
}

/// Deserializes a string by appending it to the target.
struct AppendStr<'a>(&'a mut String);

impl<'de> DeserializeSeed<'de> for AppendStr<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for AppendStr<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a feature name")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        self.0.push_str(value);
        Ok(())
    }
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
    #[serde(default)]
    n_features: Option<usize>,
    #[serde(default)]
    hash: Option<String>,
}

/// The only feature hash of hashed blocks.
pub(crate) const FNV1A_32: &str = "fnv1a_32";

/// One TF-IDF feature block with its own feature lookup, idf and weight
/// offset in the concatenated feature space.
struct Block {
    lookup: Lookup,
    idf: Vec<f32>,
    weight_offset: usize,
}

/// How a block maps a feature to its index.
enum Lookup {
    Vocabulary(Vocabulary),
    /// FNV-1a bucket of the feature among `idf.len()` buckets.
    Hashed,
}

/// A block vocabulary in three allocations: the feature names in index order
/// in one string, the end offset of each name, and a hash table of indices
/// that compares against those names (instead of a map of boxed names plus a
/// second boxed copy of each name for the top features).
struct Vocabulary {
    names: String,
    ends: Vec<u32>,
    table: HashTable<u32>,
}

fn feature_hash(feature: &str) -> u64 {
    FxBuildHasher.hash_one(feature)
}

/// Name `index` among `names` cut at `ends`.
fn name_at<'a>(names: &'a str, ends: &[u32], index: usize) -> &'a str {
    let start = index
        .checked_sub(1)
        .map_or(0, |previous| ends[previous] as usize);
    &names[start..ends[index] as usize]
}

impl Vocabulary {
    /// Order `raw` by index and index it. The indices must be a permutation
    /// of `0..idf_len` and the names unique.
    fn new(raw: RawVocabulary, idf_len: usize, label: &str) -> Result<Self, String> {
        let features = raw.entries.len();
        if idf_len != features {
            return Err(format!(
                "{label} block has {features} vocabulary entries and {idf_len} idf values"
            ));
        }
        let mut by_index = vec![None; features];
        for &(index, start, end) in &raw.entries {
            let slot = by_index
                .get_mut(index as usize)
                .ok_or_else(|| format!("{label} vocabulary index {index} is out of range"))?;
            if slot.replace((start as usize, end as usize)).is_some() {
                return Err(format!("{label} vocabulary index {index} is duplicated"));
            }
        }
        let mut names = String::with_capacity(raw.text.len());
        let mut ends = Vec::with_capacity(features);
        for (start, end) in by_index.into_iter().flatten() {
            names.push_str(&raw.text[start..end]);
            ends.push(names.len() as u32);
        }
        let mut table = HashTable::with_capacity(features);
        for index in 0..features {
            let name = name_at(&names, &ends, index);
            match table.entry(
                feature_hash(name),
                |&other| name_at(&names, &ends, other as usize) == name,
                |&other| feature_hash(name_at(&names, &ends, other as usize)),
            ) {
                Entry::Occupied(_) => {
                    return Err(format!("{label} vocabulary feature {name:?} is duplicated"))
                }
                Entry::Vacant(slot) => {
                    slot.insert(index as u32);
                }
            }
        }
        Ok(Self { names, ends, table })
    }

    fn get(&self, feature: &str) -> Option<u32> {
        self.table
            .find(feature_hash(feature), |&index| {
                self.name(index as usize) == feature
            })
            .copied()
    }

    fn name(&self, index: usize) -> &str {
        name_at(&self.names, &self.ends, index)
    }
}

impl Block {
    fn load(raw: RawBlock, weight_offset: usize, label: &str) -> Result<Self, String> {
        if raw.feature_dtype != "float32"
            || !matches!(raw.idf_dtype.as_str(), "float32" | "float64")
        {
            return Err(format!(
                "{label} blocks use float32 features and float32/64 idf"
            ));
        }
        let cfg = &raw.vectorizer;
        if cfg.sublinear_tf != Some(true)
            || !matches!(cfg.norm.as_deref(), None | Some("l2"))
            || !matches!(cfg.use_idf, None | Some(true))
        {
            return Err(format!(
                "unsupported {label} {} block configuration",
                raw.kind
            ));
        }
        let lookup = match (cfg.n_features, cfg.hash.as_deref()) {
            (None, None) => {
                Lookup::Vocabulary(Vocabulary::new(raw.vocabulary, raw.idf.len(), label)?)
            }
            (Some(buckets), Some(FNV1A_32))
                if buckets > 0
                    && buckets <= u32::MAX as usize
                    && raw.vocabulary.entries.is_empty()
                    && raw.idf.len() == buckets =>
            {
                Lookup::Hashed
            }
            _ => return Err(format!("unsupported {label} {} block hashing", raw.kind)),
        };
        Ok(Self {
            lookup,
            idf: into_f32(raw.idf),
            weight_offset,
        })
    }

    /// Number of features (vocabulary entries or buckets).
    fn len(&self) -> usize {
        self.idf.len()
    }

    fn index(&self, feature: &str) -> Option<u32> {
        match &self.lookup {
            Lookup::Vocabulary(vocabulary) => vocabulary.get(feature),
            Lookup::Hashed => Some(fnv1a_32(feature.as_bytes()) % self.len() as u32),
        }
    }

    fn name(&self, index: usize) -> String {
        match &self.lookup {
            Lookup::Vocabulary(vocabulary) => vocabulary.name(index).to_string(),
            Lookup::Hashed => format!("#{index}"),
        }
    }

    fn count(&self, counts: &mut FxHashMap<u32, u32>, feature: &str) {
        if let Some(index) = self.index(feature) {
            *counts.entry(index).or_default() += 1;
        }
    }

    /// L2-normalized sublinear TF-IDF features from feature counts, sorted by
    /// vocabulary index.
    ///
    /// Mirrors scikit-learn's float32 pipeline: `1 + ln(tf)` and the idf
    /// product are rounded to float32, while the row norm accumulates in double
    /// precision and the normalized values are stored back as float32.
    /// `ln(tf)` is taken in double precision and rounded to float32, which
    /// the Python reference reproduces exactly (single-precision `ln`
    /// implementations disagree in the last bit, e.g. numpy's at tf = 7).
    fn tfidf(&self, counts: FxHashMap<u32, u32>) -> Vec<(u32, f32)> {
        let mut values = counts
            .into_iter()
            .map(|(index, tf)| {
                let sublinear = (f64::from(tf).ln() as f32) + 1.0;
                (index, sublinear * self.idf[index as usize])
            })
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

/// A loaded K26-form model: a `char_wb` block plus a token block.
pub struct TfidfLrModel {
    name: String,
    char_wb: Block,
    char_ngrams: (usize, usize),
    tokens: Block,
    weights: Vec<f64>,
    intercept: f64,
    thresholds: L1Thresholds,
}

impl TfidfLrModel {
    /// Parse and validate a `format_version: 2` `model.json` document of the
    /// given form, with its `ask` and `block` cuts.
    pub fn from_json_slice(bytes: &[u8], form: ModelForm) -> Result<Self, String> {
        let label = form.label;
        let file: ModelFile = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid {label} model JSON: {error}"))?;
        if file.format_version != 2 {
            return Err(format!(
                "unsupported {label} model format_version {}",
                file.format_version
            ));
        }
        if file.decision_rule != "score > threshold" {
            return Err(format!(
                "unsupported {label} decision_rule {}",
                file.decision_rule
            ));
        }
        let [char_wb, tokens]: [RawBlock; 2] = file.blocks.try_into().map_err(|_| {
            format!(
                "{label} model expects a char_wb and a {} block",
                form.analyzer
            )
        })?;
        let cfg = &char_wb.vectorizer;
        let Some([min_n, max_n]) = cfg.ngram_range else {
            return Err(format!("{label} char_wb block is missing ngram_range"));
        };
        if char_wb.kind != "char_wb"
            || cfg.analyzer.as_deref() != Some("char_wb")
            || !cfg.lowercase.unwrap_or(true)
            || cfg.strip_accents.is_some()
            || min_n == 0
            || min_n > max_n
        {
            return Err(format!("unsupported {label} char_wb block configuration"));
        }
        if tokens.kind != "tokens"
            || tokens.analyzer_func.as_deref() != Some(form.analyzer)
            || tokens.vectorizer.analyzer.is_some()
        {
            return Err(format!(
                "{label} token block must use the {} analyzer",
                form.analyzer
            ));
        }
        let char_wb = Block::load(char_wb, 0, label)?;
        let tokens = Block::load(tokens, char_wb.len(), label)?;
        let total = char_wb.len() + tokens.len();
        if file.weights.len() != total {
            return Err(format!(
                "{label} model has {total} block features and {} weights",
                file.weights.len()
            ));
        }
        Ok(Self {
            name: file.name,
            char_wb,
            char_ngrams: (min_n, max_n),
            tokens,
            weights: file.weights,
            intercept: file.intercept,
            thresholds: L1Thresholds::from_model(
                &file.thresholds,
                form,
                &format!("{label} model"),
            )?,
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

    /// Cat's `ask` and `block` cuts: the clear and the detect cut.
    pub fn cuts(&self) -> (f64, f64) {
        let ask = self
            .thresholds
            .clear_threshold
            .expect("a loaded model has its clear cut");
        (ask, self.thresholds.detect_threshold)
    }

    /// Nonzero features over the concatenated feature space, in index order:
    /// (global index, L2-normalized TF-IDF value).
    fn row(&self, text: &str, tokens: impl FnOnce(&mut dyn FnMut(&str))) -> Vec<(usize, f32)> {
        let chars = self.char_wb.tfidf(self.char_counts(text));
        let mut counts = FxHashMap::default();
        tokens(&mut |token| self.tokens.count(&mut counts, token));
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

    /// Decision score of `text` (an uncalibrated logit) given its analyzer
    /// tokens (passed to the visitor), and the top positive feature contributions. `x @ weights +
    /// intercept` in scipy's order: the dot product from zero in index order,
    /// then the intercept.
    pub fn score(
        &self,
        text: &str,
        tokens: impl FnOnce(&mut dyn FnMut(&str)),
    ) -> (f64, Vec<TopFeature>) {
        let row = self.row(text, tokens);
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
            format!("char:{}", self.char_wb.name(index))
        } else {
            format!(
                "tok:{}",
                self.tokens.name(index - self.tokens.weight_offset)
            )
        }
    }

    /// Evidence spans, labelled `label`, for the `char_wb` n-grams that push
    /// `text` towards the risk class. When no n-gram does (the token block or
    /// a policy alone flags the text), the trimmed text is the one span.
    pub(crate) fn evidence(&self, text: &str, label: &str) -> Vec<EvidenceSpan> {
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
            return vec![evidence_span(label, text, start..end, 1.0)];
        }
        contributions.sort_unstable_by(|left, right| right.1.total_cmp(&left.1));
        contributions.truncate(EVIDENCE_FEATURES);
        let selected = contributions.into_iter().collect::<HashMap<_, _>>();

        let mut occurrences = Vec::<(u32, std::ops::Range<usize>)>::new();
        visit_char_wb_ngrams(text, min_n, max_n, true, |ngram, range| {
            if let Some(index) = block.index(ngram) {
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
            .map(|(range, score)| evidence_span(label, text, range, score / total))
            .collect()
    }
}

fn evidence_span(
    label: &str,
    source: &str,
    range: std::ops::Range<usize>,
    score: f64,
) -> EvidenceSpan {
    EvidenceSpan {
        label: label.to_string(),
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

/// 32-bit FNV-1a of `bytes`.
pub(crate) fn fnv1a_32(bytes: &[u8]) -> u32 {
    fnv1a_32_extend(0x811c_9dc5, bytes)
}

/// Continue a 32-bit FNV-1a `hash` over `bytes`: hashing a feature in parts
/// equals hashing its concatenation.
pub(crate) fn fnv1a_32_extend(hash: u32, bytes: &[u8]) -> u32 {
    bytes.iter().fold(hash, |hash: u32, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(0x0100_0193)
    })
}

/// scikit-learn's float32 feature matrix; the stored idf is narrowed to f32.
fn into_f32(idf: Vec<f64>) -> Vec<f32> {
    idf.into_iter().map(|value| value as f32).collect()
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
pub(crate) fn for_each_word(text: &str, mut visit: impl FnMut(usize, &str)) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_32_reference_values() {
        assert_eq!(fnv1a_32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a_32(b"a"), 0xe40c_292c);
        assert_eq!(fnv1a_32(b"foobar"), 0xbf9c_f968);
    }

    #[test]
    fn vocabulary_keeps_names_in_index_order_and_finds_them() {
        let raw: RawVocabulary = serde_json::from_str(r#"{"bär": 2, "a\"b": 0, "": 1}"#).unwrap();
        let vocabulary = Vocabulary::new(raw, 3, "test").unwrap();
        for (name, index) in [("a\"b", 0), ("", 1), ("bär", 2)] {
            assert_eq!(vocabulary.name(index as usize), name);
            assert_eq!(vocabulary.get(name), Some(index));
        }
        assert_eq!(vocabulary.get("b"), None);
    }

    #[test]
    fn vocabulary_refuses_bad_indices_and_duplicate_names() {
        let error = |json: &str, idf_len| {
            Vocabulary::new(serde_json::from_str(json).unwrap(), idf_len, "test")
                .err()
                .unwrap()
        };
        assert!(error(r#"{"a": 0}"#, 2).contains("1 vocabulary entries and 2 idf values"));
        assert!(error(r#"{"a": 0, "b": 2}"#, 2).contains("index 2 is out of range"));
        assert!(error(r#"{"a": 0, "b": 0}"#, 2).contains("index 0 is duplicated"));
        assert!(error(r#"{"a": 0, "a": 1}"#, 2).contains(r#"feature "a" is duplicated"#));
    }
}
