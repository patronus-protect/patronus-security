// SPDX-License-Identifier: GPL-3.0-only
//! Rust port of the `cat-shell-risk-commander` shell command scorer and its
//! `patronus.verdict/1`.
//!
//! The model (`format_version: 2`) concatenates two L2-normalized
//! scikit-learn TF-IDF blocks before a binary logistic regression: a
//! `TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), lowercase=True,
//! sublinear_tf=True, norm="l2")` block and a token block. The token block of
//! the released K26 model is the [`super::features::kf1`] analyzer (live
//! shell tokens, legacy markers and `patronus.facts/1` tokens); the earlier G
//! model's [`super::shell_tokens`] analyzer still loads. Decision scores match
//! scikit-learn within floating-point rounding.
//!
//! The verdict is `max(model, policies)` on `allow < ask < block`: the model
//! asks above the 1 % FPR cut and blocks above the 0.1 % FPR cut, and every
//! fired Cedar policy (see [`super::policies`]) sets at least its level. The
//! Python reference in the K26 release is the specification; the parity
//! suite in `rust/tests/shell_risk_parity.rs` checks this port against it.
//!
//! The scorer only sees command text. It never executes, parses or expands the
//! command, so it is one signal next to sandboxing and permission policy.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};

use serde::Deserialize;
use serde_json::{json, Value};

use super::facts::{extract, Facts, ShellContext};
use super::features::kf1_with_facts;
use super::policies::{
    Decision, Lowered, PolicyHit, ShellPolicies, ShellPolicyConfig, DC_RULES_JSON,
};
use super::pyjson::{self, py_round};
use super::shell_tokens;
use super::vocab::VOCAB_CSV;
use crate::detectors::NativeDetection;
use crate::{EvaluationResult, EvidenceSpan};

/// Class name returned when the verdict is `ask` or `block`.
pub const SHELL_RISK_CLASS: &str = "shell_risk";
const SAFE_CLASS: &str = "safe";
const MAX_EVIDENCE_SPANS: usize = 3;
const EVIDENCE_FEATURES: usize = 8;
/// Threshold of the `ask` decision: 1 % FPR on external agent commands.
pub const ASK_THRESHOLD: &str = "external_commands_1pct_fpr";
/// Threshold of the `block` decision: 0.1 % FPR.
pub const BLOCK_THRESHOLD: &str = "block_0_1pct_fpr";
/// Version tag of the verdict document.
pub const VERDICT_VERSION: &str = "patronus.verdict/1";
const TOP_FEATURES: usize = 5;
const G_MODEL_TYPE: &str = "tfidf_char_wb+shell_tokens__logreg";
/// Files the release manifest may list whose content ARK embeds; a bundle
/// whose copy differs is refused.
const EMBEDDED_FILES: [(&str, &str); 2] = [
    ("shellrisk/policies/dc_rules.json", DC_RULES_JSON),
    ("shellrisk/facts/shell_vocab_v1.csv", VOCAB_CSV),
];

/// A `format_version: 2` `model.json`: a `char_wb` block followed by a token
/// block, concatenated before the logistic regression.
#[derive(Deserialize)]
struct ModelFile {
    format_version: u32,
    #[serde(default)]
    model_type: Option<String>,
    name: String,
    blocks: Vec<RawBlock>,
    weights: Vec<f64>,
    intercept: f64,
    thresholds: BTreeMap<String, f64>,
    default_threshold_policy: String,
    decision_rule: String,
    #[serde(default)]
    block_feature_counts: Option<Vec<usize>>,
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

/// How a block turns command text into TF-IDF feature counts.
enum BlockAnalyzer {
    /// scikit-learn `char_wb` character n-grams.
    CharWb { min_n: usize, max_n: usize },
    /// The G model's `shell_tokens` analyzer.
    ShellTokens,
    /// The K26 model's `kf1` analyzer.
    Kf1,
}

/// One TF-IDF feature block with its own vocabulary, idf and weight offset in
/// the concatenated feature space.
struct Block {
    analyzer: BlockAnalyzer,
    vocabulary: HashMap<Box<str>, u32>,
    /// Feature name of each vocabulary index (for the verdict's top features).
    names: Vec<Box<str>>,
    idf: Vec<f32>,
    weight_offset: usize,
}

impl Block {
    /// Feature counts for `text`, keyed by this block's vocabulary index.
    /// `facts` are the context-free facts of `text` when already extracted.
    fn counts(&self, text: &str, facts: Option<&Facts>) -> HashMap<u32, u32> {
        let mut counts = HashMap::<u32, u32>::new();
        let mut count = |feature: &str| {
            if let Some(&index) = self.vocabulary.get(feature) {
                *counts.entry(index).or_default() += 1;
            }
        };
        match self.analyzer {
            BlockAnalyzer::CharWb { min_n, max_n } => {
                visit_char_wb_ngrams(text, min_n, max_n, |ngram, _| count(ngram));
            }
            BlockAnalyzer::ShellTokens => {
                shell_tokens::features(text).iter().for_each(|f| count(f));
            }
            BlockAnalyzer::Kf1 => {
                let tokens = match facts {
                    Some(facts) => kf1_with_facts(text, facts),
                    None => kf1_with_facts(text, &extract(text, None, &[])),
                };
                tokens.iter().for_each(|f| count(f));
            }
        }
        counts
    }

    /// L2-normalized sublinear TF-IDF features, sorted by vocabulary index.
    ///
    /// Mirrors scikit-learn's float32 pipeline: `1 + ln(tf)` and the idf
    /// product are rounded to float32, while the row norm accumulates in double
    /// precision and the normalized values are stored back as float32.
    fn tfidf(&self, text: &str, facts: Option<&Facts>) -> Vec<(u32, f32)> {
        let mut values = self
            .counts(text, facts)
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

    fn feature_name(&self, index: usize) -> String {
        let prefix = match self.analyzer {
            BlockAnalyzer::CharWb { .. } => "char",
            BlockAnalyzer::ShellTokens | BlockAnalyzer::Kf1 => "tok",
        };
        format!("{prefix}:{}", self.names[index])
    }
}

/// A release manifest entry: a bare digest or `{"sha256": …}`.
#[derive(Deserialize)]
#[serde(untagged)]
enum ManifestEntry {
    Digest(String),
    File { sha256: String },
}

impl ManifestEntry {
    fn sha256(&self) -> &str {
        match self {
            ManifestEntry::Digest(digest) | ManifestEntry::File { sha256: digest } => digest,
        }
    }
}

#[derive(Deserialize)]
struct BundleManifest {
    files: HashMap<String, ManifestEntry>,
}

/// `config.json` of a K26 release: which files hold the model and the policy levels.
#[derive(Deserialize)]
struct BundleConfig {
    #[serde(default)]
    model_file: Option<String>,
    #[serde(default)]
    policy_levels_file: Option<String>,
}

/// A downloaded bundle whose files are read only after their SHA-256 matches
/// the release `manifest.json`.
struct VerifiedBundle<'a> {
    dir: &'a Path,
    manifest: BundleManifest,
}

impl<'a> VerifiedBundle<'a> {
    fn open(dir: &'a Path) -> Result<Self, String> {
        let path = dir.join("manifest.json");
        let manifest: BundleManifest = serde_json::from_slice(
            &fs::read(&path)
                .map_err(|error| format!("failed to read {}: {error}", path.display()))?,
        )
        .map_err(|error| format!("invalid {}: {error}", path.display()))?;
        // ARK embeds the reference vocabulary and DefenseClaw rules; a release
        // built from different ones does not match this runtime.
        for (name, embedded) in EMBEDDED_FILES {
            if let Some(entry) = manifest.files.get(name) {
                if !sha256_hex(embedded.as_bytes()).eq_ignore_ascii_case(entry.sha256()) {
                    return Err(format!(
                        "{} lists a {name} that differs from the one this runtime embeds",
                        path.display()
                    ));
                }
            }
        }
        Ok(Self { dir, manifest })
    }

    fn has(&self, name: &str) -> bool {
        self.manifest.files.contains_key(name)
    }

    /// Bytes of `name` after checking its SHA-256 against the manifest.
    fn read(&self, name: &str) -> Result<Vec<u8>, String> {
        let expected = self.manifest.files.get(name).ok_or_else(|| {
            format!(
                "{} does not list {name}",
                self.dir.join("manifest.json").display()
            )
        })?;
        let path = self.dir.join(name);
        let bytes = fs::read(&path)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(expected.sha256()) {
            return Err(format!(
                "{} sha256 {actual} does not match manifest {}",
                path.display(),
                expected.sha256()
            ));
        }
        Ok(bytes)
    }

    fn config(&self) -> Result<Option<BundleConfig>, String> {
        if !self.has("config.json") {
            return Ok(None);
        }
        serde_json::from_slice(&self.read("config.json")?)
            .map(Some)
            .map_err(|error| format!("invalid config.json: {error}"))
    }
}

/// A loaded TF-IDF logistic-regression model: a `char_wb` block plus a token
/// block.
pub struct ShellRiskModel {
    name: String,
    blocks: Vec<Block>,
    weights: Vec<f64>,
    intercept: f64,
    thresholds: BTreeMap<String, f64>,
}

impl ShellRiskModel {
    /// Parse and validate a `format_version: 2` `model.json` document.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self, String> {
        let file: ModelFile = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid shell risk model JSON: {error}"))?;
        if file.format_version != 2 {
            return Err(format!(
                "unsupported shell risk model format_version {}",
                file.format_version
            ));
        }
        if let Some(model_type) = file.model_type.as_deref().filter(|t| *t != G_MODEL_TYPE) {
            return Err(format!("unsupported shell risk model_type {model_type}"));
        }
        require_decision_rule(&file.decision_rule)?;
        if file.blocks.len() != 2 {
            return Err(format!(
                "shell risk model expects 2 blocks, found {}",
                file.blocks.len()
            ));
        }
        let counts: Vec<usize> = file
            .block_feature_counts
            .clone()
            .unwrap_or_else(|| file.blocks.iter().map(|b| b.vocabulary.len()).collect());
        if counts.len() != file.blocks.len() {
            return Err("shell risk block_feature_counts does not match the blocks".to_string());
        }
        let total: usize = counts.iter().sum();
        if file.weights.len() != total {
            return Err(format!(
                "shell risk model has {total} block features and {} weights",
                file.weights.len()
            ));
        }
        let mut blocks = Vec::with_capacity(file.blocks.len());
        let mut weight_offset = 0;
        for (position, raw) in file.blocks.into_iter().enumerate() {
            if raw.feature_dtype != "float32" {
                return Err("shell risk block must use float32 features".to_string());
            }
            if raw.idf_dtype != "float32" && raw.idf_dtype != "float64" {
                return Err("shell risk block idf must be float32 or float64".to_string());
            }
            if raw.vocabulary.len() != counts[position] {
                return Err(format!(
                    "shell risk block {position} has {} vocabulary entries but block_feature_counts says {}",
                    raw.vocabulary.len(),
                    counts[position]
                ));
            }
            validate_vocabulary(&raw.vocabulary, raw.idf.len())?;
            let analyzer = match (position, raw.kind.as_str()) {
                (0, "char_wb") => char_wb_analyzer(&raw)?,
                (1, "shell_tokens") => {
                    token_analyzer(&raw, "features", BlockAnalyzer::ShellTokens)?
                }
                (1, "tokens") => token_analyzer(&raw, "kf1", BlockAnalyzer::Kf1)?,
                _ => {
                    return Err(format!(
                        "unexpected shell risk block {position} of kind {}",
                        raw.kind
                    ))
                }
            };
            let (vocabulary, names) = into_vocabulary(raw.vocabulary);
            blocks.push(Block {
                analyzer,
                vocabulary,
                names,
                idf: into_f32(raw.idf),
                weight_offset,
            });
            weight_offset += counts[position];
        }
        require_threshold_policy(&file.thresholds, &file.default_threshold_policy)?;
        Ok(Self {
            name: file.name,
            blocks,
            weights: file.weights,
            intercept: file.intercept,
            thresholds: file.thresholds,
        })
    }

    /// Load the model of a downloaded bundle after checking its SHA-256
    /// against the bundle's `manifest.json`.
    pub fn from_bundle_dir(dir: &Path) -> Result<Self, String> {
        let bundle = VerifiedBundle::open(dir)?;
        Self::from_bundle(&bundle)
    }

    fn from_bundle(bundle: &VerifiedBundle<'_>) -> Result<Self, String> {
        let model_file = bundle
            .config()?
            .and_then(|config| config.model_file)
            .unwrap_or_else(|| "model.json".to_string());
        Self::from_json_slice(&bundle.read(&model_file)?)
    }

    /// Model name recorded in `model.json`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Decision threshold for a named policy.
    pub fn threshold(&self, policy: &str) -> Option<f64> {
        self.thresholds.get(policy).copied()
    }

    /// Nonzero features of `text` over the concatenated feature space, in
    /// index order: (global index, L2-normalized TF-IDF value).
    fn row(&self, text: &str, facts: Option<&Facts>) -> Vec<(usize, f32)> {
        self.blocks
            .iter()
            .flat_map(|block| {
                block
                    .tfidf(text, facts)
                    .into_iter()
                    .map(|(index, value)| (block.weight_offset + index as usize, value))
            })
            .collect()
    }

    /// `x @ weights + intercept` in scipy's order: the row dot product from
    /// zero in index order, then the intercept.
    fn score_row(&self, row: &[(usize, f32)]) -> f64 {
        let mut dot = 0.0;
        for &(index, value) in row {
            dot += f64::from(value) * self.weights[index];
        }
        dot + self.intercept
    }

    /// Raw logistic-regression decision score (an uncalibrated logit).
    pub fn decision_score(&self, text: &str) -> f64 {
        self.score_row(&self.row(text, None))
    }

    /// Decision score and the top positive feature contributions (`_model`).
    fn score_with_top_features(&self, text: &str, facts: &Facts) -> (f64, Vec<TopFeature>) {
        let row = self.row(text, Some(facts));
        let score = self.score_row(&row);
        let contributions: Vec<f64> = row
            .iter()
            .map(|&(index, value)| f64::from(value) * self.weights[index])
            .collect();
        // `np.argsort(-contrib)`: equal contributions keep numpy's order.
        let negated: Vec<f64> = contributions.iter().map(|c| -c).collect();
        let top = np_argsort(&negated)
            .into_iter()
            .take(TOP_FEATURES)
            .filter(|&k| contributions[k] > 0.0)
            .map(|k| TopFeature {
                feature: self.feature_name(row[k].0),
                weight: py_round(contributions[k], 4),
            })
            .collect();
        (score, top)
    }

    fn feature_name(&self, index: usize) -> String {
        let block = self
            .blocks
            .iter()
            .rev()
            .find(|block| block.weight_offset <= index)
            .expect("feature index in range");
        block.feature_name(index - block.weight_offset)
    }

    /// The `char_wb` block, used for evidence.
    fn char_wb_block(&self) -> Option<&Block> {
        self.blocks
            .iter()
            .find(|block| matches!(block.analyzer, BlockAnalyzer::CharWb { .. }))
    }

    /// Evidence spans for the `char_wb` n-grams that push `text` towards the
    /// risk class. When no n-gram does (the token block or a policy alone
    /// flags the command), the trimmed command is the one span.
    fn evidence(&self, text: &str) -> Vec<EvidenceSpan> {
        let Some(block) = self.char_wb_block() else {
            return Vec::new();
        };
        let BlockAnalyzer::CharWb { min_n, max_n } = block.analyzer else {
            return Vec::new();
        };
        let mut contributions = block
            .tfidf(text, None)
            .into_iter()
            .map(|(index, value)| {
                (
                    index,
                    self.weights[block.weight_offset + index as usize] * f64::from(value),
                )
            })
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
        visit_char_wb_ngrams(text, min_n, max_n, |ngram, range| {
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

/// Visit every `char_wb` n-gram of `text` with the byte range of the source
/// characters it covers.
fn visit_char_wb_ngrams(
    text: &str,
    min_n: usize,
    max_n: usize,
    mut visit: impl FnMut(&str, std::ops::Range<usize>),
) {
    let mut padded = String::new();
    let mut bounds = Vec::new();
    for_each_word(text, |word_start, word| {
        let lowered = word.to_lowercase();
        padded.clear();
        padded.push(' ');
        padded.push_str(&lowered);
        padded.push(' ');
        bounds.clear();
        bounds.extend(padded.char_indices().map(|(index, _)| index));
        bounds.push(padded.len());
        let padded_len = bounds.len() - 1;
        let source = SourceMap::new(word_start, word, padded_len - 2);
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
fn into_vocabulary(vocabulary: HashMap<String, u32>) -> (HashMap<Box<str>, u32>, Vec<Box<str>>) {
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

fn require_decision_rule(decision_rule: &str) -> Result<(), String> {
    if decision_rule != "score > threshold" {
        return Err(format!(
            "unsupported shell risk decision_rule {decision_rule}"
        ));
    }
    Ok(())
}

fn require_threshold_policy(
    thresholds: &BTreeMap<String, f64>,
    default_policy: &str,
) -> Result<(), String> {
    if !thresholds.contains_key(default_policy) {
        return Err(format!(
            "shell risk default threshold policy {default_policy} is not defined"
        ));
    }
    Ok(())
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

/// Validate a `char_wb` block's vectorizer config.
fn char_wb_analyzer(block: &RawBlock) -> Result<BlockAnalyzer, String> {
    let cfg = &block.vectorizer;
    let [min_n, max_n] = cfg
        .ngram_range
        .ok_or_else(|| "shell risk char_wb block is missing ngram_range".to_string())?;
    if cfg.analyzer.as_deref() != Some("char_wb")
        || !cfg.lowercase.unwrap_or(true)
        || cfg.strip_accents.is_some()
        || cfg.sublinear_tf != Some(true)
        || !matches!(cfg.norm.as_deref(), None | Some("l2"))
        || !matches!(cfg.use_idf, None | Some(true))
        || min_n == 0
        || min_n > max_n
    {
        return Err("unsupported shell risk char_wb block configuration".to_string());
    }
    Ok(BlockAnalyzer::CharWb { min_n, max_n })
}

/// Validate a token block's vectorizer config and its analyzer function.
fn token_analyzer(
    block: &RawBlock,
    analyzer_func: &str,
    analyzer: BlockAnalyzer,
) -> Result<BlockAnalyzer, String> {
    let cfg = &block.vectorizer;
    if block.analyzer_func.as_deref() != Some(analyzer_func)
        || cfg.analyzer.is_some()
        || cfg.sublinear_tf != Some(true)
        || !matches!(cfg.norm.as_deref(), None | Some("l2"))
        || !matches!(cfg.use_idf, None | Some(true))
    {
        return Err(format!(
            "unsupported shell risk {} block configuration",
            block.kind
        ));
    }
    Ok(analyzer)
}

/// Maps padded n-gram character offsets back to the source word.
struct SourceMap {
    /// Byte offset of every source character plus the word end, when
    /// lowercasing kept the character count; otherwise only the word bounds.
    bounds: Vec<usize>,
    exact: bool,
}

impl SourceMap {
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

/// Python `str.isspace`, which also treats the ASCII separators
/// U+001C..U+001F as whitespace.
fn is_python_whitespace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// Split like Python `str.split()` and report each word's byte offset.
fn for_each_word(text: &str, mut visit: impl FnMut(usize, &str)) {
    let mut start = None;
    for (index, c) in text.char_indices() {
        if is_python_whitespace(c) {
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

fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// numpy's default `argsort` (`aquicksort`: introsort with median-of-three
/// partitions, insertion sort below 16 elements, heapsort past the depth
/// limit). It is not stable, so ties come out in numpy's order, which the
/// verdict's top features depend on.
fn np_argsort(values: &[f64]) -> Vec<usize> {
    const SMALL_QUICKSORT: usize = 15;
    let n = values.len();
    let mut order: Vec<usize> = (0..n).collect();
    if n < 2 {
        return order;
    }
    let v = |k: usize| values[k];
    let (mut pl, mut pr) = (0usize, n - 1);
    let mut stack: Vec<(usize, usize, i64)> = Vec::new();
    let mut depth = 2 * i64::from(usize::BITS - 1 - n.leading_zeros());
    loop {
        if depth < 0 {
            np_aheapsort(values, &mut order[pl..=pr]);
        } else {
            while pr - pl > SMALL_QUICKSORT {
                let pm = pl + ((pr - pl) >> 1);
                if v(order[pm]) < v(order[pl]) {
                    order.swap(pm, pl);
                }
                if v(order[pr]) < v(order[pm]) {
                    order.swap(pr, pm);
                }
                if v(order[pm]) < v(order[pl]) {
                    order.swap(pm, pl);
                }
                let pivot = v(order[pm]);
                let (mut pi, mut pj) = (pl, pr - 1);
                order.swap(pm, pj);
                loop {
                    pi += 1;
                    while v(order[pi]) < pivot {
                        pi += 1;
                    }
                    pj -= 1;
                    while pivot < v(order[pj]) {
                        pj -= 1;
                    }
                    if pi >= pj {
                        break;
                    }
                    order.swap(pi, pj);
                }
                order.swap(pi, pr - 1);
                depth -= 1;
                // Push the larger partition, continue with the smaller one.
                if pi - pl < pr - pi {
                    stack.push((pi + 1, pr, depth));
                    pr = pi - 1;
                } else {
                    stack.push((pl, pi - 1, depth));
                    pl = pi + 1;
                }
            }
            for pi in pl + 1..=pr {
                let item = order[pi];
                let mut pj = pi;
                while pj > pl && v(item) < v(order[pj - 1]) {
                    order[pj] = order[pj - 1];
                    pj -= 1;
                }
                order[pj] = item;
            }
        }
        match stack.pop() {
            Some((left, right, popped)) => (pl, pr, depth) = (left, right, popped),
            None => return order,
        }
    }
}

/// numpy's `aheapsort` over `order` (1-based heap indexing as in numpy).
fn np_aheapsort(values: &[f64], order: &mut [usize]) {
    let mut n = order.len();
    let sift = |order: &mut [usize], mut i: usize, n: usize, item: usize| {
        let mut j = i << 1;
        while j <= n {
            if j < n && values[order[j - 1]] < values[order[j]] {
                j += 1;
            }
            if values[item] < values[order[j - 1]] {
                order[i - 1] = order[j - 1];
                i = j;
                j += j;
            } else {
                break;
            }
        }
        order[i - 1] = item;
    };
    for l in (1..=n >> 1).rev() {
        let item = order[l - 1];
        sift(order, l, n, item);
    }
    while n > 1 {
        let item = order[n - 1];
        order[n - 1] = order[0];
        n -= 1;
        sift(order, 1, n, item);
    }
}

fn sigmoid(value: f64) -> f64 {
    1.0 / (1.0 + (-value).exp())
}

/// A feature that pushed the model towards the risk class, with its
/// contribution rounded to four decimals.
#[derive(Clone, Debug, PartialEq)]
pub struct TopFeature {
    pub feature: String,
    pub weight: f64,
}

/// `patronus.verdict/1` of one command.
#[derive(Clone, Debug, PartialEq)]
pub struct ShellVerdict {
    pub decision: Decision,
    /// Bundle score: the model score raised to the policy floor.
    pub score: f64,
    /// `ask` and `block` cuts on the score.
    pub ask_cut: f64,
    pub block_cut: f64,
    pub model_id: String,
    pub model_score: f64,
    pub model_decision: Decision,
    pub top_features: Vec<TopFeature>,
    /// Fired policies, strongest first.
    pub policies: Vec<PolicyHit>,
    /// Bundle-default policies the allowlist lowered from block to ask.
    pub allowlisted: Vec<Lowered>,
    pub facts: Facts,
}

impl ShellVerdict {
    /// The verdict document; `facts` holds the canonical facts when included.
    pub fn to_json(&self, with_facts: bool) -> Value {
        let mut value = json!({
            "v": VERDICT_VERSION,
            "decision": self.decision.as_str(),
            "score": py_round(self.score, 4),
            "cuts": {"ask": py_round(self.ask_cut, 6), "block": py_round(self.block_cut, 6)},
            "model": {
                "id": self.model_id,
                "score": py_round(self.model_score, 4),
                "decision": self.model_decision.as_str(),
                "top_features": self.top_features.iter()
                    .map(|f| json!({"feature": f.feature, "weight": f.weight}))
                    .collect::<Vec<_>>(),
            },
            "policies": self.policies.iter().map(|p| json!({
                "id": p.id,
                "tier": p.tier.as_str(),
                "title": p.title,
                "decision": p.decision.as_str(),
                "where": p.r#where,
            })).collect::<Vec<_>>(),
            "allowlisted": self.allowlisted.iter()
                .map(|l| json!({"id": l.id, "from": "block", "to": "ask"}))
                .collect::<Vec<_>>(),
        });
        if with_facts {
            let mut facts = self.facts.to_json();
            pyjson::canonical(&mut facts);
            value["facts"] = facts;
        }
        value
    }

    /// Compact JSON with sorted keys, as the Python reference writes it.
    pub fn to_json_string(&self, with_facts: bool) -> String {
        pyjson::dumps_compact(&self.to_json(with_facts))
    }
}

/// Score of one command.
#[derive(Debug, Clone, PartialEq)]
pub struct ShellRiskScore {
    /// Model decision score (logit).
    pub decision_score: f64,
    /// Score after policy floors.
    pub bundle_score: f64,
    /// `ask` threshold (1 % FPR cut).
    pub threshold: f64,
    pub decision: Decision,
    /// Whether the verdict is `ask` or `block`.
    pub flagged: bool,
}

/// Shell command scanner for the `shell_command` category: the K26 model plus
/// the bundle's Cedar policies, with user policies and allowlist from the
/// runtime configuration.
pub struct ShellRiskPipeline {
    model: ShellRiskModel,
    ask_cut: f64,
    block_cut: f64,
    /// Swapped by [`Self::configure`]; scans clone the `Arc` and hold no lock.
    policies: RwLock<Arc<ShellPolicies>>,
}

fn decide(score: f64, ask: f64, block: f64) -> Decision {
    if score > block {
        Decision::Block
    } else if score > ask {
        Decision::Ask
    } else {
        Decision::Allow
    }
}

impl ShellRiskPipeline {
    /// The model alone, without policies. Needs the `ask` and `block` cuts.
    pub fn new(model: ShellRiskModel) -> Result<Self, String> {
        Self::with_policies(model, ShellPolicies::none())
    }

    fn with_policies(model: ShellRiskModel, policies: ShellPolicies) -> Result<Self, String> {
        let cut = |name: &str| {
            model
                .threshold(name)
                .ok_or_else(|| format!("shell risk model has no {name} threshold"))
        };
        Ok(Self {
            ask_cut: cut(ASK_THRESHOLD)?,
            block_cut: cut(BLOCK_THRESHOLD)?,
            model,
            policies: RwLock::new(Arc::new(policies)),
        })
    }

    /// Load a verified bundle: `model.json` and the gated `policy_levels.json`
    /// named by `config.json`, each checked against `manifest.json`.
    pub fn from_bundle_dir(dir: &Path) -> Result<Self, String> {
        let bundle = VerifiedBundle::open(dir)?;
        let config = bundle
            .config()?
            .ok_or_else(|| format!("{} has no config.json", dir.display()))?;
        let levels_file = config
            .policy_levels_file
            .unwrap_or_else(|| "policy_levels.json".to_string());
        let levels: HashMap<String, String> =
            serde_json::from_slice(&bundle.read(&levels_file)?)
                .map_err(|error| format!("invalid {levels_file}: {error}"))?;
        // TODO(K26 bundle signing): verify a signature over the manifest for the core tier.
        let model = ShellRiskModel::from_bundle(&bundle)?;
        Self::with_policies(model, ShellPolicies::from_levels(&levels)?)
    }

    /// Apply user policies and allowlist from the runtime configuration,
    /// replacing earlier ones. A refused configuration leaves the pipeline
    /// unchanged.
    pub fn configure(&self, config: &ShellPolicyConfig) -> Result<(), String> {
        let configured = self.current_policies().configure(config)?;
        *self.policies.write().expect("shell policies lock poisoned") = Arc::new(configured);
        Ok(())
    }

    fn current_policies(&self) -> Arc<ShellPolicies> {
        Arc::clone(&self.policies.read().expect("shell policies lock poisoned"))
    }

    /// Loaded model.
    pub fn model(&self) -> &ShellRiskModel {
        &self.model
    }

    /// The `ask` and `block` cuts.
    pub fn cuts(&self) -> (f64, f64) {
        (self.ask_cut, self.block_cut)
    }

    /// `patronus.verdict/1` of `text`. `context` and `prior_facts` (facts of
    /// earlier commands of the same session, kept by the caller) reach the
    /// policies through the facts; the model sees the text only.
    pub fn verdict(
        &self,
        text: &str,
        context: Option<&ShellContext>,
        prior_facts: &[Facts],
    ) -> Result<ShellVerdict, String> {
        let facts = extract(text, context, prior_facts);
        let context_free = context.is_none_or(ShellContext::is_unset) && prior_facts.is_empty();
        let (model_score, top_features) = if context_free {
            self.model.score_with_top_features(text, &facts)
        } else {
            self.model
                .score_with_top_features(text, &extract(text, None, &[]))
        };
        let (policies, allowlisted) = self.current_policies().evaluate(&facts, text)?;
        // Policy floors: ask sits between the two cuts, block clearly above the block cut.
        let floor = policies.iter().map(|p| p.decision).max();
        let score = match floor {
            Some(Decision::Block) => model_score.max(self.block_cut + 2.0),
            Some(Decision::Ask) => model_score.max((self.ask_cut + self.block_cut) / 2.0),
            _ => model_score,
        };
        Ok(ShellVerdict {
            decision: decide(score, self.ask_cut, self.block_cut),
            score,
            ask_cut: self.ask_cut,
            block_cut: self.block_cut,
            model_id: self.model.name().to_string(),
            model_score,
            model_decision: decide(model_score, self.ask_cut, self.block_cut),
            top_features,
            policies,
            allowlisted,
            facts,
        })
    }

    /// Score one command without context.
    pub fn score(&self, text: &str) -> Result<ShellRiskScore, String> {
        self.verdict(text, None, &[]).map(|verdict| ShellRiskScore {
            decision_score: verdict.model_score,
            bundle_score: verdict.score,
            threshold: self.ask_cut,
            decision: verdict.decision,
            flagged: verdict.decision != Decision::Allow,
        })
    }

    /// Scan one command. `ask` and `block` both flag it; the caller maps them
    /// (the Patronus runtime asks for confirmation and never blocks on its own).
    pub fn detect(&self, text: &str) -> NativeDetection {
        let verdict = match self.verdict(text, None, &[]) {
            Ok(verdict) => verdict,
            // Policies are schema-validated at load, so evaluation does not fail;
            // if it does, fail closed and say why.
            Err(error) => {
                return NativeDetection {
                    result: EvaluationResult {
                        class_name: SHELL_RISK_CLASS.to_string(),
                        confidence: 0.5,
                        level: "L1".to_string(),
                    },
                    evidence_spans: Vec::new(),
                    details: HashMap::from([("error".to_string(), json!(error))]),
                }
            }
        };
        let flagged = verdict.decision != Decision::Allow;
        let evidence_spans = if flagged {
            self.model.evidence(text)
        } else {
            Vec::new()
        };
        let details = HashMap::from([
            ("model".to_string(), json!(self.model.name())),
            ("decision".to_string(), json!(verdict.decision.as_str())),
            ("decision_score".to_string(), json!(verdict.model_score)),
            ("bundle_score".to_string(), json!(verdict.score)),
            ("threshold".to_string(), json!(self.ask_cut)),
            ("threshold_policy".to_string(), json!(ASK_THRESHOLD)),
            ("verdict".to_string(), verdict.to_json(true)),
        ]);
        NativeDetection {
            result: EvaluationResult {
                class_name: if flagged {
                    SHELL_RISK_CLASS
                } else {
                    SAFE_CLASS
                }
                .to_string(),
                // Distance from the ask cut, squashed to 0.5..1. The logit is
                // not a calibrated probability.
                confidence: sigmoid((verdict.score - self.ask_cut).abs()),
                level: "L1".to_string(),
            },
            evidence_spans,
            details,
        }
    }

    /// Evaluate one command.
    pub fn evaluate(&self, text: &str) -> EvaluationResult {
        self.detect(text).result
    }

    /// Evaluate commands in parallel.
    pub fn evaluate_batch(&self, texts: &[String]) -> Vec<EvaluationResult> {
        use rayon::prelude::*;
        texts.par_iter().map(|text| self.evaluate(text)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A two-block K26-shaped model whose `kf1` feature `CMD=curl` is the only
    /// token feature; the `char_wb` block scores `rm -rf`.
    fn tiny_model_json() -> Value {
        json!({
            "format_version": 2,
            "name": "tiny",
            "blocks": [
                {
                    "kind": "char_wb",
                    "vectorizer": {
                        "analyzer": "char_wb", "ngram_range": [3, 5],
                        "lowercase": true, "sublinear_tf": true
                    },
                    "feature_dtype": "float32",
                    "idf_dtype": "float32",
                    "vocabulary": {" rm": 0, "rm ": 1, " rm ": 2, "-rf": 3, " ls ": 4, " ab ": 5},
                    "idf": [1.0, 1.0, 1.0, 2.0, 1.0, 1.0]
                },
                {
                    "kind": "tokens",
                    "analyzer_func": "kf1",
                    "vectorizer": {"sublinear_tf": true, "min_df": 2},
                    "feature_dtype": "float32",
                    "idf_dtype": "float32",
                    "vocabulary": {"CMD=curl": 0},
                    "idf": [1.0]
                }
            ],
            "weights": [1.0, 1.0, 1.0, 2.0, -3.0, 0.5, 4.0],
            "intercept": -1.0,
            "thresholds": {"external_commands_1pct_fpr": 0.0, "block_0_1pct_fpr": 2.5},
            "default_threshold_policy": "external_commands_1pct_fpr",
            "decision_rule": "score > threshold"
        })
    }

    fn tiny_model() -> ShellRiskModel {
        ShellRiskModel::from_json_slice(tiny_model_json().to_string().as_bytes()).unwrap()
    }

    fn ngrams(text: &str) -> Vec<(String, String)> {
        let mut out = Vec::new();
        visit_char_wb_ngrams(text, 3, 5, |ngram, range| {
            out.push((ngram.to_string(), text[range].to_string()))
        });
        out
    }

    #[test]
    fn char_wb_counts_short_words_once() {
        let grams = ngrams("ab")
            .into_iter()
            .map(|(gram, _)| gram)
            .collect::<Vec<_>>();
        assert_eq!(grams, [" ab", "ab ", " ab "]);
    }

    #[test]
    fn char_wb_lowercases_and_maps_source_ranges() {
        let grams = ngrams("RM -RF");
        assert_eq!(grams[0], (" rm".to_string(), "RM".to_string()));
        assert_eq!(grams[1], ("rm ".to_string(), "RM".to_string()));
        assert_eq!(grams[2], (" rm ".to_string(), "RM".to_string()));
        assert!(grams.contains(&("-rf".to_string(), "-RF".to_string())));
    }

    #[test]
    fn python_whitespace_includes_ascii_separators() {
        let model = tiny_model();
        assert_eq!(
            model.decision_score("rm\u{1c}-rf"),
            model.decision_score("rm -rf")
        );
        assert_eq!(
            model.decision_score("rm\u{a0}\u{2003}-rf"),
            model.decision_score("rm\t-rf")
        );
    }

    #[test]
    fn empty_text_scores_the_intercept() {
        assert_eq!(tiny_model().decision_score(""), -1.0);
        assert_eq!(tiny_model().decision_score(" \n\t"), -1.0);
    }

    #[test]
    fn sublinear_tf_idf_is_l2_normalized() {
        // " ls " occurs twice: tf = 1 + ln 2; it is the only vocabulary term.
        let score = tiny_model().decision_score("ls ls");
        assert!((score - (-1.0 - 3.0)).abs() < 1e-6, "{score}");
    }

    #[test]
    fn kf1_block_scores_token_features() {
        // CMD=curl is the only token feature: weight 4, normalized value 1.
        let score = tiny_model().decision_score("curl x");
        assert!((score - 3.0).abs() < 1e-6, "{score}");
    }

    #[test]
    fn argsort_breaks_ties_like_numpy() {
        // Reference orders from numpy 2.5 `np.argsort`.
        let cases: [(&[f64], &[usize]); 3] = [
            (&[0.125, 0.25, 1.0, 0.5, 0.5], &[0, 1, 3, 4, 2]),
            (
                &[
                    0.5, 0.125, 0.5, 0.25, 0.5, 0.5, 1.0, 1.0, 0.5, 0.25, 0.5, 1.0, 0.5, 0.5, 0.25,
                    0.5, 1.0,
                ],
                &[1, 14, 3, 9, 0, 13, 12, 10, 8, 5, 4, 2, 15, 7, 6, 11, 16],
            ),
            (
                &[
                    0.5, 0.25, 0.5, 0.25, 0.125, 1.0, 0.25, 0.5, 0.125, 0.25, 0.5, 0.25, 0.125,
                    0.5, 0.5, 0.5, 0.25, 1.0, 1.0, 0.125, 1.0, 1.0, 0.125, 0.125, 0.25, 0.25, 0.25,
                    0.5, 0.125, 1.0, 0.125, 1.0, 0.125, 0.5, 0.5, 1.0, 0.25, 0.125, 0.25, 1.0,
                ],
                &[
                    19, 28, 30, 32, 12, 22, 8, 23, 4, 37, 6, 9, 36, 3, 1, 16, 26, 38, 25, 24, 11,
                    33, 27, 34, 0, 15, 14, 13, 10, 7, 2, 20, 18, 17, 29, 31, 35, 5, 21, 39,
                ],
            ),
        ];
        for (values, expected) in cases {
            assert_eq!(np_argsort(values), expected);
        }
        let mut order = vec![0, 1, 2, 3, 4];
        np_aheapsort(&[3.0, 1.0, 2.0, 1.0, 0.0], &mut order);
        let sorted: Vec<f64> = order
            .iter()
            .map(|&k| [3.0, 1.0, 2.0, 1.0, 0.0][k])
            .collect();
        assert_eq!(sorted, [0.0, 1.0, 1.0, 2.0, 3.0]);
    }

    #[test]
    fn rejects_inconsistent_models() {
        let parse = |model: &Value| ShellRiskModel::from_json_slice(model.to_string().as_bytes());
        assert!(parse(&tiny_model_json()).is_ok());
        let mut released_g = tiny_model_json();
        released_g["blocks"][1]["kind"] = json!("shell_tokens");
        released_g["blocks"][1]["analyzer_func"] = json!("features");
        released_g["model_type"] = json!(G_MODEL_TYPE);
        assert!(parse(&released_g).is_ok());
        for broken in [
            ("/format_version", json!(1)),
            ("/blocks/0/vectorizer/analyzer", json!("char")),
            ("/blocks/0/vocabulary/ ab ", json!(6)),
            ("/blocks/1/analyzer_func", json!("other")),
            ("/blocks/1/kind", json!("shell_tokens")),
            ("/default_threshold_policy", json!("missing")),
        ] {
            let mut model = tiny_model_json();
            *model.pointer_mut(broken.0).unwrap() = broken.1.clone();
            assert!(parse(&model).is_err(), "{} = {}", broken.0, broken.1);
        }
        let mut model = tiny_model_json();
        model["block_feature_counts"] = json!([6, 2]);
        assert!(parse(&model).is_err());
        model["model_type"] = json!("other");
        assert!(parse(&model).is_err());
    }

    #[test]
    fn verdict_combines_model_and_policy_floor() {
        let pipeline = ShellRiskPipeline::new(tiny_model()).unwrap();
        let verdict = pipeline.verdict("ls", None, &[]).unwrap();
        assert_eq!(verdict.decision, Decision::Allow);
        assert!(verdict.policies.is_empty());
        let verdict = pipeline.verdict("curl x", None, &[]).unwrap();
        assert_eq!(
            (verdict.model_decision, verdict.decision),
            (Decision::Block, Decision::Block)
        );
        assert_eq!(verdict.top_features[0].feature, "tok:CMD=curl");

        let config = ShellPolicyConfig {
            user_policies: vec![super::super::policies::UserPolicy {
                id: "user.no_ls".into(),
                decision: "ask".into(),
                scope: None,
                condition: r#"context.program == "ls""#.into(),
                title: None,
            }],
            allowlist: BTreeMap::new(),
        };
        pipeline.configure(&config).unwrap();
        let verdict = pipeline.verdict("ls", None, &[]).unwrap();
        assert_eq!(verdict.decision, Decision::Ask);
        assert_eq!(verdict.score, 1.25);
        assert_eq!(verdict.policies[0].id, "user.no_ls");
        let json = verdict.to_json_string(false);
        assert!(
            json.starts_with(
                r#"{"allowlisted":[],"cuts":{"ask":0.0,"block":2.5},"decision":"ask""#
            ),
            "{json}"
        );
    }

    #[test]
    fn a_model_without_cuts_cannot_decide() {
        let mut model = tiny_model_json();
        model["thresholds"] = json!({"external_commands_1pct_fpr": 0.0});
        let model = ShellRiskModel::from_json_slice(model.to_string().as_bytes()).unwrap();
        assert!(ShellRiskPipeline::new(model).is_err());
    }

    #[test]
    fn token_only_flag_reports_the_trimmed_command() {
        let text = "  curl  ";
        let spans = tiny_model().evidence(text);
        assert_eq!(spans.len(), 1);
        assert_eq!((spans[0].start_byte, spans[0].end_byte), (2, 6));
        assert_eq!(spans[0].text, "curl");
        assert_eq!(spans[0].score, 1.0);
    }

    #[test]
    fn flagged_detection_reports_verdict_and_evidence() {
        let pipeline = ShellRiskPipeline::new(tiny_model()).unwrap();
        let detection = pipeline.detect("RM -RF");
        assert_eq!(detection.result.class_name, SHELL_RISK_CLASS);
        assert!(detection.result.confidence > 0.5);
        assert_eq!(detection.details["decision"], "ask");
        assert_eq!(detection.details["verdict"]["v"], VERDICT_VERSION);
        assert_eq!(
            detection.details["verdict"]["facts"]["segments"][0]["program"],
            "rm"
        );
        let spans = detection
            .evidence_spans
            .iter()
            .map(|span| (span.text.as_str(), span.start_byte, span.end_byte))
            .collect::<Vec<_>>();
        assert_eq!(spans, [("RM", 0, 2), ("-RF", 3, 6)]);

        let safe = pipeline.detect("ls");
        assert_eq!(safe.result.class_name, SAFE_CLASS);
        assert!(safe.evidence_spans.is_empty());
    }
}
