// SPDX-License-Identifier: GPL-3.0-only
// Entity-only inference for classic GLiNER span-level ONNX models.

use ort::{
    ep::CPU,
    session::{builder::GraphOptimizationLevel, Session},
    value::{DynValue, Tensor},
};
use regex::Regex;
use sentencepiece_rust::SentencePieceProcessor;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs, io,
    path::{Component, Path, PathBuf},
};

/// Errors returned by the GLiNER ONNX engine.
///
/// Callers can match on the variant to distinguish an actionable asset/bundle
/// problem (re-download, fix the model directory) from a caller mistake
/// (`InvalidInput`) or an internal runtime failure.
#[derive(Debug, thiserror::Error)]
pub enum ArkEngineError {
    /// A required model asset is missing from the bundle directory.
    #[error("missing GLiNER asset: {0}")]
    MissingAsset(String),
    /// The bundle exists but is inconsistent, unsupported, or corrupt.
    #[error("invalid GLiNER bundle: {0}")]
    InvalidBundle(String),
    /// The caller passed invalid arguments (labels or threshold).
    #[error("invalid input: {0}")]
    InvalidInput(String),
    /// Failed to read a bundle config file.
    #[error("failed to read GLiNER config {path}: {source}")]
    ConfigRead {
        path: String,
        #[source]
        source: io::Error,
    },
    /// Failed to parse a bundle config file.
    #[error("failed to parse GLiNER config {path}: {source}")]
    ConfigParse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    /// SentencePiece tokenizer failure.
    #[error("tokenizer error: {0}")]
    Tokenizer(String),
    /// Model inference produced an unexpected result.
    #[error("inference error: {0}")]
    Inference(String),
    /// Underlying ONNX Runtime error.
    #[error("ONNX runtime error: {0}")]
    Onnx(String),
    /// Invalid internal regex.
    #[error("regex error: {0}")]
    Regex(#[from] regex::Error),
    /// Generic I/O error.
    #[error(transparent)]
    Io(#[from] io::Error),
}

// `ort::Error` is generic over a context marker (e.g. `ort::Error<SessionBuilder>`),
// so a single `#[from]` cannot cover every call site. This blanket conversion
// flattens any ORT error context into a message.
impl<C> From<ort::Error<C>> for ArkEngineError
where
    ort::Error<C>: std::fmt::Display,
{
    fn from(error: ort::Error<C>) -> Self {
        ArkEngineError::Onnx(error.to_string())
    }
}

pub type EngineResult<T> = Result<T, ArkEngineError>;

#[derive(Debug, Clone, Serialize)]
pub struct Entity {
    pub label: String,
    pub text: String,
    pub score: f32,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_char: usize,
    pub end_char: usize,
}

#[derive(Deserialize)]
struct BundleConfig {
    max_len: usize,
    max_width: usize,
    special_tokens: HashMap<String, u32>,
    model_file: PathBuf,
}

#[derive(Deserialize)]
struct ModelConfig {
    max_len: usize,
    max_types: usize,
    max_width: usize,
    model_name: String,
    model_type: String,
    words_splitter_type: String,
}

#[derive(Deserialize)]
struct QuantizationManifest {
    model_file: PathBuf,
    precision: QuantizationPrecision,
}

#[derive(Deserialize)]
struct QuantizationPrecision {
    word_embeddings: String,
    matmul_weights: String,
}

struct WordSpan {
    start: usize,
    end: usize,
    text: String,
}

struct PreparedInput {
    input_ids: Vec<i64>,
    attention_mask: Vec<i64>,
    words_mask: Vec<i64>,
    text_length: usize,
    span_idx: Vec<i64>,
    span_mask: Vec<bool>,
    words: Vec<WordSpan>,
}

pub struct GlinerEngine {
    session: Session,
    tokenizer: SentencePieceProcessor,
    splitter: Regex,
    special_tokens: HashMap<String, u32>,
    max_len: usize,
    max_types: usize,
    max_width: usize,
    model_name: String,
    model_path: PathBuf,
}

impl GlinerEngine {
    /// Validate a local Edge bundle without creating an ONNX session.
    pub fn validate_path(path: impl AsRef<Path>) -> EngineResult<()> {
        validated_bundle(path.as_ref()).map(|_| ())
    }

    pub fn from_path(path: impl AsRef<Path>) -> EngineResult<Self> {
        let path = path.as_ref();
        let (bundle, model) = validated_bundle(path)?;
        let model_path = path.join(&bundle.model_file);
        let tokenizer = SentencePieceProcessor::open(path.join("spm.model")).map_err(|error| {
            ArkEngineError::Tokenizer(format!("failed to load spm.model: {error}"))
        })?;
        let session = Session::builder()?
            .with_optimization_level(GraphOptimizationLevel::All)?
            .with_execution_providers([CPU::default().with_arena_allocator(false).build()])?
            .with_memory_pattern(false)?
            .with_prepacking(false)?
            .commit_from_file(&model_path)?;
        Ok(Self {
            session,
            tokenizer,
            splitter: Regex::new(r"\w+(?:[-_]\w+)*|\S")?,
            special_tokens: bundle.special_tokens,
            max_len: bundle.max_len,
            max_types: model.max_types,
            max_width: bundle.max_width,
            model_name: model.model_name,
            model_path,
        })
    }

    pub fn extract_entities(
        &mut self,
        text: &str,
        labels: &[String],
        threshold: f32,
    ) -> EngineResult<Vec<Entity>> {
        self.extract_entities_with_mode(text, labels, threshold, true)
    }

    pub fn extract_entity_candidates(
        &mut self,
        text: &str,
        labels: &[String],
        threshold: f32,
    ) -> EngineResult<Vec<Entity>> {
        self.extract_entities_with_mode(text, labels, threshold, false)
    }

    fn extract_entities_with_mode(
        &mut self,
        text: &str,
        labels: &[String],
        threshold: f32,
        flat_ner: bool,
    ) -> EngineResult<Vec<Entity>> {
        let labels = normalize_labels(labels, self.max_types)?;
        if !(0.0..=1.0).contains(&threshold) {
            return Err(ArkEngineError::InvalidInput(
                "threshold must be between 0 and 1".to_string(),
            ));
        }
        let prepared = self.prepare(text, &labels)?;
        if prepared.words.is_empty() {
            return Ok(Vec::new());
        }

        let sequence_length = prepared.input_ids.len();
        let span_count = prepared.span_mask.len();
        let outputs = self.session.run(vec![
            input("input_ids", vec![1, sequence_length], prepared.input_ids)?,
            input(
                "attention_mask",
                vec![1, sequence_length],
                prepared.attention_mask,
            )?,
            input("words_mask", vec![1, sequence_length], prepared.words_mask)?,
            input(
                "text_lengths",
                vec![1, 1],
                vec![prepared.text_length as i64],
            )?,
            input("span_idx", vec![1, span_count, 2], prepared.span_idx)?,
            (
                "span_mask".to_string(),
                Tensor::from_array((vec![1, span_count], prepared.span_mask))?.into_dyn(),
            ),
        ])?;
        let logits = outputs
            .get("logits")
            .ok_or_else(|| ArkEngineError::Inference("missing logits output".to_string()))?;
        let (shape, logits) = logits.try_extract_tensor::<f32>()?;
        let expected_shape = [1, prepared.text_length, self.max_width, labels.len()];
        let actual_shape = shape
            .iter()
            .map(|dimension| usize::try_from(*dimension).unwrap_or(usize::MAX))
            .collect::<Vec<_>>();
        if actual_shape != expected_shape {
            return Err(ArkEngineError::Inference(format!(
                "logits has shape {actual_shape:?}; expected {expected_shape:?}"
            )));
        }
        let expected = prepared.text_length * self.max_width * labels.len();
        if logits.len() != expected {
            return Err(ArkEngineError::Inference(format!(
                "logits has {} values; expected {expected}",
                logits.len()
            )));
        }
        let candidates = decode_candidates(
            text,
            &labels,
            &prepared.words,
            logits,
            self.max_width,
            threshold,
        );
        Ok(if flat_ner {
            merge_flat_entities(candidates)
        } else {
            candidates
        })
    }

    pub fn text_token_count(&self, text: &str) -> EngineResult<usize> {
        self.splitter
            .find_iter(text)
            .take(self.max_len)
            .try_fold(0usize, |count, matched| {
                self.encode_word(matched.as_str())
                    .map(|ids| count + ids.len())
            })
    }

    pub fn model_name(&self) -> &str {
        &self.model_name
    }

    pub fn model_path(&self) -> &Path {
        &self.model_path
    }

    pub fn max_types(&self) -> usize {
        self.max_types
    }

    fn prepare(&self, text: &str, labels: &[String]) -> EngineResult<PreparedInput> {
        let mut words = Vec::new();
        for matched in self.splitter.find_iter(text) {
            if self.encode_word(matched.as_str())?.is_empty() {
                continue;
            }
            words.push(WordSpan {
                start: matched.start(),
                end: matched.end(),
                text: matched.as_str().to_string(),
            });
            if words.len() == self.max_len {
                break;
            }
        }
        if words.is_empty() {
            return Ok(PreparedInput {
                input_ids: Vec::new(),
                attention_mask: Vec::new(),
                words_mask: Vec::new(),
                text_length: 0,
                span_idx: Vec::new(),
                span_mask: Vec::new(),
                words,
            });
        }

        let mut input_ids = vec![i64::from(self.special("[CLS]")?)];
        let mut words_mask = vec![0];
        for label in labels {
            input_ids.push(i64::from(self.special("<<ENT>>")?));
            words_mask.push(0);
            let ids = self.encode_word(label)?;
            input_ids.extend(ids.iter().copied());
            words_mask.extend(std::iter::repeat_n(0, ids.len()));
        }
        input_ids.push(i64::from(self.special("<<SEP>>")?));
        words_mask.push(0);

        for (word_index, word) in words.iter().enumerate() {
            let ids = self.encode_word(&word.text)?;
            input_ids.extend(ids.iter().copied());
            words_mask.push((word_index + 1) as i64);
            words_mask.extend(std::iter::repeat_n(0, ids.len() - 1));
        }
        input_ids.push(i64::from(self.special("[SEP]")?));
        words_mask.push(0);

        let attention_mask = vec![1; input_ids.len()];
        let mut span_idx = Vec::with_capacity(words.len() * self.max_width * 2);
        let mut span_mask = Vec::with_capacity(words.len() * self.max_width);
        for start in 0..words.len() {
            for width in 0..self.max_width {
                span_idx.push(start as i64);
                span_idx.push((start + width) as i64);
                span_mask.push(start + width < words.len());
            }
        }
        Ok(PreparedInput {
            input_ids,
            attention_mask,
            words_mask,
            text_length: words.len(),
            span_idx,
            span_mask,
            words,
        })
    }

    fn encode_word(&self, word: &str) -> EngineResult<Vec<i64>> {
        if let Some(id) = self.special_tokens.get(word) {
            return Ok(vec![i64::from(*id)]);
        }
        self.tokenizer
            .encode(word)
            .map(|ids| ids.into_iter().map(i64::from).collect())
            .map_err(|error| {
                ArkEngineError::Tokenizer(format!("failed to tokenize {word:?}: {error}"))
            })
    }

    fn special(&self, token: &str) -> EngineResult<u32> {
        self.special_tokens.get(token).copied().ok_or_else(|| {
            ArkEngineError::InvalidBundle(format!("missing special token {token:?}"))
        })
    }
}

fn validated_bundle(path: &Path) -> EngineResult<(BundleConfig, ModelConfig)> {
    let bundle: BundleConfig = read_json(&path.join("gliner_onnx_config.json"))?;
    let model: ModelConfig = read_json(&path.join("gliner_config.json"))?;
    let quantization: QuantizationManifest = read_json(&path.join("quantization_manifest.json"))?;
    validate_bundle(&bundle, &model, &quantization)?;
    let model_path = path.join(&bundle.model_file);
    if !model_path.is_file() {
        return Err(ArkEngineError::MissingAsset(format!(
            "missing GLiNER ONNX model: {}",
            model_path.display()
        )));
    }
    let tokenizer_path = path.join("spm.model");
    if !tokenizer_path.is_file() {
        return Err(ArkEngineError::MissingAsset(format!(
            "missing GLiNER tokenizer: {}",
            tokenizer_path.display()
        )));
    }
    Ok((bundle, model))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> EngineResult<T> {
    let contents = fs::read_to_string(path).map_err(|source| ArkEngineError::ConfigRead {
        path: path.display().to_string(),
        source,
    })?;
    serde_json::from_str(&contents).map_err(|source| ArkEngineError::ConfigParse {
        path: path.display().to_string(),
        source,
    })
}

fn validate_bundle(
    bundle: &BundleConfig,
    model: &ModelConfig,
    quantization: &QuantizationManifest,
) -> EngineResult<()> {
    if bundle.max_len == 0 || bundle.max_width == 0 || model.max_types == 0 {
        return Err(ArkEngineError::InvalidBundle(
            "GLiNER max_len, max_width and max_types must be greater than zero".to_string(),
        ));
    }
    if bundle.max_len != model.max_len || bundle.max_width != model.max_width {
        return Err(ArkEngineError::InvalidBundle(
            "gliner_onnx_config.json disagrees with gliner_config.json".to_string(),
        ));
    }
    if model.model_type != "gliner" || model.words_splitter_type != "whitespace" {
        return Err(ArkEngineError::InvalidBundle(
            "only classic whitespace span-level GLiNER bundles are supported".to_string(),
        ));
    }
    if bundle.model_file != quantization.model_file
        || quantization.precision.word_embeddings != "uint4"
        || quantization.precision.matmul_weights != "qint8"
    {
        return Err(ArkEngineError::InvalidBundle(
            "GLiNER quantization manifest does not match the ONNX bundle".to_string(),
        ));
    }
    if bundle
        .model_file
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(ArkEngineError::InvalidBundle(
            "GLiNER model_file must be a relative file name".to_string(),
        ));
    }
    for token in ["[CLS]", "[SEP]", "<<ENT>>", "<<SEP>>"] {
        if !bundle.special_tokens.contains_key(token) {
            return Err(ArkEngineError::InvalidBundle(format!(
                "missing GLiNER special token {token:?}"
            )));
        }
    }
    Ok(())
}

fn normalize_labels(labels: &[String], max_types: usize) -> EngineResult<Vec<String>> {
    let mut seen = HashSet::new();
    let mut normalized = Vec::with_capacity(labels.len());
    for label in labels {
        if label.trim().is_empty() {
            return Err(ArkEngineError::InvalidInput(
                "labels must not contain empty values".to_string(),
            ));
        }
        if seen.insert(label.as_str()) {
            normalized.push(label.clone());
        }
    }
    if normalized.is_empty() {
        return Err(ArkEngineError::InvalidInput(
            "labels must not be empty".to_string(),
        ));
    }
    if normalized.len() > max_types {
        return Err(ArkEngineError::InvalidInput(format!(
            "GLiNER supports at most {max_types} unique labels, got {}",
            normalized.len()
        )));
    }
    Ok(normalized)
}

fn input(name: &str, shape: Vec<usize>, values: Vec<i64>) -> EngineResult<(String, DynValue)> {
    Ok((
        name.to_string(),
        Tensor::from_array((shape, values))?.into_dyn(),
    ))
}

fn decode_candidates(
    text: &str,
    labels: &[String],
    words: &[WordSpan],
    logits: &[f32],
    max_width: usize,
    threshold: f32,
) -> Vec<Entity> {
    let mut candidates = Vec::new();
    for start in 0..words.len() {
        for width in 0..max_width {
            let end = start + width;
            if end >= words.len() {
                continue;
            }
            for (label_index, label) in labels.iter().enumerate() {
                let index = (start * max_width + width) * labels.len() + label_index;
                let score = sigmoid(logits[index]);
                if score > threshold {
                    let start_byte = words[start].start;
                    let end_byte = words[end].end;
                    candidates.push(Entity {
                        label: label.clone(),
                        text: text[start_byte..end_byte].to_string(),
                        score,
                        start_byte,
                        end_byte,
                        start_char: text[..start_byte].chars().count(),
                        end_char: text[..end_byte].chars().count(),
                    });
                }
            }
        }
    }

    candidates
}

fn merge_flat_entities(mut candidates: Vec<Entity>) -> Vec<Entity> {
    candidates.sort_by(|left, right| right.score.total_cmp(&left.score));
    let mut entities = Vec::new();
    for candidate in candidates {
        let overlaps = entities.iter().any(|selected: &Entity| {
            candidate.start_byte < selected.end_byte && candidate.end_byte > selected.start_byte
        });
        if !overlaps {
            entities.push(candidate);
        }
    }
    entities.sort_by_key(|entity| (entity.start_byte, entity.end_byte));
    entities
}

fn sigmoid(value: f32) -> f32 {
    if value >= 0.0 {
        1.0 / (1.0 + (-value).exp())
    } else {
        let exp = value.exp();
        exp / (1.0 + exp)
    }
}
