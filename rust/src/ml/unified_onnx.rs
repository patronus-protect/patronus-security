// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ort::{session::Session, value::Tensor};

use crate::{ExecutionBackend, LabelScore, OnnxRuntimeOptions};

use super::onnx::{
    configured_session_builder, l3_ttl, token_chunks, RuntimeTokenizer, TokenTextChunk,
};

pub const UNIFIED_MODEL: &str = "unified-multitask-model-augmented-v3";
pub const UNIFIED_ONNX_PATH: &str = "onnx/int8_int4_embeddings/model.onnx";
pub const UNIFIED_MAX_LEN: usize = 256;

const HEADS: &[HeadSpec] = &[
    HeadSpec::binary("injection", "injection_logits", &["benign", "injection"]),
    HeadSpec::softmax(
        "sensitive_document",
        "sensitive_logits",
        &[
            "legal",
            "hr",
            "finance",
            "internal_and_tech",
            "source_code",
            "marketing",
            "other",
        ],
    ),
    HeadSpec::softmax(
        "tool_class",
        "tool_class_logits",
        &[
            "file",
            "database",
            "vcs",
            "api",
            "memory",
            "messaging",
            "web",
            "browser",
            "shell",
            "code",
            "system",
            "secrets",
            "infra",
            "unknown",
        ],
    ),
    HeadSpec::softmax(
        "tool_action",
        "tool_action_logits",
        &["read", "write", "list", "exec", "network", "unknown"],
    ),
    HeadSpec::multilabel(
        "tool_tags",
        "tool_tags_logits",
        &["source:sensitive", "source:untrusted", "sink:external"],
    ),
    HeadSpec::softmax(
        "routing",
        "routing_logits",
        &[
            "benign_conv",
            "code_development_request",
            "data_analytics_request",
            "office_request",
            "tool_operation_request",
        ],
    ),
    HeadSpec::softmax(
        "threat",
        "threat_logits",
        &[
            "instruction_override",
            "secrets_access",
            "tool_abuse",
            "harmful_behavior",
            "exfiltration_attempt",
            "toxic_or_harmful",
            "benign",
        ],
    ),
];

#[derive(Clone, Copy)]
enum HeadKind {
    Binary,
    Softmax,
    MultiLabel,
}

#[derive(Clone, Copy)]
struct HeadSpec {
    id: &'static str,
    output: &'static str,
    labels: &'static [&'static str],
    kind: HeadKind,
}

impl HeadSpec {
    const fn binary(
        id: &'static str,
        output: &'static str,
        labels: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            output,
            labels,
            kind: HeadKind::Binary,
        }
    }

    const fn softmax(
        id: &'static str,
        output: &'static str,
        labels: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            output,
            labels,
            kind: HeadKind::Softmax,
        }
    }

    const fn multilabel(
        id: &'static str,
        output: &'static str,
        labels: &'static [&'static str],
    ) -> Self {
        Self {
            id,
            output,
            labels,
            kind: HeadKind::MultiLabel,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UnifiedHeadOutput {
    pub class_name: String,
    pub confidence: f64,
    pub label_scores: Vec<LabelScore>,
}

#[derive(Debug, Clone)]
pub struct UnifiedModelOutput {
    pub heads: HashMap<String, UnifiedHeadOutput>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct UnifiedRawModelOutput {
    pub(crate) heads: HashMap<String, Vec<f32>>,
}

pub struct LazyUnifiedOnnxClassifier {
    dir: PathBuf,
    ttl: Duration,
    loaded: Option<UnifiedOnnxClassifier>,
    loaded_backend: Option<ExecutionBackend>,
    loaded_options: Option<OnnxRuntimeOptions>,
    last_used: Option<Instant>,
}

impl LazyUnifiedOnnxClassifier {
    pub fn from_dir(dir: impl AsRef<Path>) -> Result<Self, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();
        for path in [
            UNIFIED_ONNX_PATH,
            "onnx/quantization_manifest.json",
            "tokenizer_config.json",
            "config.json",
        ] {
            if !dir.join(path).is_file() {
                return Err(
                    format!("missing unified L3 asset: {}", dir.join(path).display()).into(),
                );
            }
        }
        if !dir.join("tokenizer.mmbpe").is_file() && !dir.join("tokenizer.json").is_file() {
            return Err(format!(
                "missing unified L3 tokenizer (neither tokenizer.mmbpe nor tokenizer.json found) in {}",
                dir.display()
            )
            .into());
        }
        validate_bundle_contract(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            ttl: l3_ttl(),
            loaded: None,
            loaded_backend: None,
            loaded_options: None,
            last_used: None,
        })
    }

    pub fn infer(
        &mut self,
        text: &str,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<UnifiedModelOutput, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend, options)?;
        let output = self
            .loaded
            .as_mut()
            .ok_or("unified L3 model is not loaded")?
            .infer(text)?;
        self.last_used = Some(Instant::now());
        Ok(output)
    }

    pub fn infer_batch(
        &mut self,
        texts: &[String],
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<Vec<UnifiedModelOutput>, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend, options)?;
        let outputs = self
            .loaded
            .as_mut()
            .ok_or("unified L3 model is not loaded")?
            .infer_batch(texts)?;
        self.last_used = Some(Instant::now());
        Ok(outputs)
    }

    pub(crate) fn infer_raw(
        &mut self,
        text: &str,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<UnifiedRawModelOutput, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend, options)?;
        let output = self
            .loaded
            .as_mut()
            .ok_or("unified L3 model is not loaded")?
            .infer_raw(text)?;
        self.last_used = Some(Instant::now());
        Ok(output)
    }

    pub(crate) fn infer_token_ids_raw(
        &mut self,
        token_ids: &[u32],
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<UnifiedRawModelOutput, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend, options)?;
        let output = self
            .loaded
            .as_mut()
            .ok_or("unified L3 model is not loaded")?
            .infer_token_ids_raw(token_ids)?;
        self.last_used = Some(Instant::now());
        Ok(output)
    }

    pub(crate) fn warmup_session(
        &mut self,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.ensure_loaded(backend, options)?;
        self.last_used = Some(Instant::now());
        Ok(())
    }

    pub(crate) fn decode_raw(
        &self,
        output: &UnifiedRawModelOutput,
    ) -> Result<UnifiedModelOutput, Box<dyn std::error::Error>> {
        decode_raw_output(output)
    }

    pub(crate) fn token_chunks(
        &mut self,
        text: &str,
        overlap_tokens: usize,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<Vec<TokenTextChunk>, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend, options)?;
        let chunks = self
            .loaded
            .as_ref()
            .ok_or("unified L3 model is not loaded")?
            .token_chunks(text, overlap_tokens)?;
        self.last_used = Some(Instant::now());
        Ok(chunks)
    }

    pub fn evict_expired(&mut self) {
        if self
            .last_used
            .is_some_and(|last_used| last_used.elapsed() >= self.ttl)
        {
            self.force_unload();
        }
    }

    pub(crate) fn force_unload(&mut self) {
        self.loaded = None;
        self.loaded_backend = None;
        self.loaded_options = None;
        self.last_used = None;
    }

    fn ensure_loaded(
        &mut self,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let options = options.normalized();
        if self.loaded.is_some()
            && self.loaded_backend == Some(backend)
            && self.loaded_options == Some(options)
        {
            return Ok(());
        }
        self.loaded = Some(UnifiedOnnxClassifier::from_dir(
            &self.dir, backend, options,
        )?);
        self.loaded_backend = Some(backend);
        self.loaded_options = Some(options);
        Ok(())
    }
}

fn validate_bundle_contract(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("config.json"))?)?;
    let labels = config
        .get("label_schema")
        .and_then(serde_json::Value::as_object)
        .ok_or("unified config.json is missing label_schema")?;
    for head in HEADS {
        let configured = labels
            .get(head.id)
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| format!("unified config is missing labels for head '{}'", head.id))?
            .iter()
            .map(|value| value.as_str().unwrap_or_default())
            .collect::<Vec<_>>();
        if configured != head.labels {
            return Err(format!(
                "unified labels for head '{}' are {configured:?}, expected {:?}",
                head.id, head.labels
            )
            .into());
        }
    }

    let quantization: serde_json::Value =
        serde_json::from_slice(&std::fs::read(dir.join("onnx/quantization_manifest.json"))?)?;
    let outputs = quantization
        .get("outputs")
        .and_then(serde_json::Value::as_object)
        .ok_or("unified quantization manifest is missing outputs")?;
    for head in HEADS {
        if outputs.get(head.id).and_then(serde_json::Value::as_str) != Some(head.output) {
            return Err(format!(
                "unified output binding for head '{}' does not match '{}'",
                head.id, head.output
            )
            .into());
        }
    }
    let variant_path = quantization
        .pointer("/variants/int8_int4_embeddings/path")
        .and_then(serde_json::Value::as_str);
    if variant_path != Some(UNIFIED_ONNX_PATH) {
        return Err(format!(
            "unified quantization manifest points at {variant_path:?}, expected {UNIFIED_ONNX_PATH}"
        )
        .into());
    }
    Ok(())
}

struct UnifiedOnnxClassifier {
    tokenizer: RuntimeTokenizer,
    session: Session,
}

impl UnifiedOnnxClassifier {
    fn infer(&mut self, text: &str) -> Result<UnifiedModelOutput, Box<dyn std::error::Error>> {
        self.infer_batch(&[text.to_string()])?
            .pop()
            .ok_or_else(|| "unified L3 returned no output".into())
    }

    fn from_dir(
        dir: &Path,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let tokenizer = RuntimeTokenizer::load(dir, "tokenizer.json")?;
        let (mut builder, _) = configured_session_builder(backend, Some(dir), options)?;
        let session = builder.commit_from_file(dir.join(UNIFIED_ONNX_PATH))?;
        let inputs = session_input_names(&session);
        if inputs != ["input_ids", "attention_mask"] {
            return Err(format!("unexpected unified L3 inputs: {inputs:?}").into());
        }
        let outputs = session_output_names(&session);
        for head in HEADS {
            if !outputs.contains(&head.output) {
                return Err(format!("unified L3 output '{}' is missing", head.output).into());
            }
        }
        Ok(Self { tokenizer, session })
    }

    fn infer_batch(
        &mut self,
        texts: &[String],
    ) -> Result<Vec<UnifiedModelOutput>, Box<dyn std::error::Error>> {
        self.infer_batch_raw(texts)?
            .iter()
            .map(decode_raw_output)
            .collect()
    }

    fn infer_raw(
        &mut self,
        text: &str,
    ) -> Result<UnifiedRawModelOutput, Box<dyn std::error::Error>> {
        self.infer_batch_raw(&[text.to_string()])?
            .pop()
            .ok_or_else(|| "unified L3 returned no raw output".into())
    }

    pub(crate) fn infer_token_ids_raw(
        &mut self,
        token_ids: &[u32],
    ) -> Result<UnifiedRawModelOutput, Box<dyn std::error::Error>> {
        self.infer_token_ids_batch_raw(&[token_ids])?
            .pop()
            .ok_or_else(|| "unified L3 returned no raw output".into())
    }

    pub(crate) fn infer_token_ids_batch_raw(
        &mut self,
        batch_token_ids: &[&[u32]],
    ) -> Result<Vec<UnifiedRawModelOutput>, Box<dyn std::error::Error>> {
        if batch_token_ids.is_empty() {
            return Ok(Vec::new());
        }
        let batch = batch_token_ids.len();
        let mut input_ids = Vec::with_capacity(batch * UNIFIED_MAX_LEN);
        let mut attention_mask = Vec::with_capacity(batch * UNIFIED_MAX_LEN);
        for tokens in batch_token_ids {
            let (ids, mask, _) = self
                .tokenizer
                .encode_inputs_from_token_ids(tokens, UNIFIED_MAX_LEN);
            input_ids.extend(ids);
            attention_mask.extend(mask);
        }
        let shape = [batch, UNIFIED_MAX_LEN];
        let outputs = self.session.run(ort::inputs![
            "input_ids" => Tensor::from_array((shape, input_ids))?,
            "attention_mask" => Tensor::from_array((shape, attention_mask))?,
        ])?;
        let mut results = (0..batch)
            .map(|_| UnifiedRawModelOutput {
                heads: HashMap::new(),
            })
            .collect::<Vec<_>>();
        for head in HEADS {
            let value = outputs
                .get(head.output)
                .ok_or_else(|| format!("unified L3 output '{}' is missing", head.output))?;
            let (shape, values) = value.try_extract_tensor::<f32>()?;
            let width = match head.kind {
                HeadKind::Binary => 1,
                _ => head.labels.len(),
            };
            if shape.as_ref() != [batch as i64, width as i64] || values.len() != batch * width {
                return Err(format!(
                    "unified L3 output '{}' has shape {shape:?}, expected [{batch}, {width}]",
                    head.output
                )
                .into());
            }
            for (index, row) in values.chunks(width).enumerate() {
                results[index]
                    .heads
                    .insert(head.id.to_string(), row.to_vec());
            }
        }
        Ok(results)
    }

    fn infer_batch_raw(
        &mut self,
        texts: &[String],
    ) -> Result<Vec<UnifiedRawModelOutput>, Box<dyn std::error::Error>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        let batch = texts.len();
        let mut input_ids = Vec::with_capacity(batch * UNIFIED_MAX_LEN);
        let mut attention_mask = Vec::with_capacity(batch * UNIFIED_MAX_LEN);
        for text in texts {
            let (ids, mask, _) = self.tokenizer.encode_inputs(text, UNIFIED_MAX_LEN)?;
            input_ids.extend(ids);
            attention_mask.extend(mask);
        }
        let shape = [batch, UNIFIED_MAX_LEN];
        let outputs = self.session.run(ort::inputs![
            "input_ids" => Tensor::from_array((shape, input_ids))?,
            "attention_mask" => Tensor::from_array((shape, attention_mask))?,
        ])?;
        let mut results = (0..batch)
            .map(|_| UnifiedRawModelOutput {
                heads: HashMap::new(),
            })
            .collect::<Vec<_>>();
        for head in HEADS {
            let value = outputs
                .get(head.output)
                .ok_or_else(|| format!("unified L3 output '{}' is missing", head.output))?;
            let (shape, values) = value.try_extract_tensor::<f32>()?;
            let width = match head.kind {
                HeadKind::Binary => 1,
                _ => head.labels.len(),
            };
            if shape.as_ref() != [batch as i64, width as i64] || values.len() != batch * width {
                return Err(format!(
                    "unified L3 output '{}' has shape {shape:?}, expected [{batch}, {width}]",
                    head.output
                )
                .into());
            }
            for (index, row) in values.chunks(width).enumerate() {
                results[index]
                    .heads
                    .insert(head.id.to_string(), row.to_vec());
            }
        }
        Ok(results)
    }

    fn token_chunks(
        &self,
        text: &str,
        overlap_tokens: usize,
    ) -> Result<Vec<TokenTextChunk>, Box<dyn std::error::Error>> {
        let special_tokens = self.tokenizer.token_count("", true)?;
        let content_tokens = UNIFIED_MAX_LEN.saturating_sub(special_tokens).max(1);
        token_chunks(text, content_tokens, overlap_tokens, |value| {
            self.tokenizer.token_count(value, false)
        })
    }
}

fn decode_raw_output(
    output: &UnifiedRawModelOutput,
) -> Result<UnifiedModelOutput, Box<dyn std::error::Error>> {
    let mut heads = HashMap::with_capacity(HEADS.len());
    for spec in HEADS {
        let logits = output
            .heads
            .get(spec.id)
            .ok_or_else(|| format!("cached unified output is missing head '{}'", spec.id))?;
        let expected = match spec.kind {
            HeadKind::Binary => 1,
            _ => spec.labels.len(),
        };
        if logits.len() != expected {
            return Err(format!(
                "cached unified head '{}' has {} logits, expected {expected}",
                spec.id,
                logits.len()
            )
            .into());
        }
        heads.insert(spec.id.to_string(), decode_head(*spec, logits));
    }
    Ok(UnifiedModelOutput { heads })
}

fn decode_head(spec: HeadSpec, logits: &[f32]) -> UnifiedHeadOutput {
    match spec.kind {
        HeadKind::Binary => {
            let positive = sigmoid(logits[0]);
            let (class_name, confidence) = if positive >= 0.5 {
                (spec.labels[1], positive)
            } else {
                (spec.labels[0], 1.0 - positive)
            };
            UnifiedHeadOutput {
                class_name: class_name.to_string(),
                confidence: f64::from(confidence),
                label_scores: vec![
                    label_score(spec.labels[0], 1.0 - positive, positive < 0.5),
                    label_score(spec.labels[1], positive, positive >= 0.5),
                ],
            }
        }
        HeadKind::Softmax => {
            let scores = softmax(logits);
            let selected = scores
                .iter()
                .enumerate()
                .max_by(|(_, left), (_, right)| left.total_cmp(right))
                .map(|(index, _)| index)
                .unwrap_or(0);
            UnifiedHeadOutput {
                class_name: spec.labels[selected].to_string(),
                confidence: f64::from(scores[selected]),
                label_scores: spec
                    .labels
                    .iter()
                    .enumerate()
                    .map(|(index, label)| label_score(label, scores[index], index == selected))
                    .collect(),
            }
        }
        HeadKind::MultiLabel => {
            let scores = logits
                .iter()
                .map(|value| sigmoid(*value))
                .collect::<Vec<_>>();
            let matched = spec
                .labels
                .iter()
                .zip(&scores)
                .filter(|(_, score)| **score >= 0.5)
                .map(|(label, _)| *label)
                .collect::<Vec<_>>();
            UnifiedHeadOutput {
                class_name: if matched.is_empty() {
                    "none".to_string()
                } else {
                    matched.join(",")
                },
                confidence: scores
                    .iter()
                    .copied()
                    .max_by(f32::total_cmp)
                    .map(f64::from)
                    .unwrap_or(0.0),
                label_scores: spec
                    .labels
                    .iter()
                    .zip(scores)
                    .map(|(label, score)| label_score(label, score, score >= 0.5))
                    .collect(),
            }
        }
    }
}

fn label_score(label: &str, confidence: f32, matched: bool) -> LabelScore {
    LabelScore {
        label: label.to_string(),
        confidence: f64::from(confidence),
        matched,
    }
}

fn sigmoid(value: f32) -> f32 {
    1.0 / (1.0 + (-value).exp())
}

fn softmax(values: &[f32]) -> Vec<f32> {
    let max = values.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let mut scores = values
        .iter()
        .map(|value| (*value - max).exp())
        .collect::<Vec<_>>();
    let sum = scores.iter().sum::<f32>();
    if sum > 0.0 {
        scores.iter_mut().for_each(|score| *score /= sum);
    }
    scores
}

#[cfg(ort_rc_10)]
fn session_input_names(session: &Session) -> Vec<&str> {
    session
        .inputs
        .iter()
        .map(|input| input.name.as_str())
        .collect()
}

#[cfg(not(ort_rc_10))]
fn session_input_names(session: &Session) -> Vec<&str> {
    session.inputs().iter().map(|input| input.name()).collect()
}

#[cfg(ort_rc_10)]
fn session_output_names(session: &Session) -> Vec<&str> {
    session
        .outputs
        .iter()
        .map(|output| output.name.as_str())
        .collect()
}

#[cfg(not(ort_rc_10))]
fn session_output_names(session: &Session) -> Vec<&str> {
    session
        .outputs()
        .iter()
        .map(|output| output.name())
        .collect()
}

#[cfg(feature = "test-util")]
#[doc(hidden)]
pub fn decode_head_logits_for_test(head_id: &str, logits: &[f32]) -> Option<UnifiedHeadOutput> {
    HEADS
        .iter()
        .find(|head| head.id == head_id)
        .copied()
        .map(|head| decode_head(head, logits))
}
