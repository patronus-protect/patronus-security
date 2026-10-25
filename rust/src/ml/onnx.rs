// SPDX-License-Identifier: GPL-3.0-only
use crate::{EvaluationResult, ExecutionBackend, OnnxRuntimeOptions};
use half::f16;
use ort::{session::Session, value::Tensor};
pub use patronus_ark_core::onnx::{
    active_execution_providers, available_execution_providers, configured_session_builder,
    warmup_runtime,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::tokenizer::{RuntimeTokenizer, MODEL_TOKENS};

const DEFAULT_MAX_LEN: usize = MODEL_TOKENS;
const DEFAULT_L3_TTL_SECS: u64 = 300;
#[derive(Clone, Default)]
pub(crate) struct TokenTextChunk {
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) text: String,
    pub(crate) token_ids: Vec<u32>,
    pub(crate) tokenizer_family: String,
}

pub struct LazyOnnxTextClassifier {
    dir: PathBuf,
    class_names: Vec<String>,
    model_name: String,
    model_sha: Option<String>,
    onnx_candidates: Vec<String>,
    tokenizer_path: String,
    max_len: usize,
    ttl: Duration,
    loaded: Option<OnnxTextClassifier>,
    wolf_runner: Option<patronus_ark_core::wolf::WolfRunner>,
    loaded_backend: Option<ExecutionBackend>,
    loaded_options: Option<OnnxRuntimeOptions>,
    last_used: Option<Instant>,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RawClassifierOutput {
    pub(crate) logits: Vec<f32>,
}

impl LazyOnnxTextClassifier {
    pub fn from_dir<P: AsRef<Path>>(
        dir: P,
        class_names: Vec<String>,
        model_name: impl Into<String>,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        Self::from_dir_with_paths(
            dir,
            class_names,
            model_name,
            &["onnx/model_fp16.onnx", "onnx/model.onnx"],
            "tokenizer.json",
            DEFAULT_MAX_LEN,
        )
    }

    pub fn from_dir_with_paths<P: AsRef<Path>>(
        dir: P,
        class_names: Vec<String>,
        model_name: impl Into<String>,
        onnx_candidates: &[&str],
        tokenizer_path: &str,
        max_len: usize,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        Self::from_dir_with_paths_and_sha(
            dir,
            class_names,
            model_name,
            onnx_candidates,
            tokenizer_path,
            max_len,
            None,
        )
    }

    pub(crate) fn from_dir_with_paths_at_sha<P: AsRef<Path>>(
        dir: P,
        class_names: Vec<String>,
        model_name: impl Into<String>,
        onnx_candidates: &[&str],
        tokenizer_path: &str,
        max_len: usize,
        model_sha: &str,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        Self::from_dir_with_paths_and_sha(
            dir,
            class_names,
            model_name,
            onnx_candidates,
            tokenizer_path,
            max_len,
            Some(model_sha.to_string()),
        )
    }

    fn from_dir_with_paths_and_sha<P: AsRef<Path>>(
        dir: P,
        class_names: Vec<String>,
        model_name: impl Into<String>,
        onnx_candidates: &[&str],
        tokenizer_path: &str,
        max_len: usize,
        model_sha: Option<String>,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();
        let tokenizer_file = dir.join(tokenizer_path);
        let compact_tokenizer_file = tokenizer_file.with_extension("mmbpe");
        if !tokenizer_file.exists() && !compact_tokenizer_file.exists() {
            return Ok(None);
        }

        let has_model = onnx_candidates
            .iter()
            .map(|candidate| dir.join(candidate))
            .any(|candidate| candidate.exists());
        if !has_model {
            return Ok(None);
        }

        Ok(Some(LazyOnnxTextClassifier {
            dir: dir.to_path_buf(),
            class_names,
            model_name: model_name.into(),
            model_sha,
            onnx_candidates: onnx_candidates
                .iter()
                .map(|candidate| candidate.to_string())
                .collect(),
            tokenizer_path: tokenizer_path.to_string(),
            max_len,
            ttl: l3_ttl(),
            loaded: None,
            wolf_runner: None,
            loaded_backend: None,
            loaded_options: None,
            last_used: None,
        }))
    }

    pub fn infer(
        &mut self,
        text: &str,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<EvaluationResult, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend, options)?;
        let model = self.loaded.as_mut().ok_or("L3 ONNX model is not loaded")?;
        let result = model.infer(text)?;
        self.last_used = Some(Instant::now());
        Ok(result)
    }

    pub fn infer_batch(
        &mut self,
        texts: &[String],
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<Vec<EvaluationResult>, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend, options)?;
        let model = self.loaded.as_mut().ok_or("L3 ONNX model is not loaded")?;
        let results = model.infer_batch(texts)?;
        self.last_used = Some(Instant::now());
        Ok(results)
    }

    pub(crate) fn infer_token_ids_raw(
        &mut self,
        token_ids: &[u32],
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<RawClassifierOutput, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend, options)?;
        let model = self.loaded.as_mut().ok_or("L3 ONNX model is not loaded")?;
        let result = model.infer_token_ids_raw(token_ids)?;
        self.last_used = Some(Instant::now());
        Ok(result)
    }

    /// Dedicated Wolf shares the synchronous Core runner and its verified export contract.
    pub(crate) fn infer_wolf_document(
        &mut self,
        text: &str,
        threshold: f64,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<patronus_ark_core::wolf::WolfResult, Box<dyn std::error::Error>> {
        let options = options.normalized();
        if self.wolf_runner.is_none()
            || self.loaded_backend != Some(backend)
            || self.loaded_options != Some(options)
        {
            self.wolf_runner = Some(patronus_ark_core::wolf::WolfRunner::new(
                &patronus_ark_core::wolf::WolfConfig {
                    bundle_dir: self.dir.clone(),
                    threshold,
                    backend,
                    runtime_options: options,
                },
            )?);
            self.loaded_backend = Some(backend);
            self.loaded_options = Some(options);
        }
        self.last_used = Some(Instant::now());
        let mut result = self
            .wolf_runner
            .as_mut()
            .ok_or("Wolf runner not loaded")?
            .scan(text)?;
        if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
            return Err("invalid Wolf threshold".into());
        }
        result.threshold = threshold;
        result.matched = result.attack_probability >= threshold;
        Ok(result)
    }

    pub(crate) fn warmup_session(
        &mut self,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.model_name == "wolf-defender-small" {
            self.infer_wolf_document("", 0.5, backend, options)?;
        } else {
            self.ensure_loaded(backend, options)?;
        }
        self.last_used = Some(Instant::now());
        Ok(())
    }

    pub(crate) fn decode_raw(&self, output: &RawClassifierOutput) -> EvaluationResult {
        result_from_logits(&output.logits, &self.class_names)
    }

    pub(crate) fn decode_probabilities(&self, output: &RawClassifierOutput) -> Vec<f32> {
        softmax(&output.logits)
    }

    pub fn metadata_clone(&self) -> Self {
        Self {
            dir: self.dir.clone(),
            class_names: self.class_names.clone(),
            model_name: self.model_name.clone(),
            model_sha: self.model_sha.clone(),
            onnx_candidates: self.onnx_candidates.clone(),
            tokenizer_path: self.tokenizer_path.clone(),
            max_len: self.max_len,
            ttl: self.ttl,
            loaded: None,
            wolf_runner: None,
            loaded_backend: None,
            loaded_options: None,
            last_used: None,
        }
    }

    pub(crate) fn model_sha(&self) -> Option<&str> {
        self.model_sha.as_deref()
    }

    pub fn model_name(&self) -> &str {
        self.loaded
            .as_ref()
            .map(|model| model.model_name())
            .unwrap_or(&self.model_name)
    }

    pub fn model_path(&self) -> Option<&Path> {
        self.wolf_runner
            .as_ref()
            .map(|model| model.model_path())
            .or_else(|| self.loaded.as_ref().map(|model| model.model_path()))
    }

    pub fn precision(&self) -> Option<&str> {
        self.wolf_runner
            .as_ref()
            .map(|_| "fp16")
            .or_else(|| self.loaded.as_ref().map(|model| model.precision()))
    }

    pub fn execution_provider(&self) -> Option<&str> {
        self.wolf_runner
            .as_ref()
            .map(|runner| runner.execution_provider())
            .or_else(|| self.loaded.as_ref().map(|model| model.execution_provider()))
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded.is_some() || self.wolf_runner.is_some()
    }

    pub fn evict_expired(&mut self) {
        if self
            .last_used
            .is_some_and(|last_used| last_used.elapsed() > self.ttl)
        {
            self.force_unload();
        }
    }

    pub(crate) fn force_unload(&mut self) {
        self.wolf_runner = None;
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
        self.loaded = None;
        self.loaded_backend = None;
        self.loaded_options = None;

        let candidates: Vec<&str> = self
            .onnx_candidates
            .iter()
            .map(|candidate| candidate.as_str())
            .collect();
        let Some(model) = OnnxTextClassifier::from_dir_with_paths(
            &self.dir,
            self.class_names.clone(),
            self.model_name.clone(),
            &candidates,
            &self.tokenizer_path,
            self.max_len,
            backend,
            options,
        )?
        else {
            return Err("L3 ONNX assets are no longer available".into());
        };
        self.loaded = Some(model);
        self.loaded_backend = Some(backend);
        self.loaded_options = Some(options);
        Ok(())
    }
}

pub struct OnnxTextClassifier {
    tokenizer: RuntimeTokenizer,
    session: Session,
    input_names: Vec<String>,
    class_names: Vec<String>,
    max_len: usize,
    model_name: String,
    model_path: PathBuf,
    precision: String,
    execution_provider: String,
}

pub(crate) fn l3_ttl() -> Duration {
    l3_ttl_from_value(std::env::var("PATRONUS_L3_TTL_SECS").ok().as_deref())
}

fn l3_ttl_from_value(value: Option<&str>) -> Duration {
    match value {
        // API deployments with sufficient RAM keep sessions resident.  A
        // Duration::MAX TTL is preferable to a magic large finite value: the
        // eviction comparison can never become true during process lifetime.
        Some("-1") => Duration::MAX,
        Some(value) => value
            .parse::<u64>()
            .map(Duration::from_secs)
            .unwrap_or_else(|_| Duration::from_secs(DEFAULT_L3_TTL_SECS)),
        None => Duration::from_secs(DEFAULT_L3_TTL_SECS),
    }
}

impl OnnxTextClassifier {
    pub fn from_dir<P: AsRef<Path>>(
        dir: P,
        class_names: Vec<String>,
        model_name: impl Into<String>,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        Self::from_dir_with_paths(
            dir,
            class_names,
            model_name,
            &["onnx/model_fp16.onnx", "onnx/model.onnx"],
            "tokenizer.json",
            DEFAULT_MAX_LEN,
            ExecutionBackend::Auto,
            OnnxRuntimeOptions::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn from_dir_with_paths<P: AsRef<Path>>(
        dir: P,
        class_names: Vec<String>,
        model_name: impl Into<String>,
        onnx_candidates: &[&str],
        tokenizer_path: &str,
        max_len: usize,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<Option<Self>, Box<dyn std::error::Error>> {
        let dir = dir.as_ref();
        let tokenizer_file = dir.join(tokenizer_path);
        let compact_tokenizer_file = tokenizer_file.with_extension("mmbpe");
        if !tokenizer_file.exists() && !compact_tokenizer_file.exists() {
            return Ok(None);
        }

        let Some(model_path) = onnx_candidates
            .iter()
            .map(|candidate| dir.join(candidate))
            .find(|candidate| candidate.exists())
        else {
            return Ok(None);
        };

        if max_len != MODEL_TOKENS {
            return Err("classifier sequence length must be 256".into());
        }
        let tokenizer_dir = dir.join(tokenizer_path);
        let tokenizer =
            RuntimeTokenizer::load(tokenizer_dir.parent().ok_or("invalid tokenizer path")?)?;
        let (mut session_builder, execution_provider) =
            configured_session_builder(backend, Some(dir), options)?;
        let session = session_builder.commit_from_file(&model_path)?;
        let input_names = session_input_names(&session);

        Ok(Some(OnnxTextClassifier {
            tokenizer,
            session,
            input_names,
            class_names,
            max_len,
            model_name: model_name.into(),
            precision: precision_for_path(&model_path),
            model_path,
            execution_provider,
        }))
    }

    pub fn infer(&mut self, text: &str) -> Result<EvaluationResult, Box<dyn std::error::Error>> {
        let mut results = self.infer_batch(&[text.to_string()])?;
        results.pop().ok_or("ONNX batch returned no result".into())
    }

    pub fn infer_batch(
        &mut self,
        texts: &[String],
    ) -> Result<Vec<EvaluationResult>, Box<dyn std::error::Error>> {
        Ok(self
            .infer_batch_raw(texts)?
            .iter()
            .map(|output| result_from_logits(&output.logits, &self.class_names))
            .collect())
    }

    pub(crate) fn infer_token_ids_raw(
        &mut self,
        token_ids: &[u32],
    ) -> Result<RawClassifierOutput, Box<dyn std::error::Error>> {
        self.infer_token_ids_batch_raw(&[token_ids])?
            .pop()
            .ok_or_else(|| "ONNX batch returned no raw output".into())
    }

    pub(crate) fn infer_token_ids_batch_raw(
        &mut self,
        token_ids_batch: &[&[u32]],
    ) -> Result<Vec<RawClassifierOutput>, Box<dyn std::error::Error>> {
        if token_ids_batch.is_empty() {
            return Ok(Vec::new());
        }

        let batch_size = token_ids_batch.len();
        let kinds = self
            .input_names
            .iter()
            .map(|name| {
                let lower = name.to_lowercase();
                if lower.contains("attention") {
                    1
                } else if lower.contains("token_type") || lower.contains("segment") {
                    2
                } else {
                    0
                }
            })
            .collect::<Vec<_>>();
        let (ids, mask, types) =
            self.tokenizer
                .batch_inputs(token_ids_batch, kinds.contains(&1), kinds.contains(&2))?;
        let mut buffers = [ids, mask, types];

        let shape = vec![batch_size, self.max_len];
        let mut inputs = Vec::with_capacity(self.input_names.len().max(1));
        if self.input_names.is_empty() {
            inputs.push((
                "input_ids".to_string(),
                Tensor::from_array((shape.clone(), std::mem::take(&mut buffers[0])))?,
            ));
        } else {
            let mut remaining = [0usize; 3];
            for &kind in &kinds {
                remaining[kind] += 1;
            }
            for (name, kind) in self.input_names.iter().zip(kinds) {
                remaining[kind] -= 1;
                let values = if remaining[kind] == 0 {
                    std::mem::take(&mut buffers[kind])
                } else {
                    buffers[kind].clone()
                };
                inputs.push((name.clone(), Tensor::from_array((shape.clone(), values))?));
            }
        }

        let logits = {
            let outputs = self.session.run(inputs)?;
            first_logits_batch(&outputs, self.class_names.len(), batch_size)?
        };
        Ok(logits
            .into_iter()
            .map(|logits| RawClassifierOutput { logits })
            .collect())
    }

    fn infer_batch_raw(
        &mut self,
        texts: &[String],
    ) -> Result<Vec<RawClassifierOutput>, Box<dyn std::error::Error>> {
        let ids = texts
            .iter()
            .map(|text| self.tokenizer.single_chunk_ids(text))
            .collect::<Result<Vec<_>, _>>()?;
        let slices = ids.iter().map(Vec::as_slice).collect::<Vec<_>>();
        self.infer_token_ids_batch_raw(&slices)
    }

    pub fn model_name(&self) -> &str {
        &self.model_name
    }

    pub fn model_path(&self) -> &Path {
        &self.model_path
    }

    pub fn precision(&self) -> &str {
        &self.precision
    }

    pub fn execution_provider(&self) -> &str {
        &self.execution_provider
    }
}

fn precision_for_path(path: &Path) -> String {
    let text = path.to_string_lossy().to_lowercase();
    if text.contains("fp16") {
        "fp16".to_string()
    } else {
        "full".to_string()
    }
}

#[cfg(ort_rc_10)]
fn session_input_names(session: &Session) -> Vec<String> {
    session
        .inputs
        .iter()
        .map(|input| input.name.clone())
        .collect()
}

#[cfg(not(ort_rc_10))]
fn session_input_names(session: &Session) -> Vec<String> {
    session
        .inputs()
        .iter()
        .map(|input| input.name().to_string())
        .collect()
}

fn first_logits_batch<'run>(
    outputs: &ort::session::SessionOutputs<'run>,
    expected_classes: usize,
    batch_size: usize,
) -> Result<Vec<Vec<f32>>, Box<dyn std::error::Error>> {
    let min_classes = expected_classes.max(2);
    let required = min_classes * batch_size;
    for (_name, value) in outputs.iter() {
        if let Ok((_shape, data)) = value.try_extract_tensor::<f32>() {
            if data.len() >= required {
                return Ok(rows_from_logits(
                    data.iter().copied(),
                    expected_classes,
                    batch_size,
                ));
            }
        }
        if let Ok((_shape, data)) = value.try_extract_tensor::<f16>() {
            if data.len() >= required {
                return Ok(rows_from_logits(
                    data.iter().map(|value| value.to_f32()),
                    expected_classes,
                    batch_size,
                ));
            }
        }
    }
    Err("ONNX model did not return f32/f16 logits".into())
}

fn rows_from_logits<I>(values: I, expected_classes: usize, batch_size: usize) -> Vec<Vec<f32>>
where
    I: IntoIterator<Item = f32>,
{
    let flat: Vec<f32> = values
        .into_iter()
        .take(batch_size * expected_classes)
        .collect();
    flat.chunks(expected_classes)
        .take(batch_size)
        .map(|chunk| chunk.to_vec())
        .collect()
}

fn result_from_logits(logits: &[f32], class_names: &[String]) -> EvaluationResult {
    let probabilities = softmax(logits);
    let (best_idx, confidence) = probabilities
        .iter()
        .copied()
        .enumerate()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .unwrap_or((0, 0.0));
    let class_name = class_names
        .get(best_idx)
        .cloned()
        .unwrap_or_else(|| best_idx.to_string());

    EvaluationResult {
        class_name,
        confidence: confidence as f64,
        level: "L3".to_string(),
    }
}

fn softmax(logits: &[f32]) -> Vec<f32> {
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let exps: Vec<f32> = logits.iter().map(|logit| (*logit - max).exp()).collect();
    let sum: f32 = exps.iter().sum();
    if sum == 0.0 {
        return vec![0.0; logits.len()];
    }
    exps.into_iter().map(|value| value / sum).collect()
}

#[cfg(test)]
mod tests {
    use super::{l3_ttl_from_value, LazyOnnxTextClassifier};
    use crate::{ExecutionBackend, OnnxRuntimeOptions};
    use std::time::Duration;

    #[test]
    fn l3_ttl_supports_resident_sessions_and_preserves_fallbacks() {
        assert_eq!(l3_ttl_from_value(Some("-1")), Duration::MAX);
        assert_eq!(l3_ttl_from_value(Some("900")), Duration::from_secs(900));
        assert_eq!(l3_ttl_from_value(Some("0")), Duration::ZERO);
        assert_eq!(l3_ttl_from_value(Some("invalid")), Duration::from_secs(300));
        assert_eq!(l3_ttl_from_value(None), Duration::from_secs(300));
    }

    #[test]
    fn warmup_session_loads_registered_lazy_assets() {
        let dir = fake_lazy_onnx_dir("warmup-session-loads-registered-lazy-assets");
        let mut classifier = LazyOnnxTextClassifier::from_dir_with_paths(
            &dir,
            vec!["benign".to_string(), "attack".to_string()],
            "fake-l3",
            &["onnx/model.onnx"],
            "tokenizer.json",
            16,
        )
        .unwrap()
        .expect("fake lazy metadata should be accepted");

        assert!(classifier
            .warmup_session(ExecutionBackend::Cpu, OnnxRuntimeOptions::default())
            .is_err());
        assert!(!classifier.is_loaded());

        let _ = std::fs::remove_dir_all(dir);
    }

    fn fake_lazy_onnx_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("patronus-ark-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("onnx")).unwrap();
        std::fs::write(dir.join("tokenizer.json"), "{}").unwrap();
        std::fs::write(dir.join("onnx/model.onnx"), []).unwrap();
        dir
    }
}
