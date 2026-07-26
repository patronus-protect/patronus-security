// SPDX-License-Identifier: GPL-3.0-only
use crate::{EvaluationResult, ExecutionBackend, OnnxRuntimeOptions};
use half::f16;
#[cfg(feature = "onnx-coreml")]
#[allow(deprecated)]
use ort::execution_providers::{ArbitrarilyConfigurableExecutionProvider, CoreMLExecutionProvider};
#[allow(deprecated)]
use ort::{
    environment::GlobalThreadPoolOptions,
    execution_providers::{
        CUDAExecutionProvider, DirectMLExecutionProvider, ExecutionProviderDispatch,
        TensorRTExecutionProvider,
    },
    session::{
        builder::{GraphOptimizationLevel, SessionBuilder},
        Session,
    },
    value::Tensor,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokenizers::Tokenizer;

use super::mmbert_tokenizer::MmbertPairTokenizer;

const DEFAULT_MAX_LEN: usize = 256;
const DEFAULT_L3_TTL_SECS: u64 = 300;

#[derive(Clone)]
pub(crate) struct TokenTextChunk {
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) text: String,
}

pub fn warmup_runtime() -> bool {
    let Ok(threading) = GlobalThreadPoolOptions::default().with_spin_control(false) else {
        return false;
    };
    let initialized = ort::init().with_global_thread_pool(threading).commit();
    #[cfg(ort_rc_10)]
    {
        initialized.unwrap_or(false)
    }
    #[cfg(not(ort_rc_10))]
    {
        initialized
    }
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
        if !tokenizer_file.exists() {
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

    pub(crate) fn infer_raw(
        &mut self,
        text: &str,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<RawClassifierOutput, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend, options)?;
        let model = self.loaded.as_mut().ok_or("L3 ONNX model is not loaded")?;
        let result = model.infer_raw(text)?;
        self.last_used = Some(Instant::now());
        Ok(result)
    }

    pub(crate) fn decode_raw(&self, output: &RawClassifierOutput) -> EvaluationResult {
        result_from_logits(&output.logits, &self.class_names)
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
            loaded_backend: None,
            loaded_options: None,
            last_used: None,
        }
    }

    pub(crate) fn model_sha(&self) -> Option<&str> {
        self.model_sha.as_deref()
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
        let model = self.loaded.as_ref().ok_or("L3 ONNX model is not loaded")?;
        model.token_chunks(text, overlap_tokens)
    }

    pub fn model_name(&self) -> &str {
        self.loaded
            .as_ref()
            .map(|model| model.model_name())
            .unwrap_or(&self.model_name)
    }

    pub fn model_path(&self) -> Option<&Path> {
        self.loaded.as_ref().map(|model| model.model_path())
    }

    pub fn precision(&self) -> Option<&str> {
        self.loaded.as_ref().map(|model| model.precision())
    }

    pub fn execution_provider(&self) -> Option<&str> {
        self.loaded.as_ref().map(|model| model.execution_provider())
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded.is_some()
    }

    pub fn evict_expired(&mut self) {
        if self
            .last_used
            .is_some_and(|last_used| last_used.elapsed() > self.ttl)
        {
            self.loaded = None;
            self.loaded_backend = None;
            self.loaded_options = None;
            self.last_used = None;
        }
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

enum RuntimeTokenizer {
    HuggingFace(Tokenizer),
    MmbertPair(MmbertPairTokenizer),
}

pub(crate) fn l3_ttl() -> Duration {
    let secs = std::env::var("PATRONUS_L3_TTL_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_L3_TTL_SECS);
    Duration::from_secs(secs)
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
        if !tokenizer_file.exists() {
            return Ok(None);
        }

        let Some(model_path) = onnx_candidates
            .iter()
            .map(|candidate| dir.join(candidate))
            .find(|candidate| candidate.exists())
        else {
            return Ok(None);
        };

        let compact_tokenizer_file = tokenizer_file.with_extension("mmbpe");
        let tokenizer = if compact_tokenizer_file.is_file() {
            RuntimeTokenizer::MmbertPair(MmbertPairTokenizer::from_file(&compact_tokenizer_file)?)
        } else {
            RuntimeTokenizer::HuggingFace(
                Tokenizer::from_file(&tokenizer_file).map_err(|err| {
                    format!("failed to load tokenizer {:?}: {}", tokenizer_file, err)
                })?,
            )
        };
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

    fn infer_raw(&mut self, text: &str) -> Result<RawClassifierOutput, Box<dyn std::error::Error>> {
        self.infer_batch_raw(&[text.to_string()])?
            .pop()
            .ok_or_else(|| "ONNX batch returned no raw output".into())
    }

    fn infer_batch_raw(
        &mut self,
        texts: &[String],
    ) -> Result<Vec<RawClassifierOutput>, Box<dyn std::error::Error>> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let batch_size = texts.len();
        let mut input_ids_all = Vec::with_capacity(batch_size * self.max_len);
        let mut attention_mask_all = Vec::with_capacity(batch_size * self.max_len);
        let mut token_type_ids_all = Vec::with_capacity(batch_size * self.max_len);

        for text in texts {
            let (input_ids, attention_mask, token_type_ids) = self.encode_inputs(text)?;
            input_ids_all.extend(input_ids);
            attention_mask_all.extend(attention_mask);
            token_type_ids_all.extend(token_type_ids);
        }

        let shape = vec![batch_size, self.max_len];
        let mut inputs = Vec::with_capacity(self.input_names.len().max(1));
        if self.input_names.is_empty() {
            inputs.push((
                "input_ids".to_string(),
                Tensor::from_array((shape.clone(), input_ids_all.clone()))?,
            ));
        } else {
            for name in &self.input_names {
                let lower = name.to_lowercase();
                let values = if lower.contains("attention") {
                    attention_mask_all.clone()
                } else if lower.contains("token_type")
                    || lower.contains("token_type_ids")
                    || lower.contains("segment")
                {
                    token_type_ids_all.clone()
                } else {
                    input_ids_all.clone()
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

    fn token_chunks(
        &self,
        text: &str,
        overlap_tokens: usize,
    ) -> Result<Vec<TokenTextChunk>, Box<dyn std::error::Error>> {
        let special_tokens = self.token_count("", true)?;
        let content_tokens = self.max_len.saturating_sub(special_tokens).max(1);
        token_chunks(text, content_tokens, overlap_tokens, |value| {
            self.token_count(value, false)
        })
    }

    fn token_count(
        &self,
        text: &str,
        add_special_tokens: bool,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        match &self.tokenizer {
            RuntimeTokenizer::HuggingFace(tokenizer) => tokenizer
                .encode(text, add_special_tokens)
                .map(|encoding| encoding.len())
                .map_err(|err| format!("failed to tokenize input: {err}").into()),
            RuntimeTokenizer::MmbertPair(tokenizer) => {
                let with_special = tokenizer.encode(text).len();
                Ok(if add_special_tokens {
                    with_special
                } else {
                    with_special.saturating_sub(2)
                })
            }
        }
    }

    fn encode_inputs(
        &self,
        text: &str,
    ) -> Result<(Vec<i64>, Vec<i64>, Vec<i64>), Box<dyn std::error::Error>> {
        let (mut input_ids, mut attention_mask) = match &self.tokenizer {
            RuntimeTokenizer::HuggingFace(tokenizer) => {
                let encoding = tokenizer
                    .encode(text, true)
                    .map_err(|err| format!("failed to tokenize input: {}", err))?;
                (
                    encoding.get_ids().iter().map(|id| *id as i64).collect(),
                    encoding
                        .get_attention_mask()
                        .iter()
                        .map(|mask| *mask as i64)
                        .collect(),
                )
            }
            RuntimeTokenizer::MmbertPair(tokenizer) => {
                let input_ids = tokenizer
                    .encode(text)
                    .into_iter()
                    .map(i64::from)
                    .collect::<Vec<_>>();
                let attention_mask = vec![1; input_ids.len()];
                (input_ids, attention_mask)
            }
        };
        truncate_and_pad(&mut input_ids, self.max_len, 0);
        truncate_and_pad(&mut attention_mask, self.max_len, 0);
        let token_type_ids = vec![0_i64; self.max_len];
        Ok((input_ids, attention_mask, token_type_ids))
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

pub(crate) fn token_chunks<F>(
    text: &str,
    max_tokens: usize,
    overlap_tokens: usize,
    mut token_count: F,
) -> Result<Vec<TokenTextChunk>, Box<dyn std::error::Error>>
where
    F: FnMut(&str) -> Result<usize, Box<dyn std::error::Error>>,
{
    if text.is_empty() {
        return Ok(vec![TokenTextChunk {
            start_byte: 0,
            end_byte: 0,
            text: String::new(),
        }]);
    }
    let boundaries = text
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(text.len()))
        .collect::<Vec<_>>();
    let mut chunks = Vec::new();
    let mut start_index = 0usize;

    while start_index + 1 < boundaries.len() {
        let start = boundaries[start_index];
        let mut low = start_index + 1;
        let mut high = boundaries.len() - 1;
        let mut end_index = low;
        while low <= high {
            let middle = low + (high - low) / 2;
            if token_count(&text[start..boundaries[middle]])? <= max_tokens {
                end_index = middle;
                low = middle + 1;
            } else {
                high = middle.saturating_sub(1);
            }
        }
        let end = boundaries[end_index];
        chunks.push(TokenTextChunk {
            start_byte: start,
            end_byte: end,
            text: text[start..end].to_string(),
        });
        if end == text.len() {
            break;
        }

        let mut low = start_index + 1;
        let mut high = end_index;
        let mut next_start = end_index;
        while low <= high {
            let middle = low + (high - low) / 2;
            if token_count(&text[boundaries[middle]..end])? <= overlap_tokens {
                next_start = middle;
                high = middle.saturating_sub(1);
            } else {
                low = middle + 1;
            }
        }
        start_index = next_start.max(start_index + 1);
    }
    Ok(chunks)
}

pub(crate) fn configured_session_builder(
    backend: ExecutionBackend,
    model_dir: Option<&Path>,
    options: OnnxRuntimeOptions,
) -> Result<(SessionBuilder, String), Box<dyn std::error::Error>> {
    let mut builder =
        Session::builder()?.with_optimization_level(GraphOptimizationLevel::Level3)?;
    let options = options.normalized();
    if let Some(threads) = options.intra_threads {
        builder = builder.with_intra_threads(threads)?;
    }
    if let Some(threads) = options.inter_threads {
        builder = builder.with_inter_threads(threads)?;
    }
    if let Some(enabled) = options.spinning {
        builder = builder.with_intra_op_spinning(enabled)?;
        builder = builder.with_inter_op_spinning(enabled)?;
    }
    let plan = execution_provider_plan(backend, model_dir)?;
    if !plan.providers.is_empty() {
        builder = builder.with_execution_providers(plan.providers)?;
    }
    Ok((builder, plan.name))
}

struct ExecutionProviderPlan {
    name: String,
    providers: Vec<ExecutionProviderDispatch>,
}

fn execution_provider_plan(
    backend: ExecutionBackend,
    model_dir: Option<&Path>,
) -> Result<ExecutionProviderPlan, Box<dyn std::error::Error>> {
    let provider = default_accelerator_provider(backend);

    if provider == Some("cpu") || provider.is_none() && backend != ExecutionBackend::Gpu {
        return Ok(ExecutionProviderPlan {
            name: "cpu".to_string(),
            providers: Vec::new(),
        });
    }

    let Some(provider) = provider else {
        return Err(format!(
            "ONNX GPU backend is not available on this platform; enable and select one of: coreml, cuda, directml, tensorrt"
        )
        .into());
    };

    let strict = backend != ExecutionBackend::Auto;
    let mut dispatch = match provider {
        "cuda" => Some(CUDAExecutionProvider::default().build()),
        "coreml" => coreml_provider(model_dir),
        "directml" => Some(DirectMLExecutionProvider::default().build()),
        "tensorrt" => Some(TensorRTExecutionProvider::default().build()),
        _ => None,
    };

    let Some(provider_dispatch) = dispatch.take() else {
        return Err(format!("Unknown ONNX execution provider: {}", provider).into());
    };

    let provider_dispatch = if strict {
        provider_dispatch.error_on_failure()
    } else {
        provider_dispatch.fail_silently()
    };
    Ok(ExecutionProviderPlan {
        name: provider.to_string(),
        providers: vec![provider_dispatch],
    })
}

fn default_accelerator_provider(backend: ExecutionBackend) -> Option<&'static str> {
    match backend {
        ExecutionBackend::Cpu => Some("cpu"),
        ExecutionBackend::Auto if cfg!(target_os = "windows") => Some("directml"),
        ExecutionBackend::Auto if cfg!(target_vendor = "apple") => Some("cpu"),
        ExecutionBackend::Auto => Some("cuda"),
        ExecutionBackend::Gpu if cfg!(target_os = "windows") => Some("directml"),
        ExecutionBackend::Gpu if cfg!(target_vendor = "apple") => None,
        ExecutionBackend::Gpu => Some("cuda"),
        ExecutionBackend::CoreMl => Some("coreml"),
        ExecutionBackend::Cuda => Some("cuda"),
        ExecutionBackend::DirectMl => Some("directml"),
        ExecutionBackend::TensorRt => Some("tensorrt"),
    }
}

#[cfg(feature = "onnx-coreml")]
fn coreml_provider(model_dir: Option<&Path>) -> Option<ExecutionProviderDispatch> {
    let mut provider = CoreMLExecutionProvider::default()
        .with_arbitrary_config("MLComputeUnits", "CPUAndGPU")
        .with_low_precision_accumulation_on_gpu(true);
    if let Some(model_dir) = model_dir {
        let cache_dir = model_dir.join(".coreml-cache");
        let tmp_dir = model_dir.join(".coreml-tmp");
        let _ = std::fs::create_dir_all(&cache_dir);
        let _ = std::fs::create_dir_all(&tmp_dir);
        std::env::set_var("TMPDIR", &tmp_dir);
        provider = provider.with_model_cache_dir(cache_dir.to_string_lossy());
    }
    Some(provider.build())
}

#[cfg(not(feature = "onnx-coreml"))]
fn coreml_provider(_model_dir: Option<&Path>) -> Option<ExecutionProviderDispatch> {
    None
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

fn truncate_and_pad(values: &mut Vec<i64>, max_len: usize, pad: i64) {
    values.truncate(max_len);
    if values.len() < max_len {
        values.resize(max_len, pad);
    }
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
    use super::{token_chunks, truncate_and_pad};

    #[test]
    fn tokenizer_inputs_use_fixed_right_padding_and_truncation() {
        let mut short = vec![1, 2, 3];
        truncate_and_pad(&mut short, 5, 0);
        assert_eq!(short, [1, 2, 3, 0, 0]);

        let mut long = vec![1, 2, 3, 4, 5, 6];
        truncate_and_pad(&mut long, 4, 0);
        assert_eq!(long, [1, 2, 3, 4]);
    }

    #[test]
    fn token_chunks_respect_budget_overlap_and_utf8_boundaries() {
        let chunks = token_chunks("abcdefghijklm🦀nopqrstuvwxyz", 10, 3, |value| {
            Ok(value.chars().count())
        })
        .unwrap();

        assert!(chunks.iter().all(|chunk| chunk.text.chars().count() <= 10));
        assert!(chunks.windows(2).all(|pair| {
            let mut suffix = pair[0].text.chars().rev().take(3).collect::<Vec<_>>();
            suffix.reverse();
            suffix == pair[1].text.chars().take(3).collect::<Vec<_>>()
        }));
        assert!(chunks.iter().all(|chunk| {
            chunk.text == "abcdefghijklm🦀nopqrstuvwxyz"[chunk.start_byte..chunk.end_byte]
        }));
    }
}
