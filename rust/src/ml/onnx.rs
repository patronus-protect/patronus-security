use crate::{EvaluationResult, ExecutionBackend};
use half::f16;
use ort::{
    ep::{self, ExecutionProviderDispatch},
    session::{
        builder::{GraphOptimizationLevel, SessionBuilder},
        Session,
    },
    value::Tensor,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use tokenizers::Tokenizer;

const DEFAULT_MAX_LEN: usize = 512;
const DEFAULT_L3_TTL_SECS: u64 = 300;

pub fn warmup_runtime() -> bool {
    ort::init().commit()
}

pub struct LazyOnnxTextClassifier {
    dir: PathBuf,
    class_names: Vec<String>,
    model_name: String,
    onnx_candidates: Vec<String>,
    tokenizer_path: String,
    max_len: usize,
    ttl: Duration,
    loaded: Option<OnnxTextClassifier>,
    loaded_backend: Option<ExecutionBackend>,
    last_used: Option<Instant>,
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
            onnx_candidates: onnx_candidates
                .iter()
                .map(|candidate| candidate.to_string())
                .collect(),
            tokenizer_path: tokenizer_path.to_string(),
            max_len,
            ttl: l3_ttl(),
            loaded: None,
            loaded_backend: None,
            last_used: None,
        }))
    }

    pub fn infer(
        &mut self,
        text: &str,
        backend: ExecutionBackend,
    ) -> Result<EvaluationResult, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend)?;
        let model = self.loaded.as_mut().ok_or("L3 ONNX model is not loaded")?;
        let result = model.infer(text)?;
        self.last_used = Some(Instant::now());
        Ok(result)
    }

    pub fn infer_batch(
        &mut self,
        texts: &[String],
        backend: ExecutionBackend,
    ) -> Result<Vec<EvaluationResult>, Box<dyn std::error::Error>> {
        self.evict_expired();
        self.ensure_loaded(backend)?;
        let model = self.loaded.as_mut().ok_or("L3 ONNX model is not loaded")?;
        let results = model.infer_batch(texts)?;
        self.last_used = Some(Instant::now());
        Ok(results)
    }

    pub fn metadata_clone(&self) -> Self {
        Self {
            dir: self.dir.clone(),
            class_names: self.class_names.clone(),
            model_name: self.model_name.clone(),
            onnx_candidates: self.onnx_candidates.clone(),
            tokenizer_path: self.tokenizer_path.clone(),
            max_len: self.max_len,
            ttl: self.ttl,
            loaded: None,
            loaded_backend: None,
            last_used: None,
        }
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
            self.last_used = None;
        }
    }

    fn ensure_loaded(
        &mut self,
        backend: ExecutionBackend,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.loaded.is_some() && self.loaded_backend == Some(backend) {
            return Ok(());
        }
        self.loaded = None;
        self.loaded_backend = None;

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
        )?
        else {
            return Err("L3 ONNX assets are no longer available".into());
        };
        self.loaded = Some(model);
        self.loaded_backend = Some(backend);
        Ok(())
    }
}

pub struct OnnxTextClassifier {
    tokenizer: Tokenizer,
    session: Session,
    input_names: Vec<String>,
    class_names: Vec<String>,
    max_len: usize,
    model_name: String,
    model_path: PathBuf,
    precision: String,
    execution_provider: String,
}

fn l3_ttl() -> Duration {
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

        let tokenizer = Tokenizer::from_file(&tokenizer_file)
            .map_err(|err| format!("failed to load tokenizer {:?}: {}", tokenizer_file, err))?;
        let (mut session_builder, execution_provider) =
            configured_session_builder(backend, Some(dir))?;
        let session = session_builder.commit_from_file(&model_path)?;
        let input_names = session
            .inputs()
            .iter()
            .map(|input| input.name().to_string())
            .collect();

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
        let class_names = self.class_names.clone();
        Ok(logits
            .iter()
            .map(|row| result_from_logits(row, &class_names))
            .collect())
    }

    fn encode_inputs(
        &self,
        text: &str,
    ) -> Result<(Vec<i64>, Vec<i64>, Vec<i64>), Box<dyn std::error::Error>> {
        let encoding = self
            .tokenizer
            .encode(text, true)
            .map_err(|err| format!("failed to tokenize input: {}", err))?;

        let mut input_ids: Vec<i64> = encoding.get_ids().iter().map(|id| *id as i64).collect();
        let mut attention_mask: Vec<i64> = encoding
            .get_attention_mask()
            .iter()
            .map(|mask| *mask as i64)
            .collect();
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

fn configured_session_builder(
    backend: ExecutionBackend,
    model_dir: Option<&Path>,
) -> Result<(SessionBuilder, String), Box<dyn std::error::Error>> {
    let mut builder = Session::builder()?.with_optimization_level(GraphOptimizationLevel::All)?;
    if let Some(threads) = env_usize("PATRONUS_ONNX_INTRA_THREADS") {
        builder = builder.with_intra_threads(threads)?;
    }
    if let Some(threads) = env_usize("PATRONUS_ONNX_INTER_THREADS") {
        builder = builder.with_inter_threads(threads)?;
    }
    if let Some(enabled) = env_bool("PATRONUS_ONNX_SPINNING") {
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
    let requested = std::env::var("PATRONUS_ONNX_EXECUTION_PROVIDER")
        .ok()
        .map(|value| value.to_lowercase().replace('-', "_"));
    let provider = requested
        .as_deref()
        .or_else(|| default_accelerator_provider(backend));

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

    let strict = backend != ExecutionBackend::Auto || requested.is_some();
    let mut dispatch = match provider {
        "cuda" => Some(ep::CUDA::default().build()),
        "coreml" => coreml_provider(model_dir),
        "directml" => Some(ep::DirectML::default().build()),
        "tensorrt" => Some(ep::TensorRT::default().build()),
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
    let mut provider = ep::CoreML::default()
        .with_compute_units(ep::coreml::ComputeUnits::CPUAndGPU)
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

fn env_usize(name: &str) -> Option<usize> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn env_bool(name: &str) -> Option<bool> {
    std::env::var(name)
        .ok()
        .and_then(|value| match value.to_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => Some(true),
            "0" | "false" | "no" | "off" => Some(false),
            _ => None,
        })
}

fn precision_for_path(path: &Path) -> String {
    let text = path.to_string_lossy().to_lowercase();
    if text.contains("fp16") {
        "fp16".to_string()
    } else {
        "full".to_string()
    }
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
