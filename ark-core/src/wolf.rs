//! Offline Wolf inference. Bundle hashes and reference logits are checked before use.
use crate::{aggregation::SmoothMax, ml::mmbert_tokenizer::MmbertPairTokenizer, ScanError};
use ort::{session::Session, value::Tensor};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WolfConfig {
    pub bundle_dir: PathBuf,
    pub threshold: f64,
    #[serde(default)]
    pub backend: crate::ExecutionBackend,
    #[serde(default)]
    pub runtime_options: crate::OnnxRuntimeOptions,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    pub path: String,
    pub blake3: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogitOutput {
    Scalar,
    BinaryMargin,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParityCase {
    #[serde(default)]
    pub text: Option<String>,
    pub token_ids: Vec<u32>,
    pub expected_logit: f64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DocumentCase {
    pub text: String,
    pub expected_logit: f64,
    pub windows: u64,
}
/// An export contract produced alongside a training-verified FP16 export.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WolfManifest {
    pub schema_version: u32,
    pub model_id: String,
    pub revision: String,
    pub precision: String,
    pub model: BundleFile,
    pub tokenizer: BundleFile,
    pub output_name: String,
    pub output: LogitOutput,
    pub content_tokens: usize,
    pub sequence_tokens: usize,
    #[serde(default)]
    pub dynamic_sequence: bool,
    pub pad_id: u32,
    pub reference: String,
    pub parity_cases: Vec<ParityCase>,
    #[serde(default)]
    pub document_cases: Vec<DocumentCase>,
    pub logit_tolerance: f64,
    #[serde(default)]
    pub relative_tolerance: f64,
    #[serde(default = "default_probability_tolerance")]
    pub probability_tolerance: f64,
}
#[derive(Debug, Clone, Serialize)]
pub struct WolfResult {
    pub document_logit: f64,
    pub attack_probability: f64,
    pub threshold: f64,
    pub matched: bool,
    pub windows: u64,
    pub model_id: String,
    pub revision: String,
    pub precision: String,
}
pub struct WolfRunner {
    session: Session,
    tokenizer: Arc<MmbertPairTokenizer>,
    manifest: WolfManifest,
    threshold: f64,
    model_path: PathBuf,
    execution_provider: String,
}
impl WolfRunner {
    pub fn new(config: &WolfConfig) -> Result<Self, ScanError> {
        if !config.threshold.is_finite() || !(0.0..=1.0).contains(&config.threshold) {
            return Err(ScanError::Config("Wolf threshold must be in [0,1]".into()));
        }
        let manifest_path = config.bundle_dir.join("wolf.manifest.json");
        let file = fs::File::open(&manifest_path).map_err(asset)?;
        if file.metadata().map_err(asset)?.len() > 1024 * 1024 {
            return Err(ScanError::Asset("Wolf manifest exceeds 1 MiB".into()));
        }
        let manifest: WolfManifest = serde_json::from_reader(file).map_err(asset)?;
        if manifest.schema_version != 1
            || manifest.model_id != "wolf-defender-small"
            || manifest.revision.is_empty()
            || manifest.precision != "fp16"
            || manifest.reference.is_empty()
            || manifest.content_tokens != 256
            || manifest.sequence_tokens != 258
            || manifest.parity_cases.is_empty()
            || !manifest.logit_tolerance.is_finite()
            || !(0.0..=0.05).contains(&manifest.logit_tolerance)
            || !manifest.relative_tolerance.is_finite()
            || !(0.0..=0.005).contains(&manifest.relative_tolerance)
            || !manifest.probability_tolerance.is_finite()
            || !(0.0..=0.005).contains(&manifest.probability_tolerance)
        {
            return Err(ScanError::Asset("invalid Wolf Single FP16 export contract (256 content + 2 special tokens required)".into()));
        }
        let model = verified_file(&config.bundle_dir, &manifest.model)?;
        let tokenizer = MmbertPairTokenizer::from_file(&verified_file(
            &config.bundle_dir,
            &manifest.tokenizer,
        )?)
        .map_err(asset)?;
        let (mut builder, execution_provider) = crate::onnx::configured_session_builder(
            config.backend,
            Some(&config.bundle_dir),
            config.runtime_options,
        )
        .map_err(inference)?;
        let session = builder.commit_from_file(&model).map_err(inference)?;
        let mut runner = Self {
            session,
            tokenizer: Arc::new(tokenizer),
            manifest,
            threshold: config.threshold,
            model_path: model,
            execution_provider,
        };
        // Running the reference cases is also the real backend warmup; no filename-based readiness.
        for case in runner.manifest.parity_cases.clone() {
            if !case.expected_logit.is_finite() {
                return Err(ScanError::Asset("non-finite reference logit".into()));
            }
            if let Some(text) = &case.text {
                let mut actual_tokens = Vec::new();
                runner
                    .tokenizer
                    .visit_tokens(text, |token| {
                        actual_tokens.push(token.id);
                        Ok(())
                    })
                    .map_err(asset)?;
                if actual_tokens != case.token_ids {
                    return Err(ScanError::Asset(
                        "compact tokenizer differs from reference text token IDs".into(),
                    ));
                }
            }
            let actual = runner.infer(&case.token_ids)?;
            if (actual - case.expected_logit).abs()
                > runner.manifest.logit_tolerance
                    + runner.manifest.relative_tolerance * case.expected_logit.abs()
                || (crate::aggregation::sigmoid(actual)
                    - crate::aggregation::sigmoid(case.expected_logit))
                .abs()
                    > runner.manifest.probability_tolerance
            {
                return Err(ScanError::Asset(format!(
                    "FP16 parity mismatch: {actual} versus {}",
                    case.expected_logit
                )));
            }
        }
        for case in runner.manifest.document_cases.clone() {
            let actual = runner.scan(&case.text)?;
            if !case.expected_logit.is_finite()
                || actual.windows != case.windows
                || (actual.document_logit - case.expected_logit).abs()
                    > runner.manifest.logit_tolerance
                        + runner.manifest.relative_tolerance * case.expected_logit.abs()
                || (actual.attack_probability - crate::aggregation::sigmoid(case.expected_logit))
                    .abs()
                    > runner.manifest.probability_tolerance
            {
                return Err(ScanError::Asset(
                    "Wolf document tokenization/pooling differs from reference".into(),
                ));
            }
        }
        Ok(runner)
    }
    pub fn execution_provider(&self) -> &str {
        &self.execution_provider
    }

    pub fn model_path(&self) -> &Path {
        &self.model_path
    }

    pub fn scan(&mut self, text: &str) -> Result<WolfResult, ScanError> {
        let mut pool = SmoothMax::default();
        let tokenizer = Arc::clone(&self.tokenizer);
        let mut pending = Vec::with_capacity(self.manifest.content_tokens);
        tokenizer
            .visit_tokens(text, |token| {
                pending.push(token.id);
                if pending.len() == self.manifest.content_tokens {
                    let logit = self.infer(&pending).map_err(|e| e.to_string())?;
                    pool.push(logit).map_err(str::to_string)?;
                    pending.clear();
                }
                Ok(())
            })
            .map_err(inference)?;
        if !pending.is_empty() || pool.count() == 0 {
            pool.push(self.infer(&pending)?).map_err(inference)?;
        }
        let document_logit = pool.logit().ok_or_else(|| inference("no Wolf windows"))?;
        let probability = pool
            .probability()
            .ok_or_else(|| inference("no Wolf probability"))?;
        Ok(WolfResult {
            document_logit,
            attack_probability: probability,
            threshold: self.threshold,
            matched: probability >= self.threshold,
            windows: pool.count(),
            model_id: self.manifest.model_id.clone(),
            revision: self.manifest.revision.clone(),
            precision: self.manifest.precision.clone(),
        })
    }
    fn infer(&mut self, tokens: &[u32]) -> Result<f64, ScanError> {
        if tokens.len() > self.manifest.content_tokens {
            return Err(inference("oversized Wolf window"));
        }
        let width = if self.manifest.dynamic_sequence {
            tokens.len() + 2
        } else {
            self.manifest.sequence_tokens
        };
        let mut ids = Vec::with_capacity(width);
        ids.push(i64::from(self.tokenizer.bos()));
        ids.extend(tokens.iter().map(|&t| i64::from(t)));
        ids.push(i64::from(self.tokenizer.eos()));
        let mut mask = vec![1_i64; ids.len()];
        ids.resize(width, i64::from(self.manifest.pad_id));
        mask.resize(width, 0);
        let mut inputs = Vec::new();
        for name in session_input_names(&self.session) {
            let values = match name.as_str() {
                "input_ids" => ids.clone(),
                "attention_mask" => mask.clone(),
                "token_type_ids" => vec![0_i64; width],
                _ => return Err(inference(format!("unsupported Wolf input {name}"))),
            };
            inputs.push((
                name.to_string(),
                Tensor::from_array(([1, width], values)).map_err(inference)?,
            ));
        }
        let outputs = self.session.run(inputs).map_err(inference)?;
        let value = outputs
            .get(&self.manifest.output_name)
            .ok_or_else(|| inference("missing Wolf output"))?;
        let values: Vec<f64> = if let Ok((_, data)) = value.try_extract_tensor::<f32>() {
            data.iter().map(|&v| f64::from(v)).collect()
        } else if let Ok((_, data)) = value.try_extract_tensor::<half::f16>() {
            data.iter().map(|v| f64::from(v.to_f32())).collect()
        } else {
            return Err(inference("Wolf output must be f32/f16 logits"));
        };
        let logit = match self.manifest.output {
            LogitOutput::Scalar if values.len() == 1 => values[0],
            LogitOutput::BinaryMargin if values.len() == 2 => values[1] - values[0],
            _ => return Err(inference("Wolf output shape does not match manifest")),
        };
        if !logit.is_finite() {
            return Err(inference("non-finite Wolf logit"));
        }
        Ok(logit)
    }
}
fn asset(error: impl std::fmt::Display) -> ScanError {
    ScanError::Asset(error.to_string())
}
fn inference(error: impl std::fmt::Display) -> ScanError {
    ScanError::Inference(error.to_string())
}
fn verified_file(base: &Path, file: &BundleFile) -> Result<PathBuf, ScanError> {
    let root = base.canonicalize().map_err(asset)?;
    let path = root.join(&file.path).canonicalize().map_err(asset)?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err(asset("bundle file must be inside bundle directory"));
    }
    let mut reader = fs::File::open(&path).map_err(asset)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let size = reader.read(&mut buffer).map_err(asset)?;
        if size == 0 {
            break;
        }
        hasher.update(&buffer[..size]);
    }
    if hasher.finalize().to_hex().as_str() != file.blake3 {
        return Err(asset(format!("checksum mismatch: {}", file.path)));
    }
    Ok(path)
}

fn default_probability_tolerance() -> f64 {
    0.005
}

/// Public artifact revision verified against PyTorch binary logits.
pub const PUBLISHED_REVISION: &str = "a6b3bb2697cb69cca88f866e45c0f33f1d2793bc";
/// Checksummed contract for the published CPU FP16 artifact and its compact tokenizer.
pub const PUBLISHED_MANIFEST: &str = include_str!("../assets/wolf-small-single-fp16.json");

#[cfg(not(ort_rc_10))]
fn session_input_names(session: &Session) -> Vec<String> {
    session
        .inputs()
        .iter()
        .map(|i| i.name().to_string())
        .collect()
}
#[cfg(ort_rc_10)]
fn session_input_names(session: &Session) -> Vec<String> {
    session.inputs.iter().map(|i| i.name.clone()).collect()
}

impl WolfConfig {
    pub fn new(bundle_dir: impl Into<PathBuf>, threshold: f64) -> Self {
        Self {
            bundle_dir: bundle_dir.into(),
            threshold,
            backend: crate::ExecutionBackend::default(),
            runtime_options: crate::OnnxRuntimeOptions::default(),
        }
    }
}
