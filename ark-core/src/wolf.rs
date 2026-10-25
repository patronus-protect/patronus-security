//! Offline Wolf inference over existing assets, with optional integrity metadata.
use crate::{
    aggregation::SmoothMax, ml::mmbert_tokenizer::MmbertPairTokenizer, ScanControl, ScanError,
};
use ort::{
    session::{RunOptions, Session},
    value::Tensor,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

pub const CONTENT_TOKENS: usize = 254;
pub const SEQUENCE_TOKENS: usize = 256;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WolfPrecision {
    #[default]
    Auto,
    Fp16,
    Int8Int4,
}
impl WolfPrecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Fp16 => "fp16",
            Self::Int8Int4 => "int8_int4",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WolfConfig {
    pub bundle_dir: PathBuf,
    pub threshold: f64,
    #[serde(default)]
    pub precision: WolfPrecision,
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
/// Non-authoritative progress over the windows processed so far.
#[derive(Debug, Clone, Copy)]
pub struct WolfProgress {
    pub windows: u64,
    pub total_windows: u64,
    /// Absent before the first inference; otherwise the running SmoothMax logit.
    pub document_logit: Option<f64>,
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
        config.validate()?;
        let manifest = asset_manifest(config)?;
        let optional_integrity = !manifest.model.blake3.is_empty();
        let model = if optional_integrity {
            verified_file(&config.bundle_dir, &manifest.model)?
        } else {
            config.bundle_dir.join(&manifest.model.path)
        };
        let tokenizer_path = if optional_integrity {
            verified_file(&config.bundle_dir, &manifest.tokenizer)?
        } else {
            config.bundle_dir.join(&manifest.tokenizer.path)
        };
        let tokenizer = crate::ml::tokenizer_store::global_tokenizer_store()
            .load_mmbert(&tokenizer_path)
            .map_err(asset)?;
        // Preserve Ark's process-wide environment policy. Wolf alone owns a
        // session pool so its configured thread budget is honored even when
        // the host already initialized a global pool.
        crate::onnx::warmup_runtime();
        let (mut builder, execution_provider) = crate::onnx::configured_session_builder(
            config.backend,
            Some(&config.bundle_dir),
            config.runtime_options,
        )
        .map_err(inference)?;
        builder = builder.with_independent_thread_pool().map_err(inference)?;
        let session = builder.commit_from_file(&model).map_err(inference)?;
        let mut runner = Self {
            session,
            tokenizer,
            manifest,
            threshold: config.threshold,
            model_path: model,
            execution_provider,
        };
        // Always execute the actual backend before declaring the scanner ready.
        runner.infer(&[], &ScanControl::default())?;
        // Integrity/reference metadata is opt-in; ordinary Ark FP16 assets need none.
        runner.verify_reference_cases()?;
        Ok(runner)
    }
    fn verify_reference_cases(&mut self) -> Result<(), ScanError> {
        if self.manifest.content_tokens != CONTENT_TOKENS
            || self.manifest.sequence_tokens != SEQUENCE_TOKENS
        {
            // Older optional manifests still verify file integrity, but their
            // 256-content-token references are not evidence for this profile.
            log::debug!("Wolf legacy-profile references skipped; runtime uses 254 content tokens");
            return Ok(());
        }
        for case in self.manifest.parity_cases.clone() {
            if !case.expected_logit.is_finite() {
                return Err(ScanError::Asset("non-finite reference logit".into()));
            }
            if let Some(text) = &case.text {
                let mut actual_tokens = Vec::new();
                self.tokenizer
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
            let actual = self.infer(&case.token_ids, &ScanControl::default())?;
            if (actual - case.expected_logit).abs()
                > self.manifest.logit_tolerance
                    + self.manifest.relative_tolerance * case.expected_logit.abs()
                || (crate::aggregation::sigmoid(actual)
                    - crate::aggregation::sigmoid(case.expected_logit))
                .abs()
                    > self.manifest.probability_tolerance
            {
                return Err(ScanError::Asset(format!(
                    "Wolf parity mismatch: {actual} versus {}",
                    case.expected_logit
                )));
            }
        }
        for case in self.manifest.document_cases.clone() {
            let actual = self.scan(&case.text)?;
            if !case.expected_logit.is_finite()
                || actual.windows != case.windows
                || (actual.document_logit - case.expected_logit).abs()
                    > self.manifest.logit_tolerance
                        + self.manifest.relative_tolerance * case.expected_logit.abs()
                || (actual.attack_probability - crate::aggregation::sigmoid(case.expected_logit))
                    .abs()
                    > self.manifest.probability_tolerance
            {
                return Err(ScanError::Asset(
                    "Wolf document tokenization/pooling differs from reference".into(),
                ));
            }
        }
        Ok(())
    }
    pub fn execution_provider(&self) -> &str {
        &self.execution_provider
    }

    pub fn precision(&self) -> &str {
        &self.manifest.precision
    }

    pub fn model_path(&self) -> &Path {
        &self.model_path
    }

    pub fn scan(&mut self, text: &str) -> Result<WolfResult, ScanError> {
        self.scan_inner(text, &ScanControl::default(), None)
    }

    /// Scan with cooperative cancellation and termination of active ONNX runs.
    pub fn scan_with_control(
        &mut self,
        text: &str,
        control: &ScanControl,
    ) -> Result<WolfResult, ScanError> {
        self.scan_inner(text, control, None)
    }

    /// Emit a start update and one update per window without retaining chunk outputs.
    /// Counting tokens first provides exact totals and uses bounded tokenizer memory.
    pub fn scan_with_progress(
        &mut self,
        text: &str,
        progress: &mut dyn FnMut(WolfProgress),
    ) -> Result<WolfResult, ScanError> {
        self.scan_inner(text, &ScanControl::default(), Some(progress))
    }

    pub fn scan_with_progress_and_control(
        &mut self,
        text: &str,
        control: &ScanControl,
        progress: &mut dyn FnMut(WolfProgress),
    ) -> Result<WolfResult, ScanError> {
        self.scan_inner(text, control, Some(progress))
    }

    fn scan_inner(
        &mut self,
        text: &str,
        control: &ScanControl,
        mut progress: Option<&mut dyn FnMut(WolfProgress)>,
    ) -> Result<WolfResult, ScanError> {
        control.check()?;
        let mut total_windows = 0;
        if progress.is_some() {
            let mut tokens = 0_u64;
            let counted = self.tokenizer.visit_tokens(text, |_| {
                control.check().map_err(|e| e.to_string())?;
                tokens = tokens.checked_add(1).ok_or("too many Wolf tokens")?;
                Ok(())
            });
            control.check()?;
            counted.map_err(inference)?;
            total_windows = tokens.div_ceil(CONTENT_TOKENS as u64).max(1);
            if let Some(callback) = progress.as_mut() {
                callback(WolfProgress {
                    windows: 0,
                    total_windows,
                    document_logit: None,
                });
            }
        }
        let mut pool = SmoothMax::default();
        let tokenizer = Arc::clone(&self.tokenizer);
        let mut pending = Vec::with_capacity(CONTENT_TOKENS);
        let scanned = tokenizer.visit_tokens(text, |token| {
            control.check().map_err(|e| e.to_string())?;
            pending.push(token.id);
            if pending.len() == CONTENT_TOKENS {
                let logit = self.infer(&pending, control).map_err(|e| e.to_string())?;
                pool.push(logit).map_err(str::to_string)?;
                if let Some(callback) = progress.as_mut() {
                    callback(WolfProgress {
                        windows: pool.count(),
                        total_windows,
                        document_logit: pool.logit(),
                    });
                }
                pending.clear();
            }
            Ok(())
        });
        control.check()?;
        scanned.map_err(inference)?;
        if !pending.is_empty() || pool.count() == 0 {
            pool.push(self.infer(&pending, control)?)
                .map_err(inference)?;
            if let Some(callback) = progress.as_mut() {
                callback(WolfProgress {
                    windows: pool.count(),
                    total_windows,
                    document_logit: pool.logit(),
                });
            }
        }
        control.check()?;
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
    fn infer(&mut self, tokens: &[u32], control: &ScanControl) -> Result<f64, ScanError> {
        control.check()?;
        if tokens.len() > CONTENT_TOKENS {
            return Err(inference("oversized Wolf window"));
        }
        let width = if self.manifest.dynamic_sequence {
            tokens.len() + 2
        } else {
            SEQUENCE_TOKENS
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
        let options = Arc::new(RunOptions::new().map_err(inference)?);
        let abort_options = Arc::clone(&options);
        let _abort = control.register_abort(move || {
            let _ = abort_options.terminate();
        })?;
        control.check()?;
        let output = self.session.run_with_options(inputs, &options);
        control.check()?;
        let outputs = output.map_err(inference)?;
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

fn validate_manifest(manifest: &WolfManifest) -> Result<(), ScanError> {
    if manifest.schema_version != 1
        || manifest.model_id != "wolf-defender-small"
        || manifest.revision.is_empty()
        || !matches!(manifest.precision.as_str(), "fp16" | "int8_int4")
        || manifest.reference.is_empty()
        || !matches!(
            (manifest.content_tokens, manifest.sequence_tokens),
            (254, 256) | (256, 258)
        )
        || manifest.parity_cases.is_empty()
        || manifest.model.blake3.is_empty()
        || manifest.tokenizer.blake3.is_empty()
        || !manifest.logit_tolerance.is_finite()
        || !(0.0..=0.05).contains(&manifest.logit_tolerance)
        || !manifest.relative_tolerance.is_finite()
        || !(0.0..=0.005).contains(&manifest.relative_tolerance)
        || !manifest.probability_tolerance.is_finite()
        || !(0.0..=0.005).contains(&manifest.probability_tolerance)
    {
        return Err(asset("invalid optional Wolf integrity manifest"));
    }
    Ok(())
}

pub(crate) fn asset_manifest(config: &WolfConfig) -> Result<WolfManifest, ScanError> {
    asset_manifest_at(&config.bundle_dir, config.precision)
}

pub(crate) fn asset_manifest_at(
    bundle_dir: &Path,
    precision: WolfPrecision,
) -> Result<WolfManifest, ScanError> {
    let manifest_path = bundle_dir.join("wolf.manifest.json");
    let supplied_manifest = match fs::File::open(&manifest_path) {
        Ok(file) => {
            if file.metadata().map_err(asset)?.len() > 1024 * 1024 {
                return Err(asset("Wolf manifest exceeds 1 MiB"));
            }
            let manifest: WolfManifest = serde_json::from_reader(file).map_err(asset)?;
            validate_manifest(&manifest)?;
            Some(manifest)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(asset(error)),
    };
    existing_assets(bundle_dir, precision, supplied_manifest.as_ref())
}

pub(crate) fn model_paths(precision: WolfPrecision) -> &'static [&'static str] {
    match precision {
        WolfPrecision::Fp16 => &[
            crate::warmup::WOLF_FP16_FILE,
            "onnx/fp16/model_fp16.onnx",
            "model_fp16.onnx",
        ],
        WolfPrecision::Int8Int4 => &[
            crate::warmup::WOLF_QUANTIZED_FILE,
            "model_int4_embeddings_int8.onnx",
        ],
        WolfPrecision::Auto => &[],
    }
}

pub(crate) fn precision_order(
    requested: WolfPrecision,
    prefer_fp16: bool,
) -> &'static [WolfPrecision] {
    match requested {
        WolfPrecision::Fp16 => &[WolfPrecision::Fp16],
        WolfPrecision::Int8Int4 => &[WolfPrecision::Int8Int4],
        WolfPrecision::Auto if prefer_fp16 => &[WolfPrecision::Fp16, WolfPrecision::Int8Int4],
        WolfPrecision::Auto => &[WolfPrecision::Int8Int4, WolfPrecision::Fp16],
    }
}

/// Precision selection preserves the legacy environment preference and available assets.
fn existing_assets(
    base: &Path,
    requested: WolfPrecision,
    supplied: Option<&WolfManifest>,
) -> Result<WolfManifest, ScanError> {
    let prefer_fp16 = std::env::var("PATRONUS_L3_PRECISION")
        .is_ok_and(|value| value.eq_ignore_ascii_case("fp16"));
    let priorities = precision_order(requested, prefer_fp16);
    let mut selected = None;
    for &precision in priorities {
        if let Some(manifest) = supplied.filter(|m| m.precision == precision.as_str()) {
            // A supplied contract remains authoritative for its own precision:
            // missing or corrupt declared files must not silently bypass integrity.
            return Ok(manifest.clone());
        }
        let paths = model_paths(precision);
        if let Some(path) = paths.iter().find(|path| base.join(path).is_file()) {
            selected = Some((*path, precision));
            break;
        }
    }
    let (model, precision) =
        selected.ok_or_else(|| asset("requested Wolf ONNX precision is unavailable"))?;
    let tokenizer = ["tokenizer.mmbpe", "tokenizer.json"]
        .into_iter()
        .find(|name| base.join(name).is_file())
        .ok_or_else(|| asset("Wolf tokenizer is missing"))?;
    let config: serde_json::Value = match fs::File::open(base.join("config.json")) {
        Ok(file) => serde_json::from_reader(file).map_err(asset)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(error) => return Err(asset(error)),
    };
    let scalar = config["num_labels"].as_u64() == Some(1)
        || config["id2label"]
            .as_object()
            .is_some_and(|labels| labels.len() == 1);
    if !scalar {
        if let Some(labels) = config["id2label"].as_object() {
            if labels.get("0").and_then(|v| v.as_str()) != Some("benign")
                || labels.get("1").and_then(|v| v.as_str()) != Some("injection")
                || labels.len() != 2
            {
                return Err(asset("Wolf binary labels must be [benign, injection]"));
            }
        }
    }
    let revision = match fs::read_to_string(base.join(".patronus-revision")) {
        Ok(revision) => revision.trim().to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "local".to_owned(),
        Err(error) => return Err(asset(error)),
    };
    let pad_id = match config.get("pad_token_id").filter(|v| !v.is_null()) {
        Some(value) => value
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| asset("invalid Wolf pad_token_id"))?,
        None => 0,
    };
    Ok(WolfManifest {
        schema_version: 1,
        model_id: "wolf-defender-small".into(),
        revision,
        precision: precision.as_str().into(),
        model: BundleFile {
            path: model.into(),
            blake3: String::new(),
        },
        tokenizer: BundleFile {
            path: tokenizer.into(),
            blake3: String::new(),
        },
        output_name: "logits".into(),
        output: if scalar {
            LogitOutput::Scalar
        } else {
            LogitOutput::BinaryMargin
        },
        content_tokens: CONTENT_TOKENS,
        sequence_tokens: SEQUENCE_TOKENS,
        dynamic_sequence: true,
        pad_id,
        reference: String::new(),
        parity_cases: Vec::new(),
        document_cases: Vec::new(),
        logit_tolerance: 0.02,
        relative_tolerance: 0.005,
        probability_tolerance: 0.005,
    })
}

fn default_probability_tolerance() -> f64 {
    0.005
}

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
    pub(crate) fn validate(&self) -> Result<(), ScanError> {
        if !self.threshold.is_finite() || !(0.0..=1.0).contains(&self.threshold) {
            return Err(ScanError::Config("Wolf threshold must be in [0,1]".into()));
        }
        Ok(())
    }

    pub fn new(bundle_dir: impl Into<PathBuf>, threshold: f64) -> Self {
        Self {
            bundle_dir: bundle_dir.into(),
            threshold,
            precision: WolfPrecision::default(),
            backend: crate::ExecutionBackend::default(),
            runtime_options: crate::OnnxRuntimeOptions::default(),
        }
    }
}

#[cfg(test)]
mod published_model_tests {
    use super::*;

    /// Full raw-logit, tokenizer and multi-window references belong in tests,
    /// rather than being rerun on every production Scanner construction.
    #[test]
    #[ignore = "requires ARK_WOLF_BUNDLE pointing to the pinned local FP16 bundle"]
    fn published_fp16_matches_short_window_training_references() {
        let bundle = std::env::var_os("ARK_WOLF_BUNDLE").expect("set ARK_WOLF_BUNDLE");
        let mut config = WolfConfig::new(PathBuf::from(bundle), 0.8);
        config.precision = WolfPrecision::Fp16;
        let mut runner = WolfRunner::new(&config).unwrap();
        let mut reference: WolfManifest = serde_json::from_str(include_str!(
            "../tests/fixtures/wolf_published_reference.json"
        ))
        .unwrap();
        // The reference revision identifies test data, not a runtime revision requirement.
        verified_file(
            &PathBuf::from(std::env::var_os("ARK_WOLF_BUNDLE").unwrap()),
            &reference.model,
        )
        .unwrap();
        verified_file(
            &PathBuf::from(std::env::var_os("ARK_WOLF_BUNDLE").unwrap()),
            &reference.tokenizer,
        )
        .unwrap();
        // These archived references used 256 content tokens. Only the short
        // dynamic-window logits are profile-independent; long-document values
        // must be regenerated independently for the 254-content profile.
        reference
            .parity_cases
            .retain(|case| case.token_ids.len() <= CONTENT_TOKENS);
        reference.document_cases.clear();
        reference.content_tokens = CONTENT_TOKENS;
        reference.sequence_tokens = SEQUENCE_TOKENS;
        reference.dynamic_sequence = true;
        runner.manifest = reference;
        runner.verify_reference_cases().unwrap();
    }
    /// Independent 254-content export/tokenization oracle. This is not the
    /// archived PyTorch 256-content document contract.
    #[test]
    #[ignore = "requires ARK_WOLF_BUNDLE with local FP16 export and tokenizer.json"]
    fn published_fp16_254_profile_matches_independent_hf_ort_oracle() {
        let bundle =
            PathBuf::from(std::env::var_os("ARK_WOLF_BUNDLE").expect("set ARK_WOLF_BUNDLE"));
        let manifest = existing_assets(&bundle, WolfPrecision::Fp16, None).unwrap();
        let model = bundle.join(&manifest.model.path);
        let benign = "Ordinary meeting notes about project planning. ".repeat(50);
        let row: serde_json::Value = serde_json::from_str(
            include_str!("../tests/fixtures/injection.jsonl")
                .lines()
                .next()
                .unwrap(),
        )
        .unwrap();
        let embedded = format!("{} {} {}", benign, row["text"].as_str().unwrap(), benign);
        let texts = [benign, embedded];
        // The oracle owns its own HF tokenization and fixed-width tensors, and
        // explicitly drops its session before creating the Core runner.
        let references = {
            let mut tokenizer =
                tokenizers::Tokenizer::from_file(bundle.join("tokenizer.json")).unwrap();
            tokenizer.with_truncation(None).unwrap();
            tokenizer.with_padding(None);
            let bos = i64::from(tokenizer.token_to_id("<bos>").unwrap());
            let eos = i64::from(tokenizer.token_to_id("<eos>").unwrap());
            let pad = i64::from(tokenizer.token_to_id("<pad>").unwrap());
            let (mut builder, _) = crate::onnx::configured_session_builder(
                crate::ExecutionBackend::Cpu,
                Some(&bundle),
                crate::OnnxRuntimeOptions::default(),
            )
            .unwrap();
            builder = builder.with_independent_thread_pool().unwrap();
            let mut session = builder.commit_from_file(&model).unwrap();
            texts
                .iter()
                .map(|text| {
                    let tokens = tokenizer
                        .encode(text.as_str(), false)
                        .unwrap()
                        .get_ids()
                        .to_vec();
                    assert!(tokens.len() > 254);
                    let mut logits = Vec::new();
                    for chunk in tokens.chunks(254) {
                        let mut ids = vec![bos];
                        ids.extend(chunk.iter().map(|&token| i64::from(token)));
                        ids.push(eos);
                        let mut mask = vec![1_i64; ids.len()];
                        ids.resize(256, pad);
                        mask.resize(256, 0);
                        let inputs = vec![
                            (
                                "input_ids",
                                Tensor::from_array(([1_usize, 256], ids)).unwrap(),
                            ),
                            (
                                "attention_mask",
                                Tensor::from_array(([1_usize, 256], mask)).unwrap(),
                            ),
                        ];
                        let outputs = session.run(inputs).unwrap();
                        let value = outputs.get("logits").unwrap();
                        let values: Vec<f64> =
                            if let Ok((_, values)) = value.try_extract_tensor::<f32>() {
                                values.iter().map(|&value| f64::from(value)).collect()
                            } else {
                                value
                                    .try_extract_tensor::<half::f16>()
                                    .unwrap()
                                    .1
                                    .iter()
                                    .map(|value| f64::from(value.to_f32()))
                                    .collect()
                            };
                        assert_eq!(values.len(), 2);
                        logits.push(values[1] - values[0]);
                    }
                    let max = logits.iter().copied().fold(f64::NEG_INFINITY, f64::max);
                    let pooled = max
                        + 0.1
                            * ((logits
                                .iter()
                                .map(|value| ((value - max) / 0.1).exp())
                                .sum::<f64>())
                            .ln()
                                - (logits.len() as f64).ln());
                    (tokens, logits.len() as u64, pooled)
                })
                .collect::<Vec<_>>()
        };
        let mut config = WolfConfig::new(&bundle, 0.8);
        config.precision = WolfPrecision::Fp16;
        config.backend = crate::ExecutionBackend::Cpu;
        let mut runner = WolfRunner::new(&config).unwrap();
        for (text, (tokens, windows, reference)) in texts.iter().zip(references) {
            let mut actual_tokens = Vec::new();
            runner
                .tokenizer
                .visit_tokens(text, |token| {
                    actual_tokens.push(token.id);
                    Ok(())
                })
                .unwrap();
            assert_eq!(actual_tokens, tokens);
            let actual = runner.scan(text).unwrap();
            assert_eq!(actual.windows, windows);
            assert!(
                (actual.document_logit - reference).abs() <= 0.02 + 0.005 * reference.abs(),
                "core={} independent={reference}",
                actual.document_logit
            );
            let probability = 1.0 / (1.0 + (-reference).exp());
            assert!((actual.attack_probability - probability).abs() <= 0.005);
        }
    }

    #[test]
    #[ignore = "requires ARK_WOLF_BUNDLE with local Wolf FP16 and tokenizer.json"]
    fn existing_fp16_and_json_tokenizer_run_without_migration() {
        let source =
            PathBuf::from(std::env::var_os("ARK_WOLF_BUNDLE").expect("set ARK_WOLF_BUNDLE"));
        let dir = std::env::temp_dir().join(format!("ark-existing-wolf-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        let relative_model = "onnx/onnx_fp16/model_fp16.onnx";
        fs::create_dir_all(dir.join("onnx/onnx_fp16")).unwrap();
        fs::hard_link(source.join(relative_model), dir.join(relative_model)).unwrap();
        fs::hard_link(source.join("tokenizer.json"), dir.join("tokenizer.json")).unwrap();
        fs::write(
            dir.join("config.json"),
            r#"{"id2label":{"0":"benign","1":"injection"},"pad_token_id":0}"#,
        )
        .unwrap();
        fs::write(
            dir.join(".patronus-revision"),
            "142fadc5474163d4c483cb761d5a6b02e3aa1741",
        )
        .unwrap();
        let mut runner = WolfRunner::new(&WolfConfig::new(&dir, 0.8)).unwrap();
        let result = runner
            .scan("Hello, please summarize the meeting agenda.")
            .unwrap();
        assert_eq!(result.revision, "142fadc5474163d4c483cb761d5a6b02e3aa1741");
        assert!(!result.matched);
        let expected: f64 = -19.3598575592041;
        assert!((result.document_logit - expected).abs() < 0.02 + 0.005 * expected.abs());
        assert!(
            runner
                .scan(&"Ordinary meeting notes. ".repeat(400))
                .unwrap()
                .windows
                > 1
        );
        assert!(!dir.join("wolf.manifest.json").exists());
        assert!(!dir.join("tokenizer.mmbpe").exists());
        assert!(!dir.join("tokenizer.mmbpe.meta.json").exists());
        assert_eq!(
            fs::read_to_string(dir.join(".patronus-revision")).unwrap(),
            "142fadc5474163d4c483cb761d5a6b02e3aa1741"
        );
    }
}

#[cfg(test)]
mod progress_tests {
    use super::*;

    #[test]
    fn progress_counts_windows_and_preserves_final_smooth_max() {
        let dir = std::env::temp_dir().join(format!("ark-wolf-progress-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        fs::write(
            dir.join("model_fp16.onnx"),
            include_bytes!("../tests/fixtures/wolf_synthetic_fp16.onnx"),
        )
        .unwrap();
        fs::write(
            dir.join("tokenizer.mmbpe"),
            include_bytes!("../tests/fixtures/tokenizer.mmbpe"),
        )
        .unwrap();
        fs::write(dir.join("config.json"), r#"{"num_labels":1}"#).unwrap();
        let mut runner = WolfRunner::new(&WolfConfig::new(&dir, 0.8)).unwrap();
        for (tokens, windows) in [(0, 1), (254, 1), (255, 2), (509, 3)] {
            let text = " a".repeat(tokens);
            let expected = runner.scan(&text).unwrap();
            let mut updates = Vec::new();
            let actual = runner
                .scan_with_progress(&text, &mut |update| updates.push(update))
                .unwrap();
            assert_eq!(updates.len(), windows + 1);
            assert!(updates[0].document_logit.is_none());
            for (index, update) in updates.iter().enumerate() {
                assert_eq!(update.windows, index as u64);
                assert_eq!(update.total_windows, windows as u64);
            }
            assert_eq!(actual.document_logit, expected.document_logit);
            assert_eq!(actual.attack_probability, expected.attack_probability);
            assert_eq!(
                updates.last().unwrap().document_logit,
                Some(actual.document_logit)
            );
        }
    }
}

#[cfg(test)]
mod resource_tests {
    use super::*;
    #[test]
    fn precision_contract_matches_legacy_preference_and_explicit_choices() {
        assert_eq!(
            precision_order(WolfPrecision::Auto, false),
            &[WolfPrecision::Int8Int4, WolfPrecision::Fp16]
        );
        assert_eq!(
            precision_order(WolfPrecision::Auto, true),
            &[WolfPrecision::Fp16, WolfPrecision::Int8Int4]
        );
        assert_eq!(
            precision_order(WolfPrecision::Fp16, false),
            &[WolfPrecision::Fp16]
        );
        assert_eq!(
            precision_order(WolfPrecision::Int8Int4, true),
            &[WolfPrecision::Int8Int4]
        );
        assert_eq!(
            serde_json::from_str::<WolfPrecision>("\"int8_int4\"").unwrap(),
            WolfPrecision::Int8Int4
        );
        assert!(serde_json::from_str::<WolfPrecision>("\"unknown\"").is_err());
    }

    #[test]
    fn existing_quantized_asset_selection_does_not_require_manifest_migration() {
        let dir = std::env::temp_dir().join(format!("ark-wolf-selection-{}", std::process::id()));
        fs::create_dir_all(dir.join("onnx/int8_int4_embeddings")).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        fs::write(
            dir.join("onnx/int8_int4_embeddings/model.onnx"),
            b"selection-only fixture",
        )
        .unwrap();
        fs::write(dir.join("tokenizer.mmbpe"), b"selection-only fixture").unwrap();
        let selected = existing_assets(&dir, WolfPrecision::Int8Int4, None).unwrap();
        assert_eq!(selected.model.path, "onnx/int8_int4_embeddings/model.onnx");
        assert_eq!(selected.precision, "int8_int4");
        assert_eq!(selected.content_tokens, 254);
        assert_eq!(selected.sequence_tokens, 256);
        assert!(existing_assets(&dir, WolfPrecision::Fp16, None).is_err());
        assert_eq!(
            existing_assets(&dir, WolfPrecision::Auto, None)
                .unwrap()
                .precision,
            "int8_int4"
        );
    }

    #[test]
    fn wolf_and_legacy_tokenizer_loaders_share_the_same_arc() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let legacy = crate::ml::tokenizer::RuntimeTokenizer::load(&dir).unwrap();
        let wolf = crate::ml::tokenizer_store::global_tokenizer_store()
            .load_mmbert(dir.join("tokenizer.mmbpe"))
            .unwrap();
        assert!(Arc::ptr_eq(&legacy.0, &wolf));
    }
}

#[cfg(test)]
mod termination_tests {
    use super::*;

    #[test]
    fn registered_deadline_interrupts_an_active_ort_run() {
        let (mut builder, _) = crate::onnx::configured_session_builder(
            crate::ExecutionBackend::Cpu,
            None,
            crate::OnnxRuntimeOptions::default(),
        )
        .unwrap();
        builder = builder.with_independent_thread_pool().unwrap();
        let mut session = builder
            .commit_from_memory(include_bytes!("../tests/fixtures/wolf_cancellable.onnx"))
            .unwrap();
        let options = Arc::new(RunOptions::new().unwrap());
        let abort_options = Arc::clone(&options);
        let control = ScanControl::with_timeout(std::time::Duration::from_millis(30)).unwrap();
        let _registration = control
            .register_abort(move || {
                let _ = abort_options.terminate();
            })
            .unwrap();
        let input = Tensor::from_array(([1_usize, 3], vec![1_i64, 400, 2])).unwrap();
        let error = match session.run_with_options(vec![("input_ids", input)], &options) {
            Err(error) => error,
            Ok(_) => panic!("ORT must acknowledge the terminate signal, not finish its loop"),
        };
        assert!(
            error.to_string().to_lowercase().contains("terminate"),
            "{error}"
        );
        assert!(matches!(control.check(), Err(ScanError::DeadlineExceeded)));
        let fresh = RunOptions::new().unwrap();
        let empty = Tensor::from_array(([1_usize, 2], vec![1_i64, 2])).unwrap();
        assert!(session
            .run_with_options(vec![("input_ids", empty)], &fresh)
            .is_ok());
    }
}
