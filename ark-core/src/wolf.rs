//! Offline Wolf inference over existing assets, with optional integrity metadata.
use crate::{
    aggregation::SmoothMax, ml::mmbert_tokenizer::MmbertPairTokenizer, ScanControl, ScanError,
};
use ort::session::Session;
mod assets;
mod inference;
#[cfg(test)]
mod tests;
mod windows;
use crate::WolfExecutionOptions;
use assets::{asset_manifest, verified_file};
pub(crate) use assets::{asset_manifest_at, model_paths, precision_order};
use serde::{Deserialize, Serialize};
use std::{
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
    options: WolfExecutionOptions,
    fixed_width: Option<usize>,
}
impl WolfRunner {
    pub fn new(config: &WolfConfig) -> Result<Self, ScanError> {
        Self::new_with_options(config, WolfExecutionOptions::default())
    }

    /// Construct and warm a runner; execution sizes are validated against the local export.
    pub fn new_with_options(
        config: &WolfConfig,
        options: WolfExecutionOptions,
    ) -> Result<Self, ScanError> {
        options.validate()?;
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
        let fixed_width =
            inference::validate_session(&session, &config.bundle_dir, options, &manifest)?;
        let mut runner = Self {
            session,
            tokenizer,
            manifest,
            threshold: config.threshold,
            model_path: model,
            execution_provider,
            options,
            fixed_width,
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
            log::debug!("Wolf references skipped for a different execution profile");
            return Ok(());
        }
        for case in self.manifest.parity_cases.clone() {
            if case.token_ids.len() > self.options.content_tokens() {
                continue;
            }
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
        // Document references also depend on the window/overlap profile. Short
        // raw-logit/tokenizer references above remain valid for custom batching.
        if self.options != WolfExecutionOptions::default() {
            return Ok(());
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
    /// Change the decision threshold without loading or warming another session.
    pub fn set_threshold(&mut self, threshold: f64) -> Result<(), ScanError> {
        validate_threshold(threshold)?;
        self.threshold = threshold;
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
            total_windows = windows::count(tokens, self.options);
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
        let mut windows = windows::Windows::new(self.options);
        let mut batch = Vec::new();
        let scanned = tokenizer.visit_tokens(text, |token| {
            control.check().map_err(|e| e.to_string())?;
            if let Some(window) = windows.push(token.id) {
                batch.push(window);
                if batch.len() == self.options.batch_size {
                    self.consume_batch(&batch, control, &mut pool, total_windows, &mut progress)
                        .map_err(|e| e.to_string())?;
                    batch.clear();
                }
            }
            Ok(())
        });
        control.check()?;
        scanned.map_err(inference)?;
        if let Some(window) = windows.finish() {
            batch.push(window);
        }
        if !batch.is_empty() {
            self.consume_batch(&batch, control, &mut pool, total_windows, &mut progress)?;
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
    /// The effective window and batch configuration of this reusable session.
    pub fn execution_options(&self) -> WolfExecutionOptions {
        self.options
    }

    fn consume_batch(
        &mut self,
        batch: &[Vec<u32>],
        control: &ScanControl,
        pool: &mut SmoothMax,
        total_windows: u64,
        progress: &mut Option<&mut dyn FnMut(WolfProgress)>,
    ) -> Result<(), ScanError> {
        for logit in self.infer_batch(batch, control)? {
            control.check()?;
            pool.push(logit).map_err(inference)?;
            if let Some(callback) = progress.as_mut() {
                callback(WolfProgress {
                    windows: pool.count(),
                    total_windows,
                    document_logit: pool.logit(),
                });
            }
        }
        Ok(())
    }

    fn infer(&mut self, tokens: &[u32], control: &ScanControl) -> Result<f64, ScanError> {
        Ok(self.infer_batch(&[tokens.to_vec()], control)?[0])
    }
}
fn asset(error: impl std::fmt::Display) -> ScanError {
    ScanError::Asset(error.to_string())
}
fn inference(error: impl std::fmt::Display) -> ScanError {
    ScanError::Inference(error.to_string())
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

fn validate_threshold(threshold: f64) -> Result<(), ScanError> {
    if !threshold.is_finite() || !(0.0..=1.0).contains(&threshold) {
        return Err(ScanError::Config("Wolf threshold must be in [0,1]".into()));
    }
    Ok(())
}

impl WolfConfig {
    pub(crate) fn validate(&self) -> Result<(), ScanError> {
        validate_threshold(self.threshold)
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
