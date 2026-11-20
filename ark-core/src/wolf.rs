//! Offline Wolf inference over existing assets, with optional integrity metadata.
use crate::{
    aggregation::ClassPool, ml::mmbert_tokenizer::MmbertPairTokenizer, ScanControl, ScanError,
};
use ort::session::Session;
mod assets;
mod inference;
mod models;
mod published;
#[cfg(test)]
mod tests;
mod windows;
use crate::{wolf_options::WolfWindows, WolfExecutionOptions};
pub use assets::graph_candidates;
use assets::{asset_manifest, verified_file};
pub(crate) use assets::{asset_manifest_at, model_paths, precision_order};
pub use models::{
    WolfModel, WolfModelSpec, WolfPrecision, PRECISION_ENV, SUPPORT_FILES, WOLF_MODELS,
};
use published::Published;
pub use published::POOLING_FILE;
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

/// The Wolf Defender L3 of the injection module: bundle, model size,
/// precision, backend and the attack-probability threshold it detects at.
/// Everything unset follows the bundle's published settings (`POOLING.json`):
/// Wolf Defender detects strictly above 0.5 over 2048-token windows with 64 overlap.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WolfConfig {
    pub bundle_dir: PathBuf,
    /// Attack-probability threshold; unset takes the bundle's published one.
    #[serde(default)]
    pub threshold: Option<f64>,
    #[serde(default)]
    pub model: WolfModel,
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
    /// Window overlap the document cases were recorded with.
    #[serde(default)]
    pub overlap_tokens: usize,
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
    /// Absent before the first inference; otherwise the running pooled logit.
    pub document_logit: Option<f64>,
}
/// One loaded Wolf graph, shared through [`crate::shared_models`] by every
/// runner of the process that loads the same graph on the same backend.
struct WolfSession {
    session: std::sync::Mutex<Session>,
    execution_provider: String,
}

pub struct WolfRunner {
    session: Arc<WolfSession>,
    tokenizer: Arc<MmbertPairTokenizer>,
    manifest: WolfManifest,
    threshold: f64,
    /// The published rule: detect only above the threshold.
    strict: bool,
    temperature: f64,
    model_path: PathBuf,
    execution_provider: String,
    options: WolfExecutionOptions,
    windows: WolfWindows,
    fixed_width: Option<usize>,
}
impl WolfRunner {
    /// Construct a runner with the bundle's published windows.
    pub fn new(config: &WolfConfig) -> Result<Self, ScanError> {
        Self::new_with_options(config, WolfExecutionOptions::default())
    }

    /// Construct and warm a runner; execution sizes are validated against the local export.
    /// Unset sizes and threshold follow the bundle's `POOLING.json`.
    pub fn new_with_options(
        config: &WolfConfig,
        options: WolfExecutionOptions,
    ) -> Result<Self, ScanError> {
        options.validate()?;
        config.validate()?;
        let published = Published::read(&config.bundle_dir)?;
        let windows = options.resolve(published.window_tokens, published.overlap_tokens)?;
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
        let key = format!(
            "{}|{:?}|{:?}",
            model.display(),
            config.backend,
            config.runtime_options
        );
        let session = crate::shared_models::shared(&key, || {
            let (builder, execution_provider) = crate::onnx::configured_session_builder(
                config.backend,
                Some(&config.bundle_dir),
                config.runtime_options,
            )
            .map_err(inference)?;
            let builder = builder.with_independent_thread_pool().map_err(inference)?;
            Ok::<_, ScanError>(WolfSession {
                session: std::sync::Mutex::new(
                    crate::onnx::commit_session(builder, &model).map_err(inference)?,
                ),
                execution_provider,
            })
        })?;
        let fixed_width = inference::validate_session(
            &*session
                .session
                .lock()
                .map_err(|_| inference("Wolf session poisoned"))?,
            &config.bundle_dir,
            windows,
            &manifest,
        )?;
        let execution_provider = session.execution_provider.clone();
        let mut runner = Self {
            session,
            tokenizer,
            manifest,
            threshold: config.threshold.unwrap_or(published.threshold),
            strict: published.strict,
            temperature: published.temperature,
            model_path: model,
            execution_provider,
            options,
            windows,
            fixed_width,
        };
        // Always execute the actual backend before declaring the scanner ready.
        runner.infer(&[], &ScanControl::default())?;
        // Integrity/reference metadata is opt-in; ordinary Ark FP16 assets need none.
        runner.verify_reference_cases()?;
        Ok(runner)
    }
    fn verify_reference_cases(&mut self) -> Result<(), ScanError> {
        if self.manifest.content_tokens != self.windows.content_tokens()
            || self.manifest.sequence_tokens != self.windows.window_tokens
        {
            // Manifests of another window still verify file integrity, but
            // their references are not evidence for this profile.
            log::debug!("Wolf references skipped for a different execution profile");
            return Ok(());
        }
        for case in self.manifest.parity_cases.clone() {
            if case.token_ids.len() > self.windows.content_tokens() {
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
        // Document references also depend on the overlap they were recorded
        // with. Short raw-logit/tokenizer references above remain valid for
        // custom batching.
        if self.windows.overlap_tokens != self.manifest.overlap_tokens
            || self.windows.batch_size != 1
        {
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

    pub fn model_id(&self) -> &str {
        &self.manifest.model_id
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
            total_windows = windows::count(tokens, self.windows);
            if let Some(callback) = progress.as_mut() {
                callback(WolfProgress {
                    windows: 0,
                    total_windows,
                    document_logit: None,
                });
            }
        }
        let mut pool = ClassPool::new(self.temperature);
        let tokenizer = Arc::clone(&self.tokenizer);
        let mut windows = windows::Windows::new(self.windows);
        let mut batch = Vec::new();
        let scanned = tokenizer.visit_tokens(text, |token| {
            control.check().map_err(|e| e.to_string())?;
            if let Some(window) = windows.push(token.id) {
                batch.push(window);
                if batch.len() == self.windows.batch_size {
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
            matched: if self.strict {
                probability > self.threshold
            } else {
                probability >= self.threshold
            },
            windows: pool.count(),
            model_id: self.manifest.model_id.clone(),
            revision: self.manifest.revision.clone(),
            precision: self.manifest.precision.clone(),
        })
    }
    /// The window and batch configuration this session was requested with;
    /// unset sizes run with the bundle's published ones.
    pub fn execution_options(&self) -> WolfExecutionOptions {
        self.options
    }

    fn consume_batch(
        &mut self,
        batch: &[Vec<u32>],
        control: &ScanControl,
        pool: &mut ClassPool,
        total_windows: u64,
        progress: &mut Option<&mut dyn FnMut(WolfProgress)>,
    ) -> Result<(), ScanError> {
        for logits in self.infer_batch(batch, control)? {
            control.check()?;
            pool.push(logits).map_err(inference)?;
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

    /// The injection-minus-benign logit of one window.
    fn infer(&mut self, tokens: &[u32], control: &ScanControl) -> Result<f64, ScanError> {
        let [benign, injection] = self.infer_batch(&[tokens.to_vec()], control)?[0];
        Ok(injection - benign)
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
        self.threshold.map_or(Ok(()), validate_threshold)
    }

    pub fn new(bundle_dir: impl Into<PathBuf>, threshold: f64) -> Self {
        Self {
            bundle_dir: bundle_dir.into(),
            threshold: Some(threshold),
            model: WolfModel::default(),
            precision: WolfPrecision::default(),
            backend: crate::ExecutionBackend::default(),
            runtime_options: crate::OnnxRuntimeOptions::default(),
        }
    }
}
