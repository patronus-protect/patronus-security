//! Offline Wolf inference over existing FP16 assets, with optional integrity metadata.
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
        if !config.threshold.is_finite() || !(0.0..=1.0).contains(&config.threshold) {
            return Err(ScanError::Config("Wolf threshold must be in [0,1]".into()));
        }
        let manifest_path = config.bundle_dir.join("wolf.manifest.json");
        let manifest = match fs::File::open(&manifest_path) {
            Ok(file) => {
                if file.metadata().map_err(asset)?.len() > 1024 * 1024 {
                    return Err(asset("Wolf manifest exceeds 1 MiB"));
                }
                let manifest: WolfManifest = serde_json::from_reader(file).map_err(asset)?;
                validate_manifest(&manifest)?;
                manifest
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                existing_fp16_assets(&config.bundle_dir)?
            }
            Err(error) => return Err(asset(error)),
        };
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
        let tokenizer = if tokenizer_path.extension().is_some_and(|ext| ext == "json") {
            let bytes = crate::assets::mmbert_tokenizer::compact_tokenizer_bytes(&tokenizer_path)
                .map_err(asset)?;
            MmbertPairTokenizer::from_bytes(&bytes).map_err(asset)?
        } else {
            MmbertPairTokenizer::from_file(&tokenizer_path).map_err(asset)?
        };
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
        // Always execute the actual backend before declaring the scanner ready.
        runner.infer(&[])?;
        // Integrity/reference metadata is opt-in; ordinary Ark FP16 assets need none.
        runner.verify_reference_cases()?;
        Ok(runner)
    }
    fn verify_reference_cases(&mut self) -> Result<(), ScanError> {
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
            let actual = self.infer(&case.token_ids)?;
            if (actual - case.expected_logit).abs()
                > self.manifest.logit_tolerance
                    + self.manifest.relative_tolerance * case.expected_logit.abs()
                || (crate::aggregation::sigmoid(actual)
                    - crate::aggregation::sigmoid(case.expected_logit))
                .abs()
                    > self.manifest.probability_tolerance
            {
                return Err(ScanError::Asset(format!(
                    "FP16 parity mismatch: {actual} versus {}",
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

    pub fn model_path(&self) -> &Path {
        &self.model_path
    }

    pub fn scan(&mut self, text: &str) -> Result<WolfResult, ScanError> {
        self.scan_inner(text, None)
    }

    /// Emit a start update and one update per window without retaining chunk outputs.
    /// Counting tokens first provides exact totals and uses bounded tokenizer memory.
    pub fn scan_with_progress(
        &mut self,
        text: &str,
        progress: &mut dyn FnMut(WolfProgress),
    ) -> Result<WolfResult, ScanError> {
        self.scan_inner(text, Some(progress))
    }

    fn scan_inner(
        &mut self,
        text: &str,
        mut progress: Option<&mut dyn FnMut(WolfProgress)>,
    ) -> Result<WolfResult, ScanError> {
        let mut total_windows = 0;
        if progress.is_some() {
            let mut tokens = 0_u64;
            self.tokenizer
                .visit_tokens(text, |_| {
                    tokens = tokens.checked_add(1).ok_or("too many Wolf tokens")?;
                    Ok(())
                })
                .map_err(inference)?;
            total_windows = tokens.div_ceil(self.manifest.content_tokens as u64).max(1);
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
        let mut pending = Vec::with_capacity(self.manifest.content_tokens);
        tokenizer
            .visit_tokens(text, |token| {
                pending.push(token.id);
                if pending.len() == self.manifest.content_tokens {
                    let logit = self.infer(&pending).map_err(|e| e.to_string())?;
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
            })
            .map_err(inference)?;
        if !pending.is_empty() || pool.count() == 0 {
            pool.push(self.infer(&pending)?).map_err(inference)?;
            if let Some(callback) = progress.as_mut() {
                callback(WolfProgress {
                    windows: pool.count(),
                    total_windows,
                    document_logit: pool.logit(),
                });
            }
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

fn validate_manifest(manifest: &WolfManifest) -> Result<(), ScanError> {
    if manifest.schema_version != 1
        || manifest.model_id != "wolf-defender-small"
        || manifest.revision.is_empty()
        || manifest.precision != "fp16"
        || manifest.reference.is_empty()
        || manifest.content_tokens != 256
        || manifest.sequence_tokens != 258
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
        return Err(asset("invalid optional Wolf FP16 integrity manifest"));
    }
    Ok(())
}

/// Reuse Ark's established FP16 layout without creating files or changing revisions.
fn existing_fp16_assets(base: &Path) -> Result<WolfManifest, ScanError> {
    let model = [
        "onnx/onnx_fp16/model_fp16.onnx",
        "onnx/fp16/model_fp16.onnx",
        "model_fp16.onnx",
    ]
    .into_iter()
    .find(|name| base.join(name).is_file())
    .ok_or_else(|| asset("Wolf FP16 ONNX model is missing"))?;
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
        precision: "fp16".into(),
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
        content_tokens: 256,
        sequence_tokens: 258,
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
    pub fn new(bundle_dir: impl Into<PathBuf>, threshold: f64) -> Self {
        Self {
            bundle_dir: bundle_dir.into(),
            threshold,
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
    fn published_fp16_matches_all_training_references() {
        let bundle = std::env::var_os("ARK_WOLF_BUNDLE").expect("set ARK_WOLF_BUNDLE");
        let mut runner = WolfRunner::new(&WolfConfig::new(PathBuf::from(bundle), 0.8)).unwrap();
        let reference: WolfManifest = serde_json::from_str(include_str!(
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
        runner.manifest = reference;
        runner.verify_reference_cases().unwrap();
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
        for (tokens, windows) in [(0, 1), (256, 1), (257, 2), (513, 3)] {
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
