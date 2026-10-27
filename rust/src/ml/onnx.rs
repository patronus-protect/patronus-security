// SPDX-License-Identifier: GPL-3.0-only
use crate::{EvaluationResult, ExecutionBackend, OnnxRuntimeOptions};
pub use patronus_ark_core::onnx::{
    active_execution_providers, available_execution_providers, configured_session_builder,
    warmup_runtime,
};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::tokenizer::MODEL_TOKENS;
pub use patronus_ark_core::ml::text_classifier::OnnxTextClassifier;
pub(crate) use patronus_ark_core::ml::text_classifier::RawClassifierOutput;

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

    /// Dedicated Wolf reuses existing FP16 assets through the synchronous Core runner.
    #[cfg(test)]
    pub(crate) fn infer_wolf_document(
        &mut self,
        text: &str,
        threshold: f64,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
    ) -> Result<patronus_ark_core::wolf::WolfResult, Box<dyn std::error::Error>> {
        self.infer_wolf_document_with_progress(
            text,
            threshold,
            backend,
            options,
            Default::default(),
            None,
        )
    }

    pub(crate) fn infer_wolf_document_with_progress(
        &mut self,
        text: &str,
        threshold: f64,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
        execution: crate::WolfExecutionOptions,
        progress: Option<&mut dyn FnMut(patronus_ark_core::wolf::WolfProgress)>,
    ) -> Result<patronus_ark_core::wolf::WolfResult, Box<dyn std::error::Error>> {
        self.infer_wolf_document_with_progress_and_control(
            text,
            threshold,
            backend,
            options,
            execution,
            &patronus_ark_core::ScanControl::default(),
            progress,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn infer_wolf_document_with_progress_and_control(
        &mut self,
        text: &str,
        threshold: f64,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
        execution: crate::WolfExecutionOptions,
        control: &patronus_ark_core::ScanControl,
        progress: Option<&mut dyn FnMut(patronus_ark_core::wolf::WolfProgress)>,
    ) -> Result<patronus_ark_core::wolf::WolfResult, Box<dyn std::error::Error>> {
        control.check()?;
        self.ensure_wolf_loaded(threshold, backend, options, execution)?;
        control.check()?;
        let runner = self.wolf_runner.as_mut().ok_or("Wolf runner not loaded")?;
        Ok(match progress {
            Some(callback) => runner.scan_with_progress_and_control(text, control, callback)?,
            None => runner.scan_with_control(text, control)?,
        })
    }

    pub(crate) fn ensure_wolf_loaded(
        &mut self,
        threshold: f64,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
        execution: crate::WolfExecutionOptions,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(runner) = self.wolf_runner.as_mut() {
            runner.set_threshold(threshold)?;
        }
        let options = options.normalized();
        if self.wolf_runner.is_none()
            || self.loaded_backend != Some(backend)
            || self.loaded_options != Some(options)
            || self
                .wolf_runner
                .as_ref()
                .is_some_and(|r| r.execution_options() != execution)
        {
            // Match the legacy lazy-loader lifetime: release the previous
            // session before allocating a replacement or changing precision/path.
            self.wolf_runner = None;
            self.loaded = None;
            self.loaded_backend = None;
            self.loaded_options = None;
            self.wolf_runner = Some(patronus_ark_core::wolf::WolfRunner::new_with_options(
                &patronus_ark_core::wolf::WolfConfig {
                    bundle_dir: self
                        .dir
                        .join(&self.tokenizer_path)
                        .parent()
                        .ok_or("invalid Wolf tokenizer path")?
                        .to_path_buf(),
                    threshold,
                    precision: Default::default(),
                    backend,
                    runtime_options: options,
                },
                execution,
            )?);
            self.loaded_backend = Some(backend);
            self.loaded_options = Some(options);
        }
        self.last_used = Some(Instant::now());
        Ok(())
    }

    pub(crate) fn warmup_session(
        &mut self,
        backend: ExecutionBackend,
        options: OnnxRuntimeOptions,
        execution: crate::WolfExecutionOptions,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if self.model_name == "wolf-defender-small" {
            self.infer_wolf_document_with_progress("", 0.5, backend, options, execution, None)?;
        } else {
            self.ensure_loaded(backend, options)?;
        }
        self.last_used = Some(Instant::now());
        Ok(())
    }

    pub(crate) fn decode_raw(&self, output: &RawClassifierOutput) -> EvaluationResult {
        output.decode(&self.class_names)
    }

    pub(crate) fn decode_probabilities(&self, output: &RawClassifierOutput) -> Vec<f32> {
        output.probabilities()
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
            .map(|runner| runner.precision())
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
        self.wolf_runner = None;
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
    fn eager_classifier_reexport_preserves_raw_logits_and_decisions() {
        let dir = fake_lazy_onnx_dir("core-eager-classifier");
        std::fs::write(
            dir.join("onnx/model.onnx"),
            include_bytes!("../../../ark-core/tests/fixtures/wolf_batch_binary.onnx"),
        )
        .unwrap();
        std::fs::write(
            dir.join("tokenizer.mmbpe"),
            include_bytes!("../../../ark-core/tests/fixtures/tokenizer.mmbpe"),
        )
        .unwrap();
        // Existing Ark users receive the Core type through the same public path.
        let mut classifier: patronus_ark_core::ml::text_classifier::OnnxTextClassifier =
            super::OnnxTextClassifier::from_dir_with_paths(
                &dir,
                vec!["benign".into(), "attack".into()],
                "fixture",
                &["onnx/model.onnx"],
                "tokenizer.json",
                256,
                ExecutionBackend::Cpu,
                OnnxRuntimeOptions::default(),
            )
            .unwrap()
            .unwrap();
        let outputs = classifier
            .infer_token_ids_batch_raw(&[&[400], &[900, 400]])
            .unwrap();
        for (output, expected) in outputs.iter().zip([0.0433_f32, 0.1343]) {
            assert_eq!(output.logits[0], 0.0);
            assert!((output.logits[1] - expected).abs() < 1e-6);
            let result = output.decode(&["benign".into(), "attack".into()]);
            assert_eq!(result.class_name, "attack");
            assert_eq!(result.level, "L3");
            assert!((result.confidence - 1.0 / (1.0 + (-f64::from(expected)).exp())).abs() < 1e-6);
        }
        drop(classifier);
        std::fs::remove_dir_all(dir).unwrap();
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
            .warmup_session(
                ExecutionBackend::Cpu,
                OnnxRuntimeOptions::default(),
                crate::WolfExecutionOptions::default(),
            )
            .is_err());
        assert!(!classifier.is_loaded());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn wolf_warmup_validates_profile_and_first_scan_reuses_warmed_session() {
        let dir = fake_lazy_onnx_dir("wolf-warmup-profile");
        let model = dir.join("model_fp16.onnx");
        std::fs::write(
            &model,
            include_bytes!("../../../ark-core/tests/fixtures/wolf_synthetic_fp16.onnx"),
        )
        .unwrap();
        std::fs::write(
            dir.join("tokenizer.mmbpe"),
            include_bytes!("../../../ark-core/tests/fixtures/tokenizer.mmbpe"),
        )
        .unwrap();
        std::fs::write(dir.join("config.json"), r#"{"num_labels":1}"#).unwrap();
        let mut classifier = LazyOnnxTextClassifier::from_dir_with_paths(
            &dir,
            vec!["benign".into(), "attack".into()],
            "wolf-defender-small",
            &["model_fp16.onnx"],
            "tokenizer.json",
            256,
        )
        .unwrap()
        .unwrap();
        let execution = crate::WolfExecutionOptions {
            window_tokens: 32,
            overlap_tokens: 10,
            batch_size: 4,
        };
        // This export has a static batch-one dimension. Reject the requested
        // profile during warmup rather than loading a different default profile.
        assert!(classifier
            .warmup_session(
                ExecutionBackend::Cpu,
                OnnxRuntimeOptions::default(),
                execution
            )
            .is_err());
        assert!(!classifier.is_loaded());
        std::fs::write(
            &model,
            include_bytes!("../../../ark-core/tests/fixtures/wolf_batch_scalar.onnx"),
        )
        .unwrap();
        classifier
            .warmup_session(
                ExecutionBackend::Cpu,
                OnnxRuntimeOptions::default(),
                execution,
            )
            .unwrap();
        std::fs::remove_file(&model).unwrap();
        let output = classifier
            .infer_wolf_document_with_progress(
                &" a".repeat(100),
                0.8,
                ExecutionBackend::Cpu,
                OnnxRuntimeOptions::default(),
                execution,
                None,
            )
            .unwrap();
        assert_eq!(output.windows, 5);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn wolf_lazy_runner_resolves_nested_legacy_bundle_and_reuses_its_session() {
        let dir = std::env::temp_dir().join(format!("ark-nested-wolf-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("l3/onnx/onnx_fp16")).unwrap();
        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(dir.clone());
        std::fs::write(
            dir.join("l3/onnx/onnx_fp16/model_fp16.onnx"),
            include_bytes!("../../../ark-core/tests/fixtures/wolf_synthetic_fp16.onnx"),
        )
        .unwrap();
        std::fs::write(
            dir.join("l3/tokenizer.mmbpe"),
            include_bytes!("../../../ark-core/tests/fixtures/tokenizer.mmbpe"),
        )
        .unwrap();
        std::fs::write(dir.join("l3/config.json"), r#"{"num_labels":1}"#).unwrap();
        let mut classifier = LazyOnnxTextClassifier::from_dir_with_paths(
            &dir,
            vec!["benign".into(), "attack".into()],
            "wolf-defender-small",
            &["l3/onnx/onnx_fp16/model_fp16.onnx"],
            "l3/tokenizer.json",
            256,
        )
        .unwrap()
        .unwrap();
        let output = classifier
            .infer_wolf_document(
                &" a".repeat(255),
                0.8,
                ExecutionBackend::Cpu,
                OnnxRuntimeOptions::default(),
            )
            .unwrap();
        assert_eq!(output.windows, 2);
        assert_eq!(classifier.precision(), Some("fp16"));
        assert!(classifier.loaded.is_none());
        std::fs::remove_file(dir.join("l3/onnx/onnx_fp16/model_fp16.onnx")).unwrap();
        let output = classifier
            .infer_wolf_document(
                " a",
                0.3,
                ExecutionBackend::Cpu,
                OnnxRuntimeOptions::default(),
            )
            .unwrap();
        assert_eq!(output.threshold, 0.3);
        assert!(output.matched);
        assert!(classifier.is_loaded());
        classifier.force_unload();
        assert!(!classifier.is_loaded());

        // Non-default document execution is delegated to Core and shares a
        // session only while its execution profile remains the same.
        let model = dir.join("l3/onnx/onnx_fp16/model_fp16.onnx");
        std::fs::write(
            &model,
            include_bytes!("../../../ark-core/tests/fixtures/wolf_batch_scalar.onnx"),
        )
        .unwrap();
        let options = crate::WolfExecutionOptions {
            window_tokens: 32,
            overlap_tokens: 10,
            batch_size: 4,
        };
        let output = classifier
            .infer_wolf_document_with_progress(
                &" a".repeat(100),
                0.8,
                ExecutionBackend::Cpu,
                OnnxRuntimeOptions::default(),
                options,
                None,
            )
            .unwrap();
        assert_eq!(output.windows, 5);
        std::fs::remove_file(&model).unwrap();
        assert!(classifier
            .infer_wolf_document_with_progress(
                " a",
                0.8,
                ExecutionBackend::Cpu,
                OnnxRuntimeOptions::default(),
                options,
                None
            )
            .is_ok());
        assert!(classifier
            .infer_wolf_document_with_progress(
                " a",
                0.8,
                ExecutionBackend::Cpu,
                OnnxRuntimeOptions::default(),
                crate::WolfExecutionOptions {
                    batch_size: 2,
                    ..options
                },
                None
            )
            .is_err());
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
