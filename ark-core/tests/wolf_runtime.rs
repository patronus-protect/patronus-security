#![cfg(feature = "wolf")]
use patronus_ark_core::wolf::WolfConfig;
use patronus_ark_core::{ScanChecks, ScanError, Scanner, ScannerConfig};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
struct Bundle(PathBuf);
impl Bundle {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "ark-wolf-runtime-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        fs::copy(
            source.join("wolf_synthetic_fp16.onnx"),
            path.join("model_fp16.onnx"),
        )
        .unwrap();
        fs::copy(source.join("tokenizer.mmbpe"), path.join("tokenizer.mmbpe")).unwrap();
        let reference: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(source.join("wolf_synthetic_reference_254.json")).unwrap(),
        )
        .unwrap();
        let entry = |name: &str| serde_json::json!({"path":name,"blake3":blake3::hash(&fs::read(path.join(name)).unwrap()).to_hex().to_string()});
        let manifest = serde_json::json!({"schema_version":1,"model_id":"wolf-defender-small","revision":"synthetic-test-only","precision":"fp16","model":entry("model_fp16.onnx"),"tokenizer":entry("tokenizer.mmbpe"),"content_tokens":254,"sequence_tokens":256,"pad_id":0,"output_name":"logits","output":"scalar","reference":reference["reference"],"parity_cases":reference["parity_cases"],"logit_tolerance":0.02});
        fs::write(
            path.join("wolf.manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        Self(path)
    }
    fn config(&self, threshold: f64) -> ScannerConfig {
        ScannerConfig {
            wolf: Some(WolfConfig {
                bundle_dir: self.0.clone(),
                threshold,
                precision: Default::default(),
                backend: Default::default(),
                runtime_options: Default::default(),
            }),
            ..Default::default()
        }
    }
}
impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn fp16_runtime_processes_every_window_with_caller_threshold() {
    let bundle = Bundle::new();
    let mut scanner = Scanner::new(bundle.config(0.9)).unwrap();
    let short = scanner.scan(" a").unwrap().wolf.unwrap();
    assert_eq!(short.windows, 1);
    assert!(!short.matched);
    let long = scanner.scan(&" a".repeat(257)).unwrap().wolf.unwrap();
    assert_eq!(long.windows, 2);
    assert!(long.document_logit.is_finite());
    let mut scanner = Scanner::new(bundle.config(0.1)).unwrap();
    assert!(scanner.scan(" a").unwrap().wolf.unwrap().matched);
}
#[test]
fn missing_corrupt_and_reference_mismatched_bundles_fail_before_scanning() {
    let bundle = Bundle::new();
    assert!(matches!(
        Scanner::new(bundle.config(f64::NAN)),
        Err(ScanError::Config(_))
    ));
    let manifest = bundle.0.join("wolf.manifest.json");
    let mut contract: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    contract["parity_cases"][0]["expected_logit"] = serde_json::json!(100.0);
    fs::write(&manifest, serde_json::to_vec(&contract).unwrap()).unwrap();
    assert!(matches!(
        Scanner::new(bundle.config(0.5)),
        Err(ScanError::Asset(_))
    ));
    fs::write(bundle.0.join("model_fp16.onnx"), b"corrupt").unwrap();
    assert!(matches!(
        Scanner::new(bundle.config(0.5)),
        Err(ScanError::Asset(_))
    ));
    fs::remove_file(bundle.0.join("model_fp16.onnx")).unwrap();
    assert!(matches!(
        Scanner::new(bundle.config(0.5)),
        Err(ScanError::Asset(_))
    ));
}

#[test]
fn dynamic_short_windows_use_matching_tensor_shapes() {
    let bundle = Bundle::new();
    let path = bundle.0.join("wolf.manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["dynamic_sequence"] = serde_json::json!(true);
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let mut scanner = Scanner::new(bundle.config(0.8)).unwrap();
    assert_eq!(scanner.scan(" a").unwrap().wolf.unwrap().windows, 1);
    assert_eq!(scanner.scan("").unwrap().wolf.unwrap().windows, 1);
    assert_eq!(
        scanner
            .scan(&" a".repeat(257))
            .unwrap()
            .wolf
            .unwrap()
            .windows,
        2
    );
}

#[test]
fn probability_error_cannot_hide_inside_logit_tolerance() {
    let bundle = Bundle::new();
    let path = bundle.0.join("wolf.manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let actual = manifest["parity_cases"][0]["expected_logit"]
        .as_f64()
        .unwrap();
    manifest["parity_cases"][0]["expected_logit"] = serde_json::json!(actual + 0.03);
    manifest["logit_tolerance"] = serde_json::json!(0.05);
    manifest["probability_tolerance"] = serde_json::json!(0.005);
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    assert!(matches!(
        Scanner::new(bundle.config(0.5)),
        Err(ScanError::Asset(_))
    ));
}

#[test]
fn existing_fp16_layout_needs_no_manifest_or_new_revision() {
    let bundle = Bundle::new();
    fs::remove_file(bundle.0.join("wolf.manifest.json")).unwrap();
    fs::create_dir_all(bundle.0.join("onnx/onnx_fp16")).unwrap();
    fs::rename(
        bundle.0.join("model_fp16.onnx"),
        bundle.0.join("onnx/onnx_fp16/model_fp16.onnx"),
    )
    .unwrap();
    fs::write(
        bundle.0.join("config.json"),
        r#"{"num_labels":1,"pad_token_id":0}"#,
    )
    .unwrap();
    fs::write(
        bundle.0.join(".patronus-revision"),
        "142fadc5474163d4c483cb761d5a6b02e3aa1741",
    )
    .unwrap();
    let before = fs::read(bundle.0.join("tokenizer.mmbpe")).unwrap();
    let mut scanner = Scanner::new(bundle.config(0.9)).unwrap();
    let result = scanner.scan(&" a".repeat(257)).unwrap().wolf.unwrap();
    assert_eq!(result.windows, 2);
    assert_eq!(result.revision, "142fadc5474163d4c483cb761d5a6b02e3aa1741");
    assert_eq!(before, fs::read(bundle.0.join("tokenizer.mmbpe")).unwrap());
    assert!(!bundle.0.join("wolf.manifest.json").exists());
    assert!(!bundle.0.join("tokenizer.mmbpe.meta.json").exists());
}

#[test]
fn absent_manifest_does_not_accept_missing_or_broken_assets() {
    let bundle = Bundle::new();
    fs::remove_file(bundle.0.join("wolf.manifest.json")).unwrap();
    fs::write(bundle.0.join("config.json"), r#"{"num_labels":1}"#).unwrap();
    fs::write(bundle.0.join("model_fp16.onnx"), b"broken").unwrap();
    assert!(matches!(
        Scanner::new(bundle.config(0.5)),
        Err(ScanError::Inference(_))
    ));
    fs::remove_file(bundle.0.join("model_fp16.onnx")).unwrap();
    assert!(matches!(
        Scanner::new(bundle.config(0.5)),
        Err(ScanError::Asset(_))
    ));
}

#[test]
fn sensitive_data_scope_never_runs_enabled_wolf_inference() {
    let bundle = Bundle::new();
    let mut scanner = Scanner::new(bundle.config(0.0)).unwrap();
    let scoped = scanner
        .scan_with_checks(
            " a",
            ScanChecks {
                pii: true,
                dlp: true,
                injection: false,
            },
        )
        .unwrap();
    assert!(scoped.wolf.is_none());
    assert!(scoped.native.iter().all(|r| r.category != "injection"));
    let full = scanner.scan(" a").unwrap();
    assert!(full.wolf.unwrap().matched);
    assert!(scanner
        .scan_with_checks(
            " a",
            ScanChecks {
                pii: true,
                dlp: true,
                injection: false
            }
        )
        .unwrap()
        .wolf
        .is_none());
}

#[test]
fn legacy_manifest_keeps_integrity_without_overriding_254_content_profile() {
    let bundle = Bundle::new();
    let path = bundle.0.join("wolf.manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    manifest["content_tokens"] = serde_json::json!(256);
    manifest["sequence_tokens"] = serde_json::json!(258);
    fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let mut runner =
        patronus_ark_core::wolf::WolfRunner::new(&WolfConfig::new(&bundle.0, 0.8)).unwrap();
    assert_eq!(runner.scan(&" a".repeat(254)).unwrap().windows, 1);
    assert_eq!(runner.scan(&" a".repeat(255)).unwrap().windows, 2);
    // Compatibility must not erase the manifest's file integrity check.
    fs::write(bundle.0.join("model_fp16.onnx"), b"corrupt").unwrap();
    assert!(matches!(
        patronus_ark_core::wolf::WolfRunner::new(&WolfConfig::new(&bundle.0, 0.8)),
        Err(ScanError::Asset(_))
    ));
}

#[test]
fn cancelled_or_expired_wolf_work_stops_with_typed_error_and_runner_is_reusable() {
    use patronus_ark_core::{wolf::WolfRunner, ScanControl};
    let bundle = Bundle::new();
    let mut runner = WolfRunner::new(&WolfConfig::new(&bundle.0, 0.8)).unwrap();
    let cancelled = ScanControl::default();
    cancelled.cancel();
    assert!(matches!(
        runner.scan_with_control(" a", &cancelled),
        Err(ScanError::Cancelled)
    ));
    let expired = ScanControl::with_timeout(std::time::Duration::ZERO).unwrap();
    assert!(matches!(
        runner.scan_with_control(" a", &expired),
        Err(ScanError::DeadlineExceeded)
    ));
    let control = ScanControl::default();
    let mut completed = 0;
    let result =
        runner.scan_with_progress_and_control(&" a".repeat(763), &control, &mut |update| {
            if update.windows > 0 {
                completed = update.windows;
                control.cancel();
            }
        });
    assert!(matches!(result, Err(ScanError::Cancelled)));
    assert_eq!(completed, 1);
    assert_eq!(runner.scan(" a").unwrap().windows, 1);
}

#[test]
fn deadline_terminates_active_onnx_loop_and_same_runner_remains_usable() {
    use patronus_ark_core::{wolf::WolfRunner, ScanControl};
    let bundle = Bundle::new();
    fs::remove_file(bundle.0.join("wolf.manifest.json")).unwrap();
    fs::write(
        bundle.0.join("model_fp16.onnx"),
        include_bytes!("fixtures/wolf_cancellable.onnx"),
    )
    .unwrap();
    fs::write(bundle.0.join("config.json"), r#"{"num_labels":1}"#).unwrap();
    let mut runner = WolfRunner::new(&WolfConfig::new(&bundle.0, 0.8)).unwrap();
    let control = ScanControl::with_timeout(std::time::Duration::from_millis(30)).unwrap();
    assert!(matches!(
        runner.scan_with_control(" a", &control),
        Err(ScanError::DeadlineExceeded)
    ));
    // A fresh RunOptions must not inherit the previous invocation's terminate bit.
    assert_eq!(
        runner
            .scan_with_control("", &ScanControl::default())
            .unwrap()
            .document_logit,
        0.0
    );
}
