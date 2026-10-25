#![cfg(feature = "wolf")]
use patronus_ark_core::wolf::WolfConfig;
use patronus_ark_core::{ScanError, Scanner, ScannerConfig};
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
            &fs::read_to_string(source.join("wolf_synthetic_reference.json")).unwrap(),
        )
        .unwrap();
        let entry = |name: &str| serde_json::json!({"path":name,"blake3":blake3::hash(&fs::read(path.join(name)).unwrap()).to_hex().to_string()});
        let manifest = serde_json::json!({"schema_version":1,"model_id":"wolf-defender-small","revision":"synthetic-test-only","precision":"fp16","model":entry("model_fp16.onnx"),"tokenizer":entry("tokenizer.mmbpe"),"content_tokens":256,"sequence_tokens":258,"pad_id":0,"output_name":"logits","output":"scalar","reference":reference["reference"],"parity_cases":reference["parity_cases"],"logit_tolerance":0.02});
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
