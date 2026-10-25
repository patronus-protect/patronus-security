#![cfg(feature = "wolf")]
use patronus_ark_core::{
    wolf::{WolfConfig, WolfPrecision},
    DownloadPolicy, ScanError, Scanner, ScannerConfig, WarmupOptions,
};
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
            "ark-core-warmup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn config(&self) -> ScannerConfig {
        let mut config = ScannerConfig::default();
        let mut wolf = WolfConfig::new(&self.0, 0.9);
        wolf.precision = WolfPrecision::Fp16;
        config.wolf = Some(wolf);
        config
    }
    fn local(&self) {
        fs::write(
            self.0.join("model_fp16.onnx"),
            include_bytes!("fixtures/wolf_synthetic_fp16.onnx"),
        )
        .unwrap();
        fs::write(
            self.0.join("tokenizer.mmbpe"),
            include_bytes!("fixtures/tokenizer.mmbpe"),
        )
        .unwrap();
        fs::write(self.0.join("config.json"), r#"{"num_labels":1}"#).unwrap();
    }
}
impl Drop for Bundle {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn complete_local_assets_are_reused_without_network_or_migration() {
    let bundle = Bundle::new();
    bundle.local();
    let before = fs::metadata(bundle.0.join("model_fp16.onnx"))
        .unwrap()
        .modified()
        .unwrap();
    let mut scanner = Scanner::warmup(
        bundle.config(),
        WarmupOptions {
            download: DownloadPolicy::Missing,
            ..WarmupOptions::default()
        },
    )
    .unwrap();
    let first = scanner.scan("Meeting agenda.").unwrap().wolf.unwrap();
    let second = scanner.scan("Meeting agenda.").unwrap().wolf.unwrap();
    assert_eq!(first.document_logit, second.document_logit);
    assert_eq!(first.precision, "fp16");
    assert_eq!(
        before,
        fs::metadata(bundle.0.join("model_fp16.onnx"))
            .unwrap()
            .modified()
            .unwrap()
    );
    assert!(!bundle.0.join("wolf.manifest.json").exists());
    assert!(!bundle.0.join(".patronus-revision").exists());
    assert!(!bundle.0.join(".patronus-wolf-prepare.lock").exists());
}
#[test]
fn offline_missing_and_corrupt_assets_fail_instead_of_starting_clean() {
    let bundle = Bundle::new();
    assert!(matches!(
        Scanner::warmup(bundle.config(), WarmupOptions::default()),
        Err(ScanError::Asset(_))
    ));
    assert_eq!(fs::read_dir(&bundle.0).unwrap().count(), 0);
    bundle.local();
    fs::write(bundle.0.join("model_fp16.onnx"), b"broken model").unwrap();
    assert!(Scanner::warmup(bundle.config(), WarmupOptions::default()).is_err());
}
#[test]
fn invalid_scan_policy_is_rejected_before_asset_preparation() {
    let bundle = Bundle::new();
    let mut config = bundle.config();
    config.max_input_bytes = 0;
    assert!(matches!(
        Scanner::warmup(
            config,
            WarmupOptions {
                download: DownloadPolicy::Missing,
                ..WarmupOptions::default()
            }
        ),
        Err(ScanError::Config(_))
    ));
    assert_eq!(fs::read_dir(&bundle.0).unwrap().count(), 0);
    let mut config = bundle.config();
    config.wolf.as_mut().unwrap().threshold = f64::NAN;
    assert!(matches!(
        Scanner::warmup(
            config,
            WarmupOptions {
                download: DownloadPolicy::Missing,
                ..WarmupOptions::default()
            }
        ),
        Err(ScanError::Config(_))
    ));
    assert_eq!(fs::read_dir(&bundle.0).unwrap().count(), 0);
}

#[cfg(feature = "download")]
#[test]
#[ignore = "downloads the official FP16 and INT8/INT4 models into fresh temporary caches"]
fn official_download_warms_both_exports_then_reuses_them_offline() {
    for precision in [WolfPrecision::Fp16, WolfPrecision::Int8Int4] {
        let bundle = Bundle::new();
        let mut config = bundle.config();
        config.wolf.as_mut().unwrap().precision = precision;
        let mut scanner = Scanner::warmup(
            config.clone(),
            WarmupOptions {
                download: DownloadPolicy::Missing,
                ..WarmupOptions::default()
            },
        )
        .unwrap();
        let first = scanner
            .scan("Please summarize the meeting agenda.")
            .unwrap()
            .wolf
            .unwrap();
        assert!(first.document_logit.is_finite());
        assert_eq!(
            fs::read_to_string(bundle.0.join(".patronus-revision"))
                .unwrap()
                .trim(),
            patronus_ark_core::warmup::WOLF_REVISION
        );
        drop(scanner);
        let mut cached = Scanner::warmup(config, WarmupOptions::default()).unwrap();
        let second = cached
            .scan("Please summarize the meeting agenda.")
            .unwrap()
            .wolf
            .unwrap();
        assert!((first.document_logit - second.document_logit).abs() < 1e-6);
    }
}
