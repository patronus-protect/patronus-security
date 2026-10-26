//! Explicit asset preparation and one-time runtime warmup. Scanning stays offline.
use crate::{ScanError, Scanner, ScannerConfig};
use serde::{Deserialize, Serialize};

pub const WOLF_MODEL_ID: &str = "wolf-defender-small";
pub const WOLF_REPOSITORY: &str = "patronus-studio/wolf-defender-prompt-injection-small";
pub const WOLF_REVISION: &str = "142fadc5474163d4c483cb761d5a6b02e3aa1741";
pub const WOLF_FP16_FILE: &str = "onnx/onnx_fp16/model_fp16.onnx";
pub const WOLF_QUANTIZED_FILE: &str = "onnx/int8_int4_embeddings/model.onnx";
pub const WOLF_FILES: &[&str] = &[
    WOLF_QUANTIZED_FILE,
    WOLF_FP16_FILE,
    "config.json",
    "tokenizer.json",
    "tokenizer_config.json",
];

/// Required files for an official export, also used by Ark's category preparation.
#[cfg(feature = "wolf")]
pub fn wolf_files(precision: crate::wolf::WolfPrecision) -> &'static [&'static str] {
    use crate::wolf::WolfPrecision;
    match precision {
        WolfPrecision::Fp16 => &[
            WOLF_FP16_FILE,
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
        WolfPrecision::Int8Int4 => &[
            WOLF_QUANTIZED_FILE,
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
        WolfPrecision::Auto => wolf_files(
            crate::wolf::precision_order(
                precision,
                std::env::var("PATRONUS_L3_PRECISION")
                    .is_ok_and(|p| p.eq_ignore_ascii_case("fp16")),
            )[0],
        ),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DownloadPolicy {
    #[default]
    Never,
    Missing,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WarmupOptions {
    pub download: DownloadPolicy,
    /// Budget for asset lock waiting, downloads and retries; not model construction.
    pub download_timeout_ms: u64,
}
impl Default for WarmupOptions {
    fn default() -> Self {
        Self {
            download: DownloadPolicy::Never,
            download_timeout_ms: 600_000,
        }
    }
}
impl WarmupOptions {
    fn validate(&self) -> Result<(), ScanError> {
        if self.download_timeout_ms == 0 {
            return Err(ScanError::Config(
                "positive download timeout required".into(),
            ));
        }
        Ok(())
    }
}
impl Scanner {
    /// Prepare configured assets, then construct one warm scanner used by subsequent scans.
    pub fn warmup(config: ScannerConfig, options: WarmupOptions) -> Result<Self, ScanError> {
        Self::warmup_with_wolf_options(config, options, crate::WolfExecutionOptions::default())
    }

    /// Prepare assets and warm one reusable scanner with explicit Wolf execution options.
    pub fn warmup_with_wolf_options(
        config: ScannerConfig,
        options: WarmupOptions,
        execution: crate::WolfExecutionOptions,
    ) -> Result<Self, ScanError> {
        execution.validate()?;
        prepare_assets(&config, &options)?;
        Self::new_with_wolf_options(config, execution)
    }
}
/// Prepare model files without creating a tokenizer, ONNX session or scanner.
pub fn prepare_assets(config: &ScannerConfig, options: &WarmupOptions) -> Result<(), ScanError> {
    config.validate()?;
    options.validate()?;
    #[cfg(feature = "wolf")]
    if let Some(wolf) = &config.wolf {
        prepare_wolf_assets(wolf, options)?;
    }
    Ok(())
}

#[cfg(feature = "wolf")]
mod cache;
#[cfg(feature = "wolf")]
pub use cache::{prepare_wolf_cache, wolf_assets_present};

#[cfg(feature = "wolf")]
pub fn prepare_wolf_assets(
    config: &crate::wolf::WolfConfig,
    options: &WarmupOptions,
) -> Result<(), ScanError> {
    prepare_wolf_assets_with_progress(config, options, None)
}
#[cfg(feature = "wolf")]
pub fn prepare_wolf_assets_with_progress(
    config: &crate::wolf::WolfConfig,
    options: &WarmupOptions,
    progress: Option<&(dyn Fn(usize, usize) + Send + Sync)>,
) -> Result<(), ScanError> {
    config.validate()?;
    prepare_wolf_cache(&config.bundle_dir, config.precision, options, progress)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn offline_is_default_and_invalid_budget_is_rejected() {
        assert_eq!(WarmupOptions::default().download, DownloadPolicy::Never);
        assert!(prepare_assets(
            &ScannerConfig::default(),
            &WarmupOptions {
                download_timeout_ms: 0,
                ..WarmupOptions::default()
            }
        )
        .is_err());
    }
    #[test]
    fn native_warmup_needs_no_assets_or_downloads() {
        let mut scanner = Scanner::warmup(
            ScannerConfig::default(),
            WarmupOptions {
                download: DownloadPolicy::Missing,
                ..WarmupOptions::default()
            },
        )
        .unwrap();
        assert!(scanner.scan("Meeting agenda.").is_ok());
    }
}
