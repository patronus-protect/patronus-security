//! Explicit asset preparation and one-time runtime warmup. Scanning stays offline.
use crate::{ScanError, Scanner, ScannerConfig};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Cat, the K26 shell-risk release: a JSON model plus gated Cedar policy levels.
pub const SHELL_MODEL: &str = "cat-shell-risk-commander";
pub const SHELL_REPOSITORY: &str = "patronus-studio/cat-shell-risk-commander";
pub const SHELL_REVISION: &str = "a971100c6757230dbebbfdadd9a539312c9a9dcb";
/// `manifest.json` is fetched last: a bundle directory with a manifest is complete.
pub const SHELL_FILES: &[&str] = &[
    "config.json",
    "model.json",
    "policy_levels.json",
    "LICENSE",
    "manifest.json",
];
/// sha256 of [`SHELL_REVISION`]'s `manifest.json`. The manifest lists the
/// sha256 of every release file, so pinning it makes any changed file a
/// refused bundle.
pub const SHELL_MANIFEST_SHA256: &str =
    "b60905b95780ff7ab2cd55c63b1eaf296ddea2f53e53d50a8f97bfdf46d8f39a";

/// The model cache root when the caller names none: `<user cache>/patronus_ark`.
/// Core and ARK keep every model they share once below this root.
#[cfg(feature = "download")]
pub fn default_cache_root() -> Option<PathBuf> {
    dirs::cache_dir().map(|dir| dir.join("patronus_ark"))
}

/// Cat's bundle directory below a model cache root. Core's prepare functions and ARK use
/// this one layout, so a root holds each shared model once.
pub fn shell_bundle_dir(root: &Path) -> PathBuf {
    root.join("shell_command/cat_shell_risk_commander")
}

/// The bundle directory of a Wolf model below a model cache root, one per model.
#[cfg(feature = "wolf")]
pub fn wolf_bundle_dir(root: &Path, model: crate::wolf::WolfModel) -> PathBuf {
    root.join("wolf").join(model.spec().id)
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
    if let Some(shell) = &config.shell {
        prepare_shell_assets(shell, options)?;
    }
    Ok(())
}

/// Whether `config.bundle_dir` holds the release `config.manifest_sha256` pins.
pub fn shell_assets_present(config: &crate::detectors::shell::ShellConfig) -> bool {
    std::fs::read(config.bundle_dir.join("manifest.json")).is_ok_and(|manifest| {
        crate::detectors::facts_common::bundle::sha256_hex(&manifest)
            .eq_ignore_ascii_case(&config.manifest_sha256)
    })
}

/// Fetch the pinned Cat release into `config.bundle_dir` unless it already holds the
/// pinned bundle; an outdated bundle is replaced. Files are verified when the scanner
/// loads them.
pub fn prepare_shell_assets(
    config: &crate::detectors::shell::ShellConfig,
    options: &WarmupOptions,
) -> Result<(), ScanError> {
    prepare_shell_assets_with_progress(config, options, None)
}

/// [`prepare_shell_assets`] reporting `(completed, total)` files.
pub fn prepare_shell_assets_with_progress(
    config: &crate::detectors::shell::ShellConfig,
    options: &WarmupOptions,
    progress: Option<&(dyn Fn(usize, usize) + Send + Sync)>,
) -> Result<(), ScanError> {
    options.validate()?;
    let dir = &config.bundle_dir;
    if shell_assets_present(config) {
        if let Some(callback) = progress {
            callback(SHELL_FILES.len(), SHELL_FILES.len());
        }
        return Ok(());
    }
    if options.download == DownloadPolicy::Never {
        return Err(ScanError::Asset(format!(
            "{} holds no pinned Cat bundle; prepare it or enable download=missing",
            dir.display()
        )));
    }
    #[cfg(not(feature = "download"))]
    {
        Err(ScanError::Config(
            "asset download requires the Core download feature".into(),
        ))
    }
    #[cfg(feature = "download")]
    {
        use crate::assets::download::{
            download_hf_file_with_options, get_hf_token, DownloadOptions,
        };
        let deadline = std::time::Instant::now()
            + std::time::Duration::from_millis(options.download_timeout_ms);
        let token = get_hf_token();
        for (done, file) in SHELL_FILES.iter().enumerate() {
            if let Some(callback) = progress {
                callback(done, SHELL_FILES.len());
            }
            let timeout = deadline
                .checked_duration_since(std::time::Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or_else(|| ScanError::Asset("Cat download deadline exceeded".into()))?;
            download_hf_file_with_options(
                token.as_deref(),
                SHELL_REPOSITORY,
                SHELL_REVISION,
                file,
                &dir.join(file),
                true,
                "Cat",
                &DownloadOptions { timeout },
            )
            .map_err(|error| ScanError::Asset(error.to_string()))?;
        }
        if let Some(callback) = progress {
            callback(SHELL_FILES.len(), SHELL_FILES.len());
        }
        Ok(())
    }
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
    prepare_wolf_cache(
        &config.bundle_dir,
        config.model,
        config.precision,
        options,
        progress,
    )
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
    fn shell_bundle_is_ready_only_at_the_pinned_manifest() {
        let root = std::env::temp_dir().join(format!("core-shell-pin-{}", std::process::id()));
        let mut config = crate::detectors::shell::ShellConfig::new(shell_bundle_dir(&root));
        assert!(!shell_assets_present(&config));
        let never = WarmupOptions::default();
        assert!(prepare_shell_assets(&config, &never).is_err());
        config.manifest_sha256 =
            crate::detectors::shell::testing::write_synthetic_bundle(&config.bundle_dir, None)
                .unwrap();
        assert!(shell_assets_present(&config));
        prepare_shell_assets(&config, &never).unwrap();
        // A bundle of another release is outdated, not ready.
        config.manifest_sha256 = SHELL_MANIFEST_SHA256.into();
        assert!(!shell_assets_present(&config));
        let _ = std::fs::remove_dir_all(root);
    }
    #[cfg(feature = "wolf")]
    #[test]
    fn each_wolf_model_has_its_own_bundle_dir() {
        let root = Path::new("/models");
        let dirs: std::collections::HashSet<_> = crate::wolf::WolfModel::ALL
            .into_iter()
            .map(|model| wolf_bundle_dir(root, model))
            .collect();
        assert_eq!(dirs.len(), 3);
        assert_eq!(
            wolf_bundle_dir(root, crate::wolf::WolfModel::Small),
            root.join("wolf/wolf-defender-small")
        );
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
