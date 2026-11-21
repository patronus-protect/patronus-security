//! Explicit asset preparation and one-time runtime warmup. Scanning stays offline.
use crate::{ScanError, Scanner, ScannerConfig, SecurityCategory};
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

/// An explicit bundle directory, else `layout` below the model cache root:
/// `root` when given, else [`default_cache_root`]. Every bundle a config
/// does not place explicitly lives below this one root.
pub fn bundle_dir_or_default(
    explicit: Option<&Path>,
    root: Option<&Path>,
    layout: impl FnOnce(&Path) -> PathBuf,
) -> Result<PathBuf, ScanError> {
    if let Some(dir) = explicit {
        return Ok(dir.to_path_buf());
    }
    if let Some(root) = root {
        return Ok(layout(root));
    }
    #[cfg(feature = "download")]
    if let Some(root) = default_cache_root() {
        return Ok(layout(&root));
    }
    Err(ScanError::Config(
        "no bundle_dir and no model cache root: set bundle_dir or cache_root".into(),
    ))
}

/// The model cache root: `root` when given, else [`default_cache_root`].
pub fn model_cache_root(root: Option<&Path>) -> Result<PathBuf, ScanError> {
    bundle_dir_or_default(None, root, Path::to_path_buf)
}

/// The model cache root when the caller names none: `<user cache>/patronus_ark`.
/// Core and ARK keep every model they share once below this root.
#[cfg(feature = "download")]
pub fn default_cache_root() -> Option<PathBuf> {
    user_cache_dir(|key| std::env::var_os(key), home::home_dir())
        .map(|dir| dir.join("patronus_ark"))
}

/// The platform's user cache directory: `%LOCALAPPDATA%` on Windows,
/// `~/Library/Caches` on macOS, else an absolute `$XDG_CACHE_HOME` or
/// `~/.cache`.
#[cfg(feature = "download")]
fn user_cache_dir(
    env: impl Fn(&str) -> Option<std::ffi::OsString>,
    home: Option<PathBuf>,
) -> Option<PathBuf> {
    if cfg!(windows) {
        env("LOCALAPPDATA").map(PathBuf::from)
    } else if cfg!(target_os = "macos") {
        home.map(|home| home.join("Library/Caches"))
    } else {
        env("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .filter(|dir| dir.is_absolute())
            .or_else(|| home.map(|home| home.join(".cache")))
    }
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
/// How warmup fetches missing model files: [`ScannerConfig`]'s `download`,
/// `download_categories` and `download_timeout_ms` keys
/// ([`ScannerConfig::warmup_options`]). The default is offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmupOptions {
    pub download: DownloadPolicy,
    /// The categories whose model files may download; unset: every category.
    pub download_categories: Option<Vec<SecurityCategory>>,
    /// Budget for asset lock waiting, downloads and retries; not model construction.
    pub download_timeout_ms: u64,
}
impl Default for WarmupOptions {
    fn default() -> Self {
        ScannerConfig::default().warmup_options()
    }
}
impl WarmupOptions {
    /// The download policy for the model files of `category`.
    pub fn download_for(&self, category: SecurityCategory) -> DownloadPolicy {
        match &self.download_categories {
            Some(categories) if !categories.contains(&category) => DownloadPolicy::Never,
            _ => self.download,
        }
    }

    /// Refuse a zero download time budget.
    pub fn validate(&self) -> Result<(), ScanError> {
        if self.download_timeout_ms == 0 {
            return Err(ScanError::Config(
                "positive download timeout required".into(),
            ));
        }
        Ok(())
    }
}
impl Scanner {
    /// Prepare configured assets under the config's download keys, then
    /// construct one warm scanner used by subsequent scans.
    pub fn warmup(config: ScannerConfig) -> Result<Self, ScanError> {
        prepare_assets(&config)?;
        Self::new(config)
    }
}
/// Prepare model files under the config's download keys without creating a
/// tokenizer, ONNX session or scanner.
pub fn prepare_assets(config: &ScannerConfig) -> Result<(), ScanError> {
    config.validate()?;
    let config = &config.resolved()?;
    let options = &config.warmup_options();
    #[cfg(feature = "wolf")]
    if let Some(wolf) = &config.wolf {
        prepare_wolf_assets(wolf, options)?;
    }
    if let Some(shell) = &config.shell {
        prepare_shell_assets(shell, options)?;
    }
    Ok(())
}

/// Whether `config.bundle_dir` holds the release `config.manifest_sha256` pins, with
/// every release file the manifest lists in place and matching it.
pub fn shell_assets_present(config: &crate::detectors::shell::ShellConfig) -> bool {
    shell_bundle_problem(config).is_none()
}

/// Why `config.bundle_dir` is not the complete pinned release, if it is not.
fn shell_bundle_problem(config: &crate::detectors::shell::ShellConfig) -> Option<String> {
    let dir = &match config.dir(None) {
        Ok(dir) => dir,
        Err(problem) => return Some(problem),
    };
    if !dir.join("manifest.json").is_file() {
        return Some(format!("{} holds no Cat bundle", dir.display()));
    }
    let bundle = match crate::detectors::facts_common::bundle::VerifiedBundle::open(
        dir,
        Some(&config.manifest_sha256),
    ) {
        Ok(bundle) => bundle,
        Err(problem) => return Some(problem),
    };
    SHELL_FILES
        .iter()
        .filter(|file| **file != "manifest.json" && bundle.lists(file))
        .find_map(|file| bundle.read(file).err())
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
    let Some(problem) = shell_bundle_problem(config) else {
        if let Some(callback) = progress {
            callback(SHELL_FILES.len(), SHELL_FILES.len());
        }
        return Ok(());
    };
    if options.download_for(SecurityCategory::ShellCommand) == DownloadPolicy::Never {
        return Err(ScanError::Asset(format!(
            "{problem}; prepare it or enable download=missing"
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
        let dir = &config.dir(None).map_err(ScanError::Config)?;
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
        &config.dir(None)?,
        config.model,
        config.precision,
        options,
        progress,
    )
}

#[cfg(test)]
mod tests {

    #[cfg(all(feature = "download", unix, not(target_os = "macos")))]
    #[test]
    fn the_cache_root_follows_xdg_and_falls_back_to_home() {
        let home = Some(PathBuf::from("/home/u"));
        let xdg =
            |dir: &'static str| move |key: &str| (key == "XDG_CACHE_HOME").then(|| dir.into());
        assert_eq!(
            super::user_cache_dir(xdg("/x/cache"), home.clone()),
            Some("/x/cache".into())
        );
        assert_eq!(
            super::user_cache_dir(xdg("relative"), home.clone()),
            Some("/home/u/.cache".into())
        );
        assert_eq!(super::user_cache_dir(|_| None, None), None);
    }

    #[cfg(all(feature = "download", target_os = "macos"))]
    #[test]
    fn the_cache_root_is_library_caches_on_macos() {
        let home = Some(PathBuf::from("/Users/u"));
        assert_eq!(
            super::user_cache_dir(|_| None, home),
            Some("/Users/u/Library/Caches".into())
        );
    }
    use super::*;
    #[test]
    fn offline_is_default_and_invalid_budget_is_rejected() {
        assert_eq!(WarmupOptions::default().download, DownloadPolicy::Never);
        assert!(prepare_assets(&ScannerConfig {
            download_timeout_ms: 0,
            ..ScannerConfig::default()
        })
        .is_err());
    }
    #[test]
    fn shell_bundle_is_ready_only_at_the_pinned_manifest() {
        let root = std::env::temp_dir().join(format!("core-shell-pin-{}", std::process::id()));
        let bundle_dir = shell_bundle_dir(&root);
        let mut config = crate::detectors::shell::ShellConfig::new(&bundle_dir);
        assert!(!shell_assets_present(&config));
        let never = WarmupOptions::default();
        assert!(prepare_shell_assets(&config, &never).is_err());
        config.manifest_sha256 =
            crate::detectors::shell::testing::write_synthetic_bundle(&bundle_dir, None).unwrap();
        assert!(shell_assets_present(&config));
        prepare_shell_assets(&config, &never).unwrap();
        // A pinned manifest without the files it lists is not a complete bundle.
        let model = std::fs::read(bundle_dir.join("model.json")).unwrap();
        std::fs::remove_file(bundle_dir.join("model.json")).unwrap();
        assert!(!shell_assets_present(&config));
        let error = prepare_shell_assets(&config, &never)
            .unwrap_err()
            .to_string();
        assert!(error.contains("model.json"), "{error}");
        std::fs::write(bundle_dir.join("model.json"), b"{}").unwrap();
        assert!(!shell_assets_present(&config));
        std::fs::write(bundle_dir.join("model.json"), model).unwrap();
        assert!(shell_assets_present(&config));
        // A bundle of another release is outdated, not ready.
        config.manifest_sha256 = SHELL_MANIFEST_SHA256.into();
        assert!(!shell_assets_present(&config));
        let error = prepare_shell_assets(&config, &never)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("is not the pinned release manifest"),
            "{error}"
        );
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
        let mut scanner = Scanner::warmup(ScannerConfig {
            download: DownloadPolicy::Missing,
            ..ScannerConfig::default()
        })
        .unwrap();
        assert!(scanner.scan("Meeting agenda.").is_ok());
    }
    #[test]
    fn download_keys_are_config_keys_applied_per_category() {
        let config: ScannerConfig = serde_json::from_value(serde_json::json!({
            "download": "missing",
            "download_categories": ["shell_command"],
            "download_timeout_ms": 1000,
        }))
        .unwrap();
        let options = config.warmup_options();
        assert_eq!(options.download_timeout_ms, 1000);
        assert_eq!(
            options.download_for(SecurityCategory::ShellCommand),
            DownloadPolicy::Missing
        );
        assert_eq!(
            options.download_for(SecurityCategory::Injection),
            DownloadPolicy::Never
        );
        assert_eq!(
            ScannerConfig::default()
                .warmup_options()
                .download_for(SecurityCategory::ShellCommand),
            DownloadPolicy::Never
        );
    }
}
