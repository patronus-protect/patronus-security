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
mod cache {
    use super::*;
    use crate::wolf::WolfPrecision;
    #[cfg(feature = "download")]
    use std::fs;
    use std::{
        fs::File,
        path::Path,
        time::{Duration, Instant},
    };
    const LOCK: &str = ".patronus-wolf-prepare.lock";
    const PENDING: &str = ".patronus-wolf-pending";
    #[cfg(feature = "download")]
    const REVISION: &str = ".patronus-revision";
    fn asset(e: impl std::fmt::Display) -> ScanError {
        ScanError::Asset(e.to_string())
    }
    fn deadline(options: &WarmupOptions) -> Result<Instant, ScanError> {
        Instant::now()
            .checked_add(Duration::from_millis(options.download_timeout_ms))
            .ok_or_else(|| ScanError::Config("download timeout overflows clock".into()))
    }
    fn remaining(deadline: Instant) -> Result<Duration, ScanError> {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| asset("Wolf asset preparation deadline exceeded"))
    }
    fn lock_contended(error: &std::io::Error) -> bool {
        error.kind() == std::io::ErrorKind::WouldBlock
            || error.raw_os_error() == fs2::lock_contended_error().raw_os_error()
    }
    fn wait_lock(file: &File, exclusive: bool, deadline: Instant) -> Result<(), ScanError> {
        loop {
            remaining(deadline)?;
            let result = if exclusive {
                fs2::FileExt::try_lock_exclusive(file)
            } else {
                fs2::FileExt::try_lock_shared(file)
            };
            match result {
                Ok(()) => return Ok(()),
                Err(e) if lock_contended(&e) => {
                    std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(10)))
                }
                Err(e) => return Err(asset(e)),
            }
        }
    }
    fn read_lock(dir: &Path) -> Result<Option<File>, ScanError> {
        match File::open(dir.join(LOCK)) {
            Ok(file) => Ok(Some(file)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(asset(e)),
        }
    }
    fn preferred(precision: WolfPrecision) -> &'static [WolfPrecision] {
        crate::wolf::precision_order(
            precision,
            std::env::var("PATRONUS_L3_PRECISION").is_ok_and(|p| p.eq_ignore_ascii_case("fp16")),
        )
    }
    fn available(dir: &Path, precision: WolfPrecision) -> Option<WolfPrecision> {
        preferred(precision).iter().copied().find(|&p| {
            crate::wolf::model_paths(p)
                .iter()
                .any(|file| dir.join(file).is_file())
        })
    }
    fn local_present(dir: &Path, precision: WolfPrecision) -> Result<bool, ScanError> {
        if !dir.join("wolf.manifest.json").is_file()
            && (available(dir, precision).is_none()
                || !["tokenizer.mmbpe", "tokenizer.json"]
                    .iter()
                    .any(|p| dir.join(p).is_file()))
        {
            return Ok(false);
        }
        let manifest = crate::wolf::asset_manifest_at(dir, precision)?;
        Ok(
            dir.join(&manifest.model.path).is_file()
                && dir.join(&manifest.tokenizer.path).is_file(),
        )
    }
    /// Nonblocking readiness. A cache being prepared, or an unfinished managed cache, is not ready.
    pub fn wolf_assets_present(dir: &Path, precision: WolfPrecision) -> Result<bool, ScanError> {
        let lock = read_lock(dir)?;
        if let Some(lock) = &lock {
            match fs2::FileExt::try_lock_shared(lock) {
                Ok(()) => {}
                Err(e) if lock_contended(&e) => return Ok(false),
                Err(e) => return Err(asset(e)),
            }
        }
        if dir.join(PENDING).exists() {
            return Ok(false);
        }
        local_present(dir, precision)
    }
    /// Prepare a cache without constructing a decision policy, tokenizer or ONNX session.
    pub fn prepare_wolf_cache(
        dir: &Path,
        precision: WolfPrecision,
        options: &WarmupOptions,
        progress: Option<&(dyn Fn(usize, usize) + Send + Sync)>,
    ) -> Result<(), ScanError> {
        options.validate()?;
        let deadline = deadline(options)?;
        // Read-only callers can use existing readonly caches. They never create lockfiles.
        {
            let lock = read_lock(dir)?;
            if let Some(lock) = &lock {
                wait_lock(lock, false, deadline)?;
            }
            if !dir.join(PENDING).exists() && local_present(dir, precision)? {
                if let Some(callback) = progress {
                    callback(4, 4);
                }
                return Ok(());
            }
            if options.download == DownloadPolicy::Never {
                return Err(asset(
                    "Wolf assets missing or preparation incomplete; prepare them or enable download=missing",
                ));
            }
        }
        #[cfg(not(feature = "download"))]
        {
            Err(ScanError::Config(
                "asset download requires the Core download feature".into(),
            ))
        }
        #[cfg(feature = "download")]
        {
            download(dir, precision, deadline, progress)
        }
    }
    #[cfg(feature = "download")]
    fn pending_origin() -> String {
        format!("{WOLF_REPOSITORY}\n{WOLF_REVISION}\n")
    }
    #[cfg(feature = "download")]
    fn atomic_marker(dir: &Path, name: &str, value: &str) -> Result<(), ScanError> {
        use std::{
            io::Write,
            sync::atomic::{AtomicU64, Ordering},
        };
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = dir.join(format!(
            "{name}.tmp-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(asset)?;
            file.write_all(value.as_bytes()).map_err(asset)?;
            file.sync_all().map_err(asset)?;
            drop(file);
            fs::rename(&path, dir.join(name)).map_err(asset)
        })();
        if result.is_err() {
            let _ = fs::remove_file(path);
        }
        result
    }
    #[cfg(feature = "download")]
    fn has_unknown_files(dir: &Path) -> Result<bool, ScanError> {
        for entry in fs::read_dir(dir).map_err(asset)? {
            let entry = entry.map_err(asset)?;
            if entry.file_name() == LOCK {
                continue;
            }
            if entry.file_type().map_err(asset)?.is_dir() {
                if has_unknown_files(&entry.path())? {
                    return Ok(true);
                }
            } else {
                return Ok(true);
            }
        }
        Ok(false)
    }
    #[cfg(feature = "download")]
    fn establish_origin(dir: &Path) -> Result<(), ScanError> {
        if dir.join("wolf.manifest.json").exists() {
            return Err(asset(
                "prepare the files declared by the supplied Wolf manifest locally",
            ));
        }
        let revision = match fs::read_to_string(dir.join(REVISION)) {
            Ok(value) => Some(value),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(asset(e)),
        };
        if revision
            .as_deref()
            .is_some_and(|r| r.trim() != WOLF_REVISION)
        {
            return Err(asset(
                "incomplete Wolf cache has a different revision; use a separate empty cache",
            ));
        }
        match fs::read_to_string(dir.join(PENDING)) {
            Ok(value) if value == pending_origin() => return Ok(()),
            Ok(_) => return Err(asset("Wolf pending cache has an unknown origin")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(asset(e)),
        }
        if revision.is_none() && has_unknown_files(dir)? {
            return Err(asset(
                "incomplete local Wolf assets have unknown provenance; use a separate empty cache",
            ));
        }
        // Persist origin before the first asset, so interrupted downloads can safely resume.
        atomic_marker(dir, PENDING, &pending_origin())
    }
    #[cfg(feature = "download")]
    fn download(
        dir: &Path,
        precision: WolfPrecision,
        deadline: Instant,
        progress: Option<&(dyn Fn(usize, usize) + Send + Sync)>,
    ) -> Result<(), ScanError> {
        use crate::assets::download::{
            download_hf_file_with_options, get_hf_token, DownloadOptions,
        };
        fs::create_dir_all(dir).map_err(asset)?;
        let lock = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(LOCK))
            .map_err(asset)?;
        wait_lock(&lock, true, deadline)?;
        // Recheck after admission: a different process may already have completed this cache.
        if !dir.join(PENDING).exists() && local_present(dir, precision)? {
            if let Some(callback) = progress {
                callback(4, 4);
            }
            return Ok(());
        }
        establish_origin(dir)?;
        let precision = available(dir, precision).unwrap_or(preferred(precision)[0]);
        let files = wolf_files(precision);
        let present = |file: &str| {
            if file == WOLF_FP16_FILE || file == WOLF_QUANTIZED_FILE {
                available(dir, precision).is_some()
            } else if file == "tokenizer.json" {
                dir.join("tokenizer.mmbpe").is_file() || dir.join(file).is_file()
            } else {
                dir.join(file).is_file()
            }
        };
        let mut completed = files.iter().filter(|file| present(file)).count();
        if let Some(callback) = progress {
            callback(completed, files.len());
        }
        let token = if completed < files.len() {
            get_hf_token()
        } else {
            None
        };
        for &file in files {
            if present(file) {
                continue;
            }
            download_hf_file_with_options(
                token.as_deref(),
                WOLF_REPOSITORY,
                WOLF_REVISION,
                file,
                &dir.join(file),
                true,
                WOLF_MODEL_ID,
                &DownloadOptions {
                    timeout: remaining(deadline)?,
                },
            )
            .map_err(asset)?;
            completed += 1;
            if let Some(callback) = progress {
                callback(completed, files.len());
            }
        }
        remaining(deadline)?;
        if !dir.join("tokenizer.mmbpe").exists() && dir.join("tokenizer.json").is_file() {
            crate::assets::mmbert_tokenizer::ensure_mmbert_compact_tokenizer(
                WOLF_MODEL_ID,
                &dir.join("tokenizer.json"),
            )
            .map_err(asset)?
            .ok_or_else(|| asset("unsupported Wolf tokenizer"))?;
        }
        if !local_present(dir, precision)? {
            return Err(asset("Wolf preparation did not produce complete assets"));
        }
        atomic_marker(dir, REVISION, WOLF_REVISION)?;
        fs::remove_file(dir.join(PENDING)).map_err(asset)?;
        Ok(())
    }
    #[cfg(all(test, feature = "download"))]
    mod tests {
        use super::*;
        use std::path::PathBuf;
        struct Directory(PathBuf);
        impl Directory {
            fn new() -> Self {
                use std::sync::atomic::{AtomicU64, Ordering};
                static NEXT: AtomicU64 = AtomicU64::new(0);
                let path = std::env::temp_dir().join(format!(
                    "ark-cache-test-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
                fs::create_dir_all(&path).unwrap();
                Self(path)
            }
            fn complete(&self) {
                fs::create_dir_all(self.0.join("onnx/onnx_fp16")).unwrap();
                fs::write(
                    self.0.join(WOLF_FP16_FILE),
                    include_bytes!("../tests/fixtures/wolf_synthetic_fp16.onnx"),
                )
                .unwrap();
                fs::write(
                    self.0.join("tokenizer.mmbpe"),
                    include_bytes!("../tests/fixtures/tokenizer.mmbpe"),
                )
                .unwrap();
                fs::write(self.0.join("config.json"), r#"{"num_labels":1}"#).unwrap();
                fs::write(self.0.join("tokenizer_config.json"), "{}").unwrap();
            }
        }
        impl Drop for Directory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        fn missing() -> WarmupOptions {
            WarmupOptions {
                download: DownloadPolicy::Missing,
                ..Default::default()
            }
        }
        #[test]
        fn managed_preparation_builds_the_compact_tokenizer_without_loading_a_model() {
            let dir = Directory::new();
            dir.complete();
            fs::remove_file(dir.0.join("tokenizer.mmbpe")).unwrap();
            let mut vocab = serde_json::Map::new();
            for (token, id) in [("<bos>", 0), ("<eos>", 1), ("<unk>", 2), ("▁", 3)] {
                vocab.insert(token.to_owned(), id.into());
            }
            for byte in 0..=255 {
                vocab.insert(format!("<{byte:#04X}>"), (byte + 10).into());
            }
            fs::write(
                dir.0.join("tokenizer.json"),
                serde_json::to_vec(&serde_json::json!({
                    "added_tokens": [{"id":0,"content":"<bos>"},{"id":1,"content":"<eos>"}],
                    "model":{"type":"BPE","byte_fallback":true,"vocab":vocab,"merges":[]}
                }))
                .unwrap(),
            )
            .unwrap();
            atomic_marker(&dir.0, PENDING, &pending_origin()).unwrap();
            // An invalid ONNX file proves asset preparation never initializes a session.
            fs::write(dir.0.join(WOLF_FP16_FILE), b"not a model").unwrap();
            prepare_wolf_cache(&dir.0, WolfPrecision::Fp16, &missing(), None).unwrap();
            assert!(dir.0.join("tokenizer.mmbpe").is_file());
            assert!(!dir.0.join(PENDING).exists());
        }
        #[test]
        fn complete_unmanaged_local_bundle_is_never_relabelled() {
            let dir = Directory::new();
            dir.complete();
            prepare_wolf_cache(&dir.0, WolfPrecision::Fp16, &missing(), None).unwrap();
            assert!(wolf_assets_present(&dir.0, WolfPrecision::Fp16).unwrap());
            assert!(!dir.0.join(REVISION).exists());
            assert!(!dir.0.join(PENDING).exists());
            assert!(!dir.0.join(LOCK).exists());
        }
        #[test]
        fn unknown_partial_cache_is_rejected_before_any_download() {
            let dir = Directory::new();
            fs::write(dir.0.join("tokenizer.mmbpe"), b"local export").unwrap();
            let error =
                prepare_wolf_cache(&dir.0, WolfPrecision::Fp16, &missing(), None).unwrap_err();
            assert!(error.to_string().contains("unknown provenance"));
            assert_eq!(
                fs::read(dir.0.join("tokenizer.mmbpe")).unwrap(),
                b"local export"
            );
            assert!(!dir.0.join(PENDING).exists());
            assert!(!dir.0.join(REVISION).exists());
        }
        #[test]
        fn pending_origin_precedes_files_and_only_complete_cache_gets_revision() {
            let dir = Directory::new();
            establish_origin(&dir.0).unwrap();
            assert_eq!(
                fs::read_to_string(dir.0.join(PENDING)).unwrap(),
                pending_origin()
            );
            assert!(!dir.0.join(REVISION).exists());
            dir.complete();
            assert!(!wolf_assets_present(&dir.0, WolfPrecision::Fp16).unwrap());
            assert!(prepare_wolf_cache(
                &dir.0,
                WolfPrecision::Fp16,
                &WarmupOptions::default(),
                None
            )
            .is_err());
            prepare_wolf_cache(&dir.0, WolfPrecision::Fp16, &missing(), None).unwrap();
            assert_eq!(
                fs::read_to_string(dir.0.join(REVISION)).unwrap(),
                WOLF_REVISION
            );
            assert!(!dir.0.join(PENDING).exists());
            assert!(wolf_assets_present(&dir.0, WolfPrecision::Fp16).unwrap());
        }
        #[test]
        fn legacy_current_pin_can_resume_but_other_origins_cannot() {
            let trusted = Directory::new();
            fs::write(trusted.0.join(REVISION), WOLF_REVISION).unwrap();
            fs::write(trusted.0.join("config.json"), "{}").unwrap();
            establish_origin(&trusted.0).unwrap();
            let other = Directory::new();
            fs::write(other.0.join(REVISION), "other-revision").unwrap();
            assert!(establish_origin(&other.0).is_err());
            fs::remove_file(other.0.join(REVISION)).unwrap();
            fs::write(other.0.join(PENDING), "unrelated-source").unwrap();
            assert!(establish_origin(&other.0).is_err());
        }
        #[test]
        fn offline_preparation_honors_held_bundle_lock() {
            let dir = Directory::new();
            dir.complete();
            let lock = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(dir.0.join(LOCK))
                .unwrap();
            fs2::FileExt::lock_exclusive(&lock).unwrap();
            assert!(!wolf_assets_present(&dir.0, WolfPrecision::Fp16).unwrap());
            let options = WarmupOptions {
                download_timeout_ms: 30,
                ..Default::default()
            };
            assert!(
                prepare_wolf_cache(&dir.0, WolfPrecision::Fp16, &options, None)
                    .unwrap_err()
                    .to_string()
                    .contains("deadline")
            );
            drop(lock);
            prepare_wolf_cache(&dir.0, WolfPrecision::Fp16, &options, None).unwrap();
        }
    }
}
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
