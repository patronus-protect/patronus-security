// SPDX-License-Identifier: MIT OR Apache-2.0
//! Revision-pinned models that a Core user registers. A [`ModelSpec`] names a
//! model's repository, pin, cache directory and optional environment override;
//! Core resolves the directory, checks that it holds the pinned revision,
//! fetches the files the caller lists and prepares their generated files in one
//! [`ModelSpec::prepare`], so a user such as Ark keeps only its model table and
//! model-specific file lists.
use crate::{warmup::DownloadPolicy, ScanError};
use std::{
    fs, io,
    path::{Path, PathBuf},
};

/// Names the revision a managed model directory holds; written after its files.
pub const REVISION_MARKER: &str = ".patronus-revision";

/// One revision-pinned model below a model cache root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModelSpec {
    /// Public model name, used in logs and progress reports.
    pub id: &'static str,
    /// Hugging Face repository.
    pub repository: &'static str,
    /// Immutable commit revision the cache is pinned to.
    pub revision: &'static str,
    /// Directory inside the repository that holds the model files; empty for its root.
    pub source_prefix: &'static str,
    /// Model directory below the cache root.
    pub cache_subdir: &'static str,
    /// Environment variable naming a local directory that replaces the cache directory.
    /// Such a directory is the caller's own: Core neither checks its pin nor fetches into it.
    pub env_override: Option<&'static str>,
}

impl ModelSpec {
    /// A model at the root of `repository`, without environment override.
    pub const fn new(
        id: &'static str,
        repository: &'static str,
        revision: &'static str,
        cache_subdir: &'static str,
    ) -> Self {
        Self {
            id,
            repository,
            revision,
            source_prefix: "",
            cache_subdir,
            env_override: None,
        }
    }

    /// The same model, read from `prefix` inside its repository.
    pub const fn with_source_prefix(mut self, prefix: &'static str) -> Self {
        self.source_prefix = prefix;
        self
    }

    /// The same model, replaced by the directory the environment variable `key` names.
    pub const fn with_env_override(mut self, key: &'static str) -> Self {
        self.env_override = Some(key);
        self
    }

    /// The local directory the environment override names, when it is set.
    pub fn override_dir(&self) -> Option<PathBuf> {
        self.env_override
            .and_then(std::env::var_os)
            .map(PathBuf::from)
    }

    /// The managed cache directory below `root`.
    pub fn cache_dir(&self, root: &Path) -> PathBuf {
        root.join(self.cache_subdir)
    }

    /// The directory to load from: the environment override, else the cache directory.
    pub fn dir(&self, root: &Path) -> PathBuf {
        self.override_dir().unwrap_or_else(|| self.cache_dir(root))
    }

    /// Whether `dir`'s revision marker names this model's pin.
    pub fn is_current(&self, dir: &Path) -> bool {
        stored_revision(dir)
            .is_ok_and(|stored| stored.as_deref().map(str::trim) == Some(self.revision))
    }

    /// Whether `dir` holds this model's pin and every file of `files`.
    pub fn files_present(&self, dir: &Path, files: &[&str]) -> bool {
        self.is_current(dir) && files.iter().all(|file| dir.join(file).is_file())
    }

    /// The fetch of `relative` (below the source prefix) at this model's pin into `dest`.
    pub fn file(&self, relative: &str, dest: PathBuf) -> ModelFile {
        let prefix = self.source_prefix.trim_matches('/');
        let relative = relative.trim_start_matches('/');
        ModelFile {
            repository: self.repository,
            revision: self.revision,
            source: if prefix.is_empty() {
                relative.to_owned()
            } else {
                format!("{prefix}/{relative}")
            },
            dest,
            required: true,
            label: self.id,
        }
    }

    /// Prepare this model in the cache directory below `root` for loading `files`: when
    /// the directory does not hold the pin with every file, fetch them (all of them for
    /// another pin) and mark it current, or fail under [`DownloadPolicy::Never`]. With
    /// `generate`, then write the generated files (see [`PrepareOptions::generate`]).
    pub fn prepare(
        &self,
        root: &Path,
        files: &[&str],
        options: &PrepareOptions<'_>,
    ) -> Result<PathBuf, ScanError> {
        let dir = self.cache_dir(root);
        if !self.files_present(&dir, files) {
            if options.download == DownloadPolicy::Never {
                return Err(ScanError::Asset(format!(
                    "missing {} assets at {}; downloads disabled",
                    self.id,
                    dir.display()
                )));
            }
            self.fetch(&dir, files, options.progress)?;
        }
        if options.generate {
            prepare_generated_files(self.id, &dir, files);
        }
        Ok(dir)
    }

    /// Fetch `files` into `dir`: those missing, or all of them when `dir` holds another
    /// pin. Then mark it current.
    #[cfg(feature = "download")]
    fn fetch(
        &self,
        dir: &Path,
        files: &[&str],
        progress: Option<&Progress<'_>>,
    ) -> Result<(), ScanError> {
        let current = self.is_current(dir);
        let missing = files
            .iter()
            .filter(|file| !current || !dir.join(file).is_file())
            .map(|file| self.file(file, dir.join(file)))
            .collect::<Vec<_>>();
        fetch_files(&missing, files.len(), progress)?;
        self.mark_current(dir)
    }

    #[cfg(not(feature = "download"))]
    fn fetch(&self, _: &Path, _: &[&str], _: Option<&Progress<'_>>) -> Result<(), ScanError> {
        Err(no_download())
    }

    /// Prepare a package-style model, whose own `manifest` file lists its
    /// files, in the cache directory below `root`: fetch the manifest when the
    /// directory does not hold the pin (or lacks it), then `list` the package
    /// from the directory and whether it already held the pin. Fetch the
    /// listed files that are missing (all of them for another pin) and the
    /// shared files whose copy is not current, link every shared copy into
    /// the directory, mark it current, or fail under
    /// [`DownloadPolicy::Never`] when anything is to fetch. With `generate`,
    /// then write the generated files of the listed files.
    pub fn prepare_package(
        &self,
        root: &Path,
        manifest: &str,
        list: impl FnOnce(&Path, bool) -> Result<PackageFiles, ScanError>,
        options: &PrepareOptions<'_>,
    ) -> Result<PathBuf, ScanError> {
        let dir = self.cache_dir(root);
        let current = self.is_current(&dir);
        let refuse = |options: &PrepareOptions<'_>| -> Result<(), ScanError> {
            if options.download == DownloadPolicy::Never {
                return Err(ScanError::Asset(format!(
                    "missing {} assets at {}; downloads disabled",
                    self.id,
                    dir.display()
                )));
            }
            Ok(())
        };
        let manifest_path = dir.join(manifest);
        let fetch_manifest = !current || !manifest_path.is_file();
        if fetch_manifest {
            refuse(options)?;
            self.fetch_package(&[self.file(manifest, manifest_path)], 1, options.progress)?;
        }
        let package = list(&dir, current)?;
        let fetches = package
            .shared
            .iter()
            .filter(|file| !file.current)
            .map(|file| self.file(&file.relative, file.path.clone()))
            .chain(
                package
                    .files
                    .iter()
                    .filter(|file| !current || !dir.join(file).is_file())
                    .map(|file| self.file(file, dir.join(file))),
            )
            .collect::<Vec<_>>();
        if !fetches.is_empty() {
            refuse(options)?;
            let total = package.files.len() + package.shared.len() + 1;
            self.fetch_package(&fetches, total, options.progress)?;
        }
        for file in &package.shared {
            link_shared_file(&file.path, &dir.join(&file.relative)).map_err(|error| {
                ScanError::Asset(format!("link {}: {error}", file.path.display()))
            })?;
        }
        #[cfg(feature = "download")]
        if fetch_manifest || !fetches.is_empty() {
            self.mark_current(&dir)?;
        }
        if options.generate {
            let files = package.files.iter().map(String::as_str).collect::<Vec<_>>();
            prepare_generated_files(self.id, &dir, &files);
        }
        Ok(dir)
    }

    #[cfg(feature = "download")]
    fn fetch_package(
        &self,
        files: &[ModelFile],
        total: usize,
        progress: Option<&Progress<'_>>,
    ) -> Result<(), ScanError> {
        fetch_files(files, total, progress)
    }

    #[cfg(not(feature = "download"))]
    fn fetch_package(
        &self,
        _: &[ModelFile],
        _: usize,
        _: Option<&Progress<'_>>,
    ) -> Result<(), ScanError> {
        Err(no_download())
    }

    /// Write `dir`'s revision marker; call it once every file of the pin is in place.
    #[cfg(feature = "download")]
    pub fn mark_current(&self, dir: &Path) -> Result<(), ScanError> {
        fs::create_dir_all(dir).map_err(asset)?;
        atomic_marker(dir, REVISION_MARKER, self.revision)
    }
}

/// The files of a package-style model, as its manifest lists them
/// ([`ModelSpec::prepare_package`]).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackageFiles {
    /// Files inside the model directory, below the source prefix; neither
    /// the manifest nor a shared file.
    pub files: Vec<String>,
    /// Files the model shares with other models.
    pub shared: Vec<SharedFile>,
}

/// A file several models share: one copy at `path`, linked into each model
/// directory at `relative`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedFile {
    /// Path inside the model directory and below the source prefix.
    pub relative: String,
    /// The shared copy.
    pub path: PathBuf,
    /// Whether the shared copy is current; one that is not is fetched again.
    pub current: bool,
}

/// Link `dest` to the shared copy `shared`, replacing what `dest` held: a
/// symbolic link, or on Windows a hard link where it can.
pub fn link_shared_file(shared: &Path, dest: &Path) -> io::Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::symlink_metadata(dest).is_ok() {
        fs::remove_file(dest)?;
    }
    #[cfg(unix)]
    return std::os::unix::fs::symlink(shared, dest);
    #[cfg(windows)]
    return fs::hard_link(shared, dest)
        .or_else(|_| std::os::windows::fs::symlink_file(shared, dest));
    #[cfg(not(any(unix, windows)))]
    return fs::hard_link(shared, dest);
}

#[cfg(not(feature = "download"))]
fn no_download() -> ScanError {
    ScanError::Config("asset download requires the Core download feature".into())
}

/// How [`ModelSpec::prepare`] treats a missing model and its generated files.
#[derive(Clone, Copy, Default)]
pub struct PrepareOptions<'a> {
    /// Whether a missing model, or one cached at another pin, is fetched.
    pub download: DownloadPolicy,
    /// Whether the generated files are written: the compact mmBERT tokenizer next to its
    /// `tokenizer.json` and external weight data for the `.onnx` graphs among the files.
    /// Loading only consumes them, so a delivery step sets it and a runtime start does not.
    pub generate: bool,
    /// Reports `(completed, total)` files of a fetch.
    pub progress: Option<&'a Progress<'a>>,
}

/// One file to fetch from a pinned repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelFile {
    pub repository: &'static str,
    pub revision: &'static str,
    /// Path inside the repository.
    pub source: String,
    pub dest: PathBuf,
    /// Whether a missing file fails the fetch; an optional one is skipped.
    pub required: bool,
    /// Name used in logs.
    pub label: &'static str,
}

/// Reports `(completed, total)` files; it may run on several fetch threads.
pub type Progress<'a> = dyn Fn(usize, usize) + Sync + 'a;

/// Parallel file fetches; more mostly contend for the same connection.
#[cfg(feature = "download")]
const FETCH_WORKERS: usize = 6;

/// Fetch `files` in parallel with Core's downloader (retries, per-file lock, atomic
/// replace). `total` counts the files already in place too: progress starts at
/// `total - files.len()` and reports every finished file.
#[cfg(feature = "download")]
pub fn fetch_files(
    files: &[ModelFile],
    total: usize,
    progress: Option<&Progress<'_>>,
) -> Result<(), ScanError> {
    let done = total.saturating_sub(files.len());
    if let Some(progress) = progress {
        progress(done, total);
    }
    if files.is_empty() {
        return Ok(());
    }
    let token = crate::assets::download::get_hf_token();
    run_bounded(
        files,
        FETCH_WORKERS,
        |file| {
            crate::assets::download::download_hf_file_at_revision(
                token.as_deref(),
                file.repository,
                file.revision,
                &file.source,
                &file.dest,
                file.required,
                file.label,
            )
            .map(drop)
            .map_err(asset)
        },
        |completed| {
            if let Some(progress) = progress {
                progress(done + completed, total);
            }
        },
    )
}

/// Run `work` over `items` on at most `workers` threads; the first error stops new work.
/// `finished` receives the running count of completed items, in order.
#[cfg(feature = "download")]
fn run_bounded<T: Sync>(
    items: &[T],
    workers: usize,
    work: impl Fn(&T) -> Result<(), ScanError> + Sync,
    finished: impl Fn(usize) + Sync,
) -> Result<(), ScanError> {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex, PoisonError,
    };
    let next = AtomicUsize::new(0);
    let completed = Mutex::new(0_usize);
    let failure = Mutex::new(None);
    std::thread::scope(|scope| {
        for _ in 0..workers.min(items.len()) {
            scope.spawn(|| loop {
                if failure
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .is_some()
                {
                    break;
                }
                let Some(item) = items.get(next.fetch_add(1, Ordering::Relaxed)) else {
                    break;
                };
                if let Err(error) = work(item) {
                    failure
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .get_or_insert(error);
                    break;
                }
                let mut completed = completed.lock().unwrap_or_else(PoisonError::into_inner);
                *completed += 1;
                finished(*completed);
            });
        }
    });
    match failure.into_inner().unwrap_or_else(PoisonError::into_inner) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Prepare the generated files of a fetched model in `dir`: the compact mmBERT tokenizer
/// next to its `tokenizer.json`, and external weight data for the `.onnx` graphs among
/// `files`, so ONNX Runtime memory-maps them. Both steps are best effort: a failure is
/// logged and leaves the source files, which load as before.
fn prepare_generated_files(id: &str, dir: &Path, files: &[&str]) {
    let tokenizer = dir.join("tokenizer.json");
    if tokenizer.is_file() {
        match crate::assets::mmbert_tokenizer::ensure_mmbert_compact_tokenizer(id, &tokenizer) {
            Ok(Some(path)) => log::debug!("compact tokenizer of {id} ready at {}", path.display()),
            Ok(None) => log::debug!("{id} has no compact tokenizer format"),
            Err(error) => log::warn!(
                "failed to prepare the compact tokenizer of {id} at {}: {error}; tokenizer.json remains available",
                dir.display()
            ),
        }
    }
    for graph in files
        .iter()
        .filter(|file| file.ends_with(".onnx"))
        .map(|file| dir.join(file))
    {
        match crate::onnx::externalize_weights(&graph) {
            Ok(true) => log::info!("moved the weights of {} to external data", graph.display()),
            Ok(false) => {}
            Err(error) => log::warn!(
                "weights of {} stay inline; external data rewrite failed: {error}",
                graph.display()
            ),
        }
    }
}

/// The raw revision marker of `dir`, if it has one.
pub(crate) fn stored_revision(dir: &Path) -> io::Result<Option<String>> {
    match fs::read_to_string(dir.join(REVISION_MARKER)) {
        Ok(revision) => Ok(Some(revision)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "download")]
fn asset(error: impl std::fmt::Display) -> ScanError {
    ScanError::Asset(error.to_string())
}

/// Write `value` to `dir/name` through a synced temporary file and a rename, so a reader
/// never sees a partial marker.
#[cfg(feature = "download")]
pub(crate) fn atomic_marker(dir: &Path, name: &str, value: &str) -> Result<(), ScanError> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    const SPEC: ModelSpec = ModelSpec::new("test-model", "org/repo", "rev-a", "models/test")
        .with_source_prefix("/l2/")
        .with_env_override("PATRONUS_MODEL_ASSETS_TEST_DIR");

    struct Directory(PathBuf);
    impl Directory {
        fn new(name: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "ark-model-assets-{name}-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_env_override_replaces_the_cache_dir() {
        let root = Path::new("/models");
        assert_eq!(SPEC.cache_dir(root), root.join("models/test"));
        assert_eq!(SPEC.dir(root), root.join("models/test"));
        std::env::set_var("PATRONUS_MODEL_ASSETS_TEST_DIR", "/local/export");
        assert_eq!(SPEC.dir(root), PathBuf::from("/local/export"));
        assert_eq!(SPEC.cache_dir(root), root.join("models/test"));
        std::env::remove_var("PATRONUS_MODEL_ASSETS_TEST_DIR");
        assert_eq!(SPEC.override_dir(), None);
    }

    #[test]
    fn files_resolve_below_the_source_prefix_at_the_pin() {
        let file = SPEC.file("/tokenizer/tokenizer.json", PathBuf::from("dest"));
        assert_eq!(file.source, "l2/tokenizer/tokenizer.json");
        assert_eq!((file.repository, file.revision), ("org/repo", "rev-a"));
        assert!(file.required);
        let root = ModelSpec::new("m", "org/repo", "rev", "m").file("config.json", "d".into());
        assert_eq!(root.source, "config.json");
    }

    #[test]
    fn a_model_is_present_only_at_its_pin_with_every_file() {
        let dir = Directory::new("present");
        fs::write(dir.0.join("model.onnx"), b"graph").unwrap();
        assert!(!SPEC.is_current(&dir.0));
        assert!(!SPEC.files_present(&dir.0, &["model.onnx"]));
        fs::write(dir.0.join(REVISION_MARKER), "rev-a\n").unwrap();
        assert!(SPEC.files_present(&dir.0, &["model.onnx"]));
        assert!(!SPEC.files_present(&dir.0, &["model.onnx", "config.json"]));
        fs::write(dir.0.join(REVISION_MARKER), "rev-b").unwrap();
        assert!(!SPEC.files_present(&dir.0, &["model.onnx"]));
    }

    #[test]
    fn a_present_package_links_its_shared_files_and_a_stale_one_needs_permission() {
        let root = Directory::new("prepare-package");
        let dir = SPEC.cache_dir(&root.0);
        let offline = PrepareOptions::default();
        let error = SPEC
            .prepare_package(&root.0, "manifest.json", |_, _| unreachable!(), &offline)
            .unwrap_err();
        assert!(error.to_string().contains("downloads disabled"), "{error}");

        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("manifest.json"), b"{}").unwrap();
        fs::write(dir.join("head.bin"), b"head").unwrap();
        fs::write(dir.join(REVISION_MARKER), "rev-a").unwrap();
        let shared = root.0.join("shared/tokenizer.json");
        fs::create_dir_all(shared.parent().unwrap()).unwrap();
        fs::write(&shared, b"tokens").unwrap();
        let package = |current| PackageFiles {
            files: vec!["head.bin".into()],
            shared: vec![SharedFile {
                relative: "tok/tokenizer.json".into(),
                path: shared.clone(),
                current,
            }],
        };
        let prepared = SPEC
            .prepare_package(
                &root.0,
                "manifest.json",
                |listed, pinned| {
                    assert_eq!((listed, pinned), (dir.as_path(), true));
                    Ok(package(true))
                },
                &offline,
            )
            .unwrap();
        assert_eq!(prepared, dir);
        assert_eq!(fs::read(dir.join("tok/tokenizer.json")).unwrap(), b"tokens");

        let error = SPEC
            .prepare_package(
                &root.0,
                "manifest.json",
                |_, _| Ok(package(false)),
                &offline,
            )
            .unwrap_err();
        assert!(error.to_string().contains("downloads disabled"), "{error}");
    }

    #[test]
    fn preparing_a_present_model_needs_no_download_and_a_missing_one_needs_permission() {
        let root = Directory::new("prepare-policy");
        let dir = SPEC.cache_dir(&root.0);
        let files = ["model.onnx"];
        let offline = PrepareOptions::default();
        let error = SPEC.prepare(&root.0, &files, &offline).unwrap_err();
        assert!(matches!(error, ScanError::Asset(_)), "{error}");
        assert!(error.to_string().contains("test-model"), "{error}");
        assert!(error.to_string().contains("downloads disabled"), "{error}");

        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("model.onnx"), b"graph").unwrap();
        fs::write(dir.join(REVISION_MARKER), "rev-a").unwrap();
        for download in [DownloadPolicy::Never, DownloadPolicy::Missing] {
            let options = PrepareOptions {
                download,
                ..PrepareOptions::default()
            };
            assert_eq!(SPEC.prepare(&root.0, &files, &options).unwrap(), dir);
        }
    }

    #[cfg(not(feature = "download"))]
    #[test]
    fn preparing_a_missing_model_without_the_download_feature_is_a_config_error() {
        let root = Directory::new("prepare-no-download");
        let options = PrepareOptions {
            download: DownloadPolicy::Missing,
            ..PrepareOptions::default()
        };
        let error = SPEC
            .prepare(&root.0, &["model.onnx"], &options)
            .unwrap_err();
        assert!(matches!(error, ScanError::Config(_)), "{error}");
    }

    #[cfg(feature = "download")]
    #[test]
    fn marking_current_writes_the_pin_atomically() {
        let dir = Directory::new("mark");
        let nested = dir.0.join("new/model");
        SPEC.mark_current(&nested).unwrap();
        assert_eq!(
            fs::read_to_string(nested.join(REVISION_MARKER)).unwrap(),
            "rev-a"
        );
        assert_eq!(fs::read_dir(&nested).unwrap().count(), 1);
        assert!(SPEC.is_current(&nested));
    }

    #[cfg(feature = "download")]
    #[test]
    fn fetching_nothing_reports_the_files_in_place() {
        let reports = std::sync::Mutex::new(Vec::new());
        let report = |done, total| reports.lock().unwrap().push((done, total));
        fetch_files(&[], 3, Some(&report)).unwrap();
        assert_eq!(*reports.lock().unwrap(), vec![(3, 3)]);
    }

    #[cfg(feature = "download")]
    #[test]
    fn parallel_work_is_bounded_ordered_in_progress_and_stops_at_an_error() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let active = AtomicUsize::new(0);
        let maximum = AtomicUsize::new(0);
        let reported = std::sync::Mutex::new(Vec::new());
        let items = (0..12).collect::<Vec<_>>();
        run_bounded(
            &items,
            4,
            |_| {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                maximum.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(std::time::Duration::from_millis(10));
                active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            },
            |completed| reported.lock().unwrap().push(completed),
        )
        .unwrap();
        assert!((2..=4).contains(&maximum.load(Ordering::SeqCst)));
        assert_eq!(*reported.lock().unwrap(), (1..=12).collect::<Vec<_>>());

        let started = AtomicUsize::new(0);
        let error = run_bounded(
            &items,
            1,
            |item| {
                started.fetch_add(1, Ordering::SeqCst);
                if *item == 2 {
                    Err(asset("broken"))
                } else {
                    Ok(())
                }
            },
            |_| {},
        )
        .unwrap_err();
        assert!(error.to_string().contains("broken"));
        assert_eq!(started.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn only_a_generating_preparation_writes_the_compact_tokenizer_and_external_weights() {
        use crate::onnx::{external_data_path, has_inline_weights, testing};
        let dir = Directory::new("prepare");
        crate::assets::mmbert_tokenizer::tests::write_supported_tokenizer(
            &dir.0.join("tokenizer.json"),
            "prepare",
        );
        let graph = dir.0.join("onnx/model.onnx");
        fs::create_dir_all(graph.parent().unwrap()).unwrap();
        fs::write(&graph, testing::model_with_weights()).unwrap();
        let files = ["onnx/model.onnx", "tokenizer.json"];
        let spec = ModelSpec::new("mmbert-test", "org/repo", "rev", "");
        fs::write(dir.0.join(REVISION_MARKER), "rev").unwrap();
        spec.prepare(&dir.0, &files, &PrepareOptions::default())
            .unwrap();
        assert!(!dir.0.join("tokenizer.mmbpe").exists());
        assert!(has_inline_weights(&graph).unwrap());
        let generate = PrepareOptions {
            generate: true,
            ..PrepareOptions::default()
        };
        spec.prepare(&dir.0, &files, &generate).unwrap();
        assert!(dir.0.join("tokenizer.mmbpe").is_file());
        assert!(!has_inline_weights(&graph).unwrap());
        assert!(external_data_path(&graph).is_file());
    }
}
