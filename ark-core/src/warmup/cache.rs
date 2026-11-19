use super::*;
use crate::wolf::{WolfModel, WolfPrecision};
#[cfg(feature = "download")]
use std::fs;
use std::{
    fs::File,
    path::Path,
    time::{Duration, Instant},
};
const LOCK: &str = ".patronus-wolf-prepare.lock";
const PENDING: &str = ".patronus-wolf-pending";
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
fn available(
    dir: &Path,
    model: WolfModel,
    precision: WolfPrecision,
) -> Result<Option<WolfPrecision>, ScanError> {
    Ok(crate::wolf::precision_order(precision)?
        .into_iter()
        .find(|&p| {
            crate::wolf::model_paths(model, p)
                .iter()
                .any(|file| dir.join(file).is_file())
        }))
}
/// A managed cache whose marker names another pin holds another model or revision.
fn other_pin(dir: &Path, model: WolfModel) -> Result<bool, ScanError> {
    match std::fs::read_to_string(dir.join(REVISION)) {
        Ok(revision) => Ok(revision.trim() != model.spec().revision),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(asset(e)),
    }
}
fn local_present(
    dir: &Path,
    model: WolfModel,
    precision: WolfPrecision,
) -> Result<bool, ScanError> {
    if other_pin(dir, model)? {
        return Ok(false);
    }
    if !dir.join("wolf.manifest.json").is_file()
        && (available(dir, model, precision)?.is_none()
            || !["tokenizer.mmbpe", "tokenizer.json"]
                .iter()
                .any(|p| dir.join(p).is_file()))
    {
        return Ok(false);
    }
    let manifest = crate::wolf::asset_manifest_at(dir, model, precision)?;
    Ok(dir.join(&manifest.model.path).is_file() && dir.join(&manifest.tokenizer.path).is_file())
}
/// The selected graph of a cache when it may be rewritten to external data: not when a
/// supplied integrity manifest applies to it, whose BLAKE3 pins the graph as published and
/// which [`crate::wolf::WolfRunner`] checks on every load.
fn rewritable_graph(
    dir: &Path,
    model: WolfModel,
    precision: WolfPrecision,
) -> Result<Option<std::path::PathBuf>, ScanError> {
    let manifest = crate::wolf::asset_manifest_at(dir, model, precision)?;
    Ok(manifest
        .model
        .blake3
        .is_empty()
        .then(|| dir.join(&manifest.model.path)))
}
/// Rewrite the selected graph of a cache to external data (see
/// [`crate::onnx::externalize_weights`]); the caller holds the exclusive bundle lock.
fn externalize_graph(
    dir: &Path,
    model: WolfModel,
    precision: WolfPrecision,
) -> Result<(), ScanError> {
    let Some(graph) = rewritable_graph(dir, model, precision)? else {
        return Ok(());
    };
    if crate::onnx::externalize_weights(&graph).map_err(asset)? {
        log::info!("moved the weights of {} to external data", graph.display());
    }
    Ok(())
}
/// Rewrite the selected graph of a complete managed cache to external data, once, under the
/// exclusive bundle lock. Unmanaged local bundles, and graphs a supplied manifest pins, are
/// never rewritten. A failure is logged and leaves the inline graph, which loads as before.
fn externalize_cached(dir: &Path, model: WolfModel, precision: WolfPrecision, deadline: Instant) {
    let result = (|| {
        if other_pin(dir, model)? || !dir.join(REVISION).is_file() {
            return Ok(());
        }
        let Some(graph) = rewritable_graph(dir, model, precision)? else {
            return Ok(());
        };
        if !crate::onnx::has_inline_weights(&graph).map_err(asset)? {
            return Ok(());
        }
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.join(LOCK))
            .map_err(asset)?;
        wait_lock(&lock, true, deadline)?;
        externalize_graph(dir, model, precision)
    })();
    if let Err(error) = result {
        log::warn!("Wolf weights in {} stay inline: {error}", dir.display());
    }
}
/// Nonblocking readiness. A cache being prepared, or an unfinished managed cache, is not ready.
pub fn wolf_assets_present(
    dir: &Path,
    model: WolfModel,
    precision: WolfPrecision,
) -> Result<bool, ScanError> {
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
    local_present(dir, model, precision)
}
/// Prepare a cache without constructing a decision policy, tokenizer or ONNX session.
pub fn prepare_wolf_cache(
    dir: &Path,
    model: WolfModel,
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
        if !dir.join(PENDING).exists() && local_present(dir, model, precision)? {
            drop(lock);
            externalize_cached(dir, model, precision, deadline);
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
        download(dir, model, precision, deadline, progress)
    }
}
#[cfg(feature = "download")]
fn pending_origin(model: WolfModel) -> String {
    let spec = model.spec();
    format!("{}\n{}\n", spec.repository, spec.revision)
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
        // Downloads keep a per-file transport lock next to each asset on purpose.
        if entry.file_name() == LOCK
            || entry
                .file_name()
                .to_string_lossy()
                .ends_with(".patronus-download.lock")
        {
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
fn establish_origin(dir: &Path, model: WolfModel) -> Result<(), ScanError> {
    if dir.join("wolf.manifest.json").exists() {
        return Err(asset(
            "prepare the files declared by the supplied Wolf manifest locally",
        ));
    }
    if other_pin(dir, model)? {
        clear_managed(dir)?;
    }
    let revision = match fs::read_to_string(dir.join(REVISION)) {
        Ok(value) => Some(value),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(asset(e)),
    };
    match fs::read_to_string(dir.join(PENDING)) {
        Ok(value) if value == pending_origin(model) => return Ok(()),
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
    atomic_marker(dir, PENDING, &pending_origin(model))
}
/// Remove the files a completed managed cache of another pin may hold, revision
/// marker last, so an upgrade never loads a stale graph or compact tokenizer.
#[cfg(feature = "download")]
fn clear_managed(dir: &Path) -> Result<(), ScanError> {
    let graphs = crate::wolf::WolfModel::ALL.into_iter().flat_map(|model| {
        crate::wolf::WolfPrecision::CONCRETE
            .into_iter()
            .filter_map(move |precision| model.spec().graph(precision))
    });
    let generated = ["tokenizer.mmbpe", "tokenizer.mmbpe.meta.json"];
    let files = graphs
        .flat_map(|graph| {
            let graph = dir.join(graph);
            [crate::onnx::external_data_path(&graph), graph]
        })
        .chain(
            crate::wolf::SUPPORT_FILES
                .into_iter()
                .chain(generated)
                .chain([REVISION])
                .map(|file| dir.join(file)),
        );
    for file in files {
        match fs::remove_file(file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(asset(e)),
        }
    }
    Ok(())
}
#[cfg(feature = "download")]
fn download(
    dir: &Path,
    model: WolfModel,
    precision: WolfPrecision,
    deadline: Instant,
    progress: Option<&(dyn Fn(usize, usize) + Send + Sync)>,
) -> Result<(), ScanError> {
    use crate::assets::download::{download_hf_file_with_options, get_hf_token, DownloadOptions};
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
    if !dir.join(PENDING).exists() && local_present(dir, model, precision)? {
        if let Some(callback) = progress {
            callback(4, 4);
        }
        return Ok(());
    }
    establish_origin(dir, model)?;
    let precision = match available(dir, model, precision)? {
        Some(precision) => precision,
        None => precision.resolve()?,
    };
    let spec = model.spec();
    let files = spec
        .files(precision)
        .ok_or_else(|| asset("Wolf precision did not resolve to an export"))?;
    let graph = files[0];
    let present = |file: &str| {
        if file == graph {
            dir.join(file).is_file()
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
    for file in files {
        if present(file) {
            continue;
        }
        download_hf_file_with_options(
            token.as_deref(),
            spec.repository,
            spec.revision,
            file,
            &dir.join(file),
            true,
            spec.id,
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
            spec.id,
            &dir.join("tokenizer.json"),
        )
        .map_err(asset)?
        .ok_or_else(|| asset("unsupported Wolf tokenizer"))?;
    }
    // The pin is written last; until then the old marker is gone and PENDING names the origin.
    if !local_present(dir, model, precision)? {
        return Err(asset("Wolf preparation did not produce complete assets"));
    }
    if let Err(error) = externalize_graph(dir, model, precision) {
        log::warn!("Wolf weights in {} stay inline: {error}", dir.display());
    }
    atomic_marker(dir, REVISION, spec.revision)?;
    fs::remove_file(dir.join(PENDING)).map_err(asset)?;
    Ok(())
}
#[cfg(all(test, feature = "download"))]
mod tests {
    use super::*;
    use std::path::PathBuf;
    const SMALL: WolfModel = WolfModel::Small;
    const FP16: &str = "onnx/onnx_fp16/model_fp16.onnx";
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
                self.0.join(FP16),
                include_bytes!("../../tests/fixtures/wolf_synthetic_fp16.onnx"),
            )
            .unwrap();
            fs::write(
                self.0.join("tokenizer.mmbpe"),
                include_bytes!("../../tests/fixtures/tokenizer.mmbpe"),
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
        atomic_marker(&dir.0, PENDING, &pending_origin(SMALL)).unwrap();
        // An invalid ONNX file proves asset preparation never initializes a session.
        fs::write(dir.0.join(FP16), b"not a model").unwrap();
        prepare_wolf_cache(&dir.0, SMALL, WolfPrecision::Fp16, &missing(), None).unwrap();
        assert!(dir.0.join("tokenizer.mmbpe").is_file());
        assert!(!dir.0.join(PENDING).exists());
    }
    #[test]
    fn complete_unmanaged_local_bundle_is_never_relabelled() {
        let dir = Directory::new();
        dir.complete();
        prepare_wolf_cache(&dir.0, SMALL, WolfPrecision::Fp16, &missing(), None).unwrap();
        assert!(wolf_assets_present(&dir.0, SMALL, WolfPrecision::Fp16).unwrap());
        assert!(!dir.0.join(REVISION).exists());
        assert!(!dir.0.join(PENDING).exists());
        assert!(!dir.0.join(LOCK).exists());
    }
    #[test]
    fn unknown_partial_cache_is_rejected_before_any_download() {
        let dir = Directory::new();
        fs::write(dir.0.join("tokenizer.mmbpe"), b"local export").unwrap();
        let error =
            prepare_wolf_cache(&dir.0, SMALL, WolfPrecision::Fp16, &missing(), None).unwrap_err();
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
        establish_origin(&dir.0, SMALL).unwrap();
        assert_eq!(
            fs::read_to_string(dir.0.join(PENDING)).unwrap(),
            pending_origin(SMALL)
        );
        assert!(!dir.0.join(REVISION).exists());
        dir.complete();
        assert!(!wolf_assets_present(&dir.0, SMALL, WolfPrecision::Fp16).unwrap());
        assert!(prepare_wolf_cache(
            &dir.0,
            SMALL,
            WolfPrecision::Fp16,
            &WarmupOptions::default(),
            None
        )
        .is_err());
        prepare_wolf_cache(&dir.0, SMALL, WolfPrecision::Fp16, &missing(), None).unwrap();
        assert_eq!(
            fs::read_to_string(dir.0.join(REVISION)).unwrap(),
            SMALL.spec().revision
        );
        assert!(!dir.0.join(PENDING).exists());
        assert!(wolf_assets_present(&dir.0, SMALL, WolfPrecision::Fp16).unwrap());
    }
    #[test]
    fn current_pin_can_resume_but_foreign_pending_origins_cannot() {
        let trusted = Directory::new();
        fs::write(trusted.0.join(REVISION), SMALL.spec().revision).unwrap();
        fs::write(trusted.0.join("config.json"), "{}").unwrap();
        establish_origin(&trusted.0, SMALL).unwrap();
        let other = Directory::new();
        fs::write(other.0.join(PENDING), "unrelated-source").unwrap();
        assert!(establish_origin(&other.0, SMALL).is_err());
    }
    #[test]
    fn completed_cache_of_another_pin_is_cleared_before_the_upgrade() {
        let dir = Directory::new();
        dir.complete();
        let old_graph = "onnx/int8_int4_embeddings/model.onnx";
        fs::create_dir_all(dir.0.join("onnx/int8_int4_embeddings")).unwrap();
        fs::write(dir.0.join(old_graph), b"previous release").unwrap();
        let old_data = crate::onnx::external_data_path(&dir.0.join(old_graph));
        fs::write(&old_data, b"previous weights").unwrap();
        // Real downloads leave their per-file transport locks behind.
        for file in [old_graph, "config.json", "tokenizer.json"] {
            fs::write(dir.0.join(format!("{file}.patronus-download.lock")), b"").unwrap();
        }
        fs::write(
            dir.0.join(REVISION),
            "142fadc5474163d4c483cb761d5a6b02e3aa1741",
        )
        .unwrap();
        // Complete files of an older pin are never served as the current model.
        assert!(!wolf_assets_present(&dir.0, SMALL, WolfPrecision::Int8Int4).unwrap());
        establish_origin(&dir.0, SMALL).unwrap();
        for file in [old_graph, FP16, "tokenizer.mmbpe", "config.json", REVISION] {
            assert!(!dir.0.join(file).exists(), "{file} survived the upgrade");
        }
        assert!(!old_data.exists());
        assert_eq!(
            fs::read_to_string(dir.0.join(PENDING)).unwrap(),
            pending_origin(SMALL)
        );
        // Another model in the same directory is a different pin as well.
        fs::write(dir.0.join(REVISION), SMALL.spec().revision).unwrap();
        assert!(other_pin(&dir.0, WolfModel::Edge).unwrap());
        assert!(!other_pin(&dir.0, SMALL).unwrap());
    }
    fn with_weights(dir: &Directory) -> PathBuf {
        let graph = dir.0.join(FP16);
        fs::write(&graph, crate::onnx::testing::model_with_weights()).unwrap();
        graph
    }
    fn externalized(graph: &Path) -> bool {
        !crate::onnx::has_inline_weights(graph).unwrap()
            && crate::onnx::external_data_path(graph).is_file()
    }
    #[test]
    fn a_completed_download_moves_the_graph_weights_before_the_pin() {
        let dir = Directory::new();
        establish_origin(&dir.0, SMALL).unwrap();
        dir.complete();
        let graph = with_weights(&dir);
        prepare_wolf_cache(&dir.0, SMALL, WolfPrecision::Fp16, &missing(), None).unwrap();
        assert!(externalized(&graph));
        assert_eq!(
            fs::read_to_string(dir.0.join(REVISION)).unwrap(),
            SMALL.spec().revision
        );
    }
    #[test]
    fn a_managed_cache_moves_its_graph_weights_once_and_local_bundles_keep_theirs() {
        let managed = Directory::new();
        managed.complete();
        let graph = with_weights(&managed);
        fs::write(managed.0.join(REVISION), SMALL.spec().revision).unwrap();
        fs::write(managed.0.join(LOCK), b"").unwrap();
        // Offline preparation of a cache prepared before the rewrite existed.
        let offline = WarmupOptions::default();
        prepare_wolf_cache(&managed.0, SMALL, WolfPrecision::Fp16, &offline, None).unwrap();
        assert!(externalized(&graph));
        let rewritten = fs::read(&graph).unwrap();
        prepare_wolf_cache(&managed.0, SMALL, WolfPrecision::Fp16, &offline, None).unwrap();
        assert_eq!(fs::read(&graph).unwrap(), rewritten);
        assert!(wolf_assets_present(&managed.0, SMALL, WolfPrecision::Fp16).unwrap());

        // An unmanaged local bundle, which a supplied manifest may pin, is never rewritten.
        let local = Directory::new();
        local.complete();
        let graph = with_weights(&local);
        prepare_wolf_cache(&local.0, SMALL, WolfPrecision::Fp16, &missing(), None).unwrap();
        assert!(crate::onnx::has_inline_weights(&graph).unwrap());
        assert!(!crate::onnx::external_data_path(&graph).exists());
    }
    #[test]
    fn a_managed_cache_with_a_supplied_manifest_keeps_the_pinned_graph_inline() {
        let dir = Directory::new();
        dir.complete();
        let graph = with_weights(&dir);
        fs::write(dir.0.join(REVISION), SMALL.spec().revision).unwrap();
        fs::write(dir.0.join(LOCK), b"").unwrap();
        let blake3 = |path: &str| blake3::hash(&fs::read(dir.0.join(path)).unwrap()).to_hex();
        let manifest = serde_json::json!({
            "schema_version": 1, "model_id": SMALL.spec().id, "revision": "pinned",
            "precision": "fp16",
            "model": {"path": FP16, "blake3": blake3(FP16).as_str()},
            "tokenizer": {"path": "tokenizer.mmbpe", "blake3": blake3("tokenizer.mmbpe").as_str()},
            "content_tokens": 254, "sequence_tokens": 256, "pad_id": 0,
            "output_name": "logits", "output": "scalar", "reference": "synthetic",
            "parity_cases": [{"token_ids": [], "expected_logit": 0.0}], "logit_tolerance": 0.02
        });
        fs::write(dir.0.join("wolf.manifest.json"), manifest.to_string()).unwrap();
        let pinned = fs::read(&graph).unwrap();
        prepare_wolf_cache(
            &dir.0,
            SMALL,
            WolfPrecision::Fp16,
            &WarmupOptions::default(),
            None,
        )
        .unwrap();
        // The manifest pins the graph as published: it stays inline and keeps its hash.
        assert_eq!(fs::read(&graph).unwrap(), pinned);
        assert!(!crate::onnx::external_data_path(&graph).exists());
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
        assert!(!wolf_assets_present(&dir.0, SMALL, WolfPrecision::Fp16).unwrap());
        let options = WarmupOptions {
            download_timeout_ms: 30,
            ..Default::default()
        };
        assert!(
            prepare_wolf_cache(&dir.0, SMALL, WolfPrecision::Fp16, &options, None)
                .unwrap_err()
                .to_string()
                .contains("deadline")
        );
        drop(lock);
        prepare_wolf_cache(&dir.0, SMALL, WolfPrecision::Fp16, &options, None).unwrap();
    }
}
