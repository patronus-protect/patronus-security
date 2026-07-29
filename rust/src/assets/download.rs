// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use rayon::prelude::*;

use crate::{
    SecurityAssetProgress, SecurityAssetProgressCallback, SecurityCategory, SecurityLevel,
};

use crate::ml::ntdb_executor::manifest::PackageManifest;

use super::{
    compact_tokenizer::ensure_granite_compact_tokenizer,
    mmbert_tokenizer::ensure_mmbert_compact_tokenizer,
    specs::{
        AssetSpec, NtdbL2PackageAssetSpec, PipelineModelAssetSpec, ASSET_MANIFEST,
        DEDICATED_L3_ASSETS, DYNAMIC_PII_ASSET, NTDB_L2_PACKAGE_MANIFEST, UNIFIED_L3_ASSET,
    },
};

#[derive(Clone)]
struct SharedEmbedderFile {
    relative_path: String,
    shared_file: PathBuf,
    package_file: PathBuf,
}

const ASSET_DOWNLOAD_CONCURRENCY: usize = 6;

fn download_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| ureq::AgentBuilder::new().build())
}

fn asset_download_pool() -> &'static rayon::ThreadPool {
    static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();
    POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(ASSET_DOWNLOAD_CONCURRENCY)
            .thread_name(|index| format!("patronus-ark-asset-download-{index}"))
            .build()
            .expect("failed to create Patronus Ark asset download pool")
    })
}

fn run_downloads_in_parallel<T, F>(
    items: &[T],
    progress: Option<&SecurityAssetProgressCallback>,
    category: SecurityCategory,
    model: &str,
    completed_files: usize,
    total_files: usize,
    download: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    T: Sync,
    F: Fn(&T) -> Result<(), String> + Send + Sync,
{
    if let Some(callback) = progress {
        callback(SecurityAssetProgress {
            category,
            model: model.to_string(),
            completed_files,
            total_files,
        });
    }
    let completed = Mutex::new(completed_files);
    let result: Result<(), String> = asset_download_pool().install(|| {
        items.par_iter().try_for_each(|item| {
            download(item)?;
            if let Some(callback) = progress {
                let mut completed = completed
                    .lock()
                    .map_err(|error| format!("asset progress lock poisoned: {error}"))?;
                *completed += 1;
                callback(SecurityAssetProgress {
                    category,
                    model: model.to_string(),
                    completed_files: *completed,
                    total_files,
                });
            }
            Ok(())
        })
    });
    result.map_err(Into::into)
}

/// Return manifest entries needed for a category up to `max_level`.
pub fn category_assets(category: SecurityCategory, max_level: SecurityLevel) -> Vec<AssetSpec> {
    ASSET_MANIFEST
        .iter()
        .copied()
        .filter(|asset| asset.category == category && asset.level <= max_level)
        .collect()
}

/// Return NTDB v2 L2 package entries needed for a category up to `max_level`.
pub fn ntdb_l2_package_assets(
    category: SecurityCategory,
    max_level: SecurityLevel,
) -> Vec<NtdbL2PackageAssetSpec> {
    NTDB_L2_PACKAGE_MANIFEST
        .iter()
        .copied()
        .filter(|asset| asset.category == category && asset.level <= max_level)
        .collect()
}

/// Return the NTDB v2 L2 package entry for a public model name.
pub fn ntdb_l2_package_asset(
    category: SecurityCategory,
    max_level: SecurityLevel,
    model: &str,
) -> Option<NtdbL2PackageAssetSpec> {
    ntdb_l2_package_assets(category, max_level)
        .into_iter()
        .find(|asset| asset.model == model)
}

/// Check whether all required assets for a category are present in `target_dir`.
pub fn required_assets_present(
    category: SecurityCategory,
    max_level: SecurityLevel,
    target_dir: &Path,
) -> bool {
    category_assets(category, max_level)
        .into_iter()
        .filter(|asset| asset.required)
        .all(|asset| target_dir.join(asset.destination_path).exists())
}

/// Check whether the complete revision-pinned `dynamic-pii` model is cached.
pub fn dynamic_pii_assets_present(target_dir: &Path) -> bool {
    pipeline_model_assets_present(DYNAMIC_PII_ASSET, target_dir)
}

/// Download the revision-pinned `dynamic-pii` GLiNER bundle.
pub fn download_dynamic_pii_assets(
    target_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    download_pipeline_model_assets(DYNAMIC_PII_ASSET, target_dir, None)
}

pub(crate) fn download_dynamic_pii_assets_with_progress(
    target_dir: &Path,
    progress: &SecurityAssetProgressCallback,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    download_pipeline_model_assets(DYNAMIC_PII_ASSET, target_dir, Some(progress))
}

/// Check whether the complete revision-pinned unified L3 model is cached.
pub fn unified_l3_assets_present(target_dir: &Path) -> bool {
    pipeline_model_assets_present(UNIFIED_L3_ASSET, target_dir)
}

/// Download the revision-pinned unified L3 bundle.
pub fn download_unified_l3_assets(
    target_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    download_pipeline_model_assets(UNIFIED_L3_ASSET, target_dir, None)
}

pub(crate) fn download_unified_l3_assets_with_progress(
    target_dir: &Path,
    progress: &SecurityAssetProgressCallback,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    download_pipeline_model_assets(UNIFIED_L3_ASSET, target_dir, Some(progress))
}

/// Return the revision-pinned dedicated L3 bundle for a classifier category.
pub fn dedicated_l3_asset(category: SecurityCategory) -> Option<PipelineModelAssetSpec> {
    DEDICATED_L3_ASSETS
        .iter()
        .copied()
        .find(|asset| asset.category == category)
}

/// Check whether a category's dedicated L3 bundle is cached.
pub fn dedicated_l3_assets_present(category: SecurityCategory, target_dir: &Path) -> bool {
    dedicated_l3_asset(category)
        .is_none_or(|asset| pipeline_model_assets_present(asset, target_dir))
}

/// Download a category's revision-pinned dedicated L3 bundle when it has one.
pub fn download_dedicated_l3_assets(
    category: SecurityCategory,
    target_dir: &Path,
) -> Result<Option<PathBuf>, Box<dyn std::error::Error>> {
    dedicated_l3_asset(category)
        .map(|asset| download_pipeline_model_assets(asset, target_dir, None))
        .transpose()
}

fn pipeline_model_assets_present(asset: PipelineModelAssetSpec, target_dir: &Path) -> bool {
    let bundle_dir = target_dir.join(asset.destination_path);
    bundle_revision_matches(&bundle_dir, asset.revision)
        && asset
            .files
            .iter()
            .all(|file| bundle_dir.join(file).is_file())
}

fn download_pipeline_model_assets(
    asset: PipelineModelAssetSpec,
    target_dir: &Path,
    progress: Option<&SecurityAssetProgressCallback>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let token = hf_token();
    let bundle_dir = target_dir.join(asset.destination_path);
    let revision_matches = bundle_revision_matches(&bundle_dir, asset.revision);
    let missing_files = asset
        .files
        .iter()
        .copied()
        .filter(|file| !revision_matches || !bundle_dir.join(file).is_file())
        .collect::<Vec<_>>();
    run_downloads_in_parallel(
        &missing_files,
        progress,
        asset.category,
        asset.model,
        asset.files.len() - missing_files.len(),
        asset.files.len(),
        |file| {
            download_hf_file_at_revision(
                token.as_deref(),
                asset.repo,
                asset.revision,
                file,
                &bundle_dir.join(file),
                true,
                asset.model,
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
        },
    )?;
    fs::write(bundle_dir.join(".patronus-revision"), asset.revision)?;
    prepare_pipeline_model_compact_tokenizer(asset, &bundle_dir);
    Ok(bundle_dir)
}

pub(crate) fn prepare_cached_pipeline_model_compact_tokenizer(
    asset: PipelineModelAssetSpec,
    target_dir: &Path,
) {
    let bundle_dir = target_dir.join(asset.destination_path);
    if pipeline_model_assets_present(asset, target_dir) {
        prepare_pipeline_model_compact_tokenizer(asset, &bundle_dir);
    }
}

fn prepare_pipeline_model_compact_tokenizer(asset: PipelineModelAssetSpec, bundle_dir: &Path) {
    let tokenizer_json = bundle_dir.join("tokenizer.json");
    if !tokenizer_json.is_file() {
        return;
    }
    if let Err(err) = ensure_mmbert_compact_tokenizer(asset.model, &tokenizer_json) {
        log::warn!(
            "failed to prepare compact mmBERT tokenizer for {} at {}: {err}; tokenizer.json remains available",
            asset.model,
            bundle_dir.display()
        );
    }
}

fn bundle_revision_matches(bundle_dir: &Path, revision: &str) -> bool {
    fs::read_to_string(bundle_dir.join(".patronus-revision"))
        .is_ok_and(|stored| stored.trim() == revision)
}

/// Download missing manifest assets for a category into `target_dir`.
///
/// Required asset failures return an error. Optional asset failures are skipped.
pub fn download_category_assets(
    category: SecurityCategory,
    max_level: SecurityLevel,
    target_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = hf_token();
    let assets = category_assets(category, max_level)
        .into_iter()
        .filter(|asset| asset.required || download_optional_assets())
        .collect::<Vec<_>>();
    let missing_assets = assets
        .iter()
        .copied()
        .filter(|asset| !target_dir.join(asset.destination_path).exists())
        .collect::<Vec<_>>();
    run_downloads_in_parallel(
        &missing_assets,
        None,
        category,
        category.as_str(),
        assets.len() - missing_assets.len(),
        assets.len(),
        |asset| {
            download_hf_file_at_revision(
                token.as_deref(),
                asset.repo,
                asset.revision.unwrap_or("main"),
                asset.source_path,
                &target_dir.join(asset.destination_path),
                asset.required,
                &format!("L{} asset", asset.level as u8),
            )
            .map(|_| ())
            .map_err(|error| error.to_string())
        },
    )
}

/// Download a missing NTDB v2 L2 package from Hugging Face into `target_dir`.
///
/// The package is downloaded manifest-first: `manifest.json` is fetched from
/// the package prefix, then runtime files referenced by that manifest are
/// downloaded into the same local package tree.
pub fn download_ntdb_l2_package(
    category: SecurityCategory,
    max_level: SecurityLevel,
    model: &str,
    target_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let asset = ntdb_l2_package_asset(category, max_level, model).ok_or_else(|| {
        format!(
            "missing NTDB v2 L2 asset spec for {}/{}",
            category.as_str(),
            model
        )
    })?;
    download_ntdb_l2_package_asset_inner(asset, target_dir, None)
}

pub(crate) fn download_ntdb_l2_package_with_progress(
    category: SecurityCategory,
    max_level: SecurityLevel,
    model: &str,
    target_dir: &Path,
    progress: &SecurityAssetProgressCallback,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let asset = ntdb_l2_package_asset(category, max_level, model).ok_or_else(|| {
        format!(
            "missing NTDB v2 L2 asset spec for {}/{}",
            category.as_str(),
            model
        )
    })?;
    download_ntdb_l2_package_asset_inner(asset, target_dir, Some(progress))
}

enum NtdbDownloadJob {
    Shared(SharedEmbedderFile),
    Package {
        source_path: String,
        destination: PathBuf,
    },
}

fn download_ntdb_l2_package_asset_inner(
    asset: NtdbL2PackageAssetSpec,
    target_dir: &Path,
    progress: Option<&SecurityAssetProgressCallback>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let token = hf_token();
    let package_dir = target_dir.join(asset.destination_path);
    let manifest_dest = package_dir.join("manifest.json");
    let manifest_source = prefixed_source_path(asset.source_prefix, "manifest.json");
    let revision_matches = bundle_revision_matches(&package_dir, asset.revision);

    if !revision_matches || !manifest_dest.exists() {
        if let Some(callback) = progress {
            callback(SecurityAssetProgress {
                category: asset.category,
                model: asset.model.to_string(),
                completed_files: 0,
                total_files: 1,
            });
        }
        download_hf_file_at_revision(
            token.as_deref(),
            asset.repo,
            asset.revision,
            &manifest_source,
            &manifest_dest,
            asset.required,
            "NTDB v2 L2 manifest",
        )?;
        if let Some(callback) = progress {
            callback(SecurityAssetProgress {
                category: asset.category,
                model: asset.model.to_string(),
                completed_files: 1,
                total_files: 1,
            });
        }
    }

    let manifest_json = fs::read_to_string(&manifest_dest).map_err(|err| {
        format!(
            "failed to read downloaded NTDB v2 L2 manifest {}: {err}",
            manifest_dest.display()
        )
    })?;
    let manifest: PackageManifest = serde_json::from_str(&manifest_json)?;
    let shared_embedder_files = ntdb_l2_shared_embedder_files(&manifest, target_dir, &package_dir)?;
    migrate_legacy_shared_embedder_files(&manifest, &shared_embedder_files)?;
    let shared_relative_paths = shared_embedder_files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect::<HashSet<_>>();

    let manifest_files = ntdb_l2_package_manifest_files_from_manifest(&manifest)?;
    let mut jobs = Vec::new();
    for file in &shared_embedder_files {
        if revision_matches && file.shared_file.exists() {
            link_shared_embedder_file(&file.shared_file, &file.package_file)?;
        } else {
            jobs.push(NtdbDownloadJob::Shared(file.clone()));
        }
    }
    for relative_path in &manifest_files {
        if shared_relative_paths.contains(relative_path) {
            continue;
        }
        let dest_file = package_dir.join(&relative_path);
        if revision_matches && dest_file.exists() {
            continue;
        }
        jobs.push(NtdbDownloadJob::Package {
            source_path: prefixed_source_path(asset.source_prefix, relative_path),
            destination: dest_file,
        });
    }

    let total_files = manifest_files.len() + 1;
    run_downloads_in_parallel(
        &jobs,
        progress,
        asset.category,
        asset.model,
        total_files - jobs.len(),
        total_files,
        |job| match job {
            NtdbDownloadJob::Shared(file) => {
                download_shared_embedder_file(token.as_deref(), asset, file)
                    .map_err(|error| error.to_string())
            }
            NtdbDownloadJob::Package {
                source_path,
                destination,
            } => download_hf_file_at_revision(
                token.as_deref(),
                asset.repo,
                asset.revision,
                source_path,
                destination,
                asset.required,
                "NTDB v2 L2 package file",
            )
            .map(|_| ())
            .map_err(|error| error.to_string()),
        },
    )?;
    fs::write(package_dir.join(".patronus-revision"), asset.revision)?;

    if let Err(err) = prepare_downloaded_compact_tokenizer(&manifest, &shared_embedder_files) {
        log::warn!(
            "failed to prepare compact tokenizer for {}: {err}; tokenizer.json remains available",
            package_dir.display()
        );
    }

    Ok(package_dir)
}

fn prepare_downloaded_compact_tokenizer(
    manifest: &PackageManifest,
    shared_embedder_files: &[SharedEmbedderFile],
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(tokenizer_file) = shared_embedder_files
        .iter()
        .find(|file| file.relative_path.ends_with("/tokenizer.json"))
    else {
        return Ok(());
    };
    prepare_compact_tokenizer(
        manifest,
        &tokenizer_file.shared_file,
        &tokenizer_file.package_file,
    )
}

/// Prepare the generated compact tokenizer for an already cached official package.
///
/// The package tokenizer is normally a link into the shared encoder cache. Resolving
/// it first keeps one generated `.kit` per shared Granite tokenizer. Local model
/// overrides are deliberately handled by the caller and are not modified here.
pub(crate) fn prepare_cached_ntdb_l2_compact_tokenizer(
    manifest: &PackageManifest,
    package_dir: &Path,
    prepared_shared_tokenizers: &mut HashSet<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let category_dir = package_dir.parent().and_then(Path::parent).ok_or_else(|| {
        format!(
            "invalid cached NTDB package path: {}",
            package_dir.display()
        )
    })?;
    let shared_embedder_files = ntdb_l2_shared_embedder_files(manifest, category_dir, package_dir)?;
    migrate_legacy_shared_embedder_files(manifest, &shared_embedder_files)?;
    let Some(tokenizer_file) = shared_embedder_files
        .iter()
        .find(|file| file.relative_path.ends_with("/tokenizer.json"))
    else {
        return Ok(());
    };
    if prepared_shared_tokenizers.contains(&tokenizer_file.shared_file) {
        for extension in ["kit", "mmbpe"] {
            let shared_compact_path = tokenizer_file
                .shared_file
                .with_file_name(format!("tokenizer.{extension}"));
            if shared_compact_path.is_file() {
                link_compact_tokenizer(
                    &shared_compact_path,
                    &tokenizer_file.package_file,
                    extension,
                )?;
            }
        }
        return Ok(());
    }
    prepare_downloaded_compact_tokenizer(manifest, &shared_embedder_files)?;
    prepared_shared_tokenizers.insert(tokenizer_file.shared_file.clone());
    Ok(())
}

fn prepare_compact_tokenizer(
    manifest: &PackageManifest,
    source_tokenizer_json: &Path,
    package_tokenizer_json: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(shared_compact_path) =
        ensure_granite_compact_tokenizer(&manifest.minilm, source_tokenizer_json)?
    else {
        let source_model = manifest
            .minilm
            .shared_embedder_identity()
            .unwrap_or("manifest-local-embedder");
        let Some(shared_compact_path) =
            ensure_mmbert_compact_tokenizer(source_model, source_tokenizer_json)?
        else {
            return Ok(());
        };
        return link_compact_tokenizer(&shared_compact_path, package_tokenizer_json, "mmbpe");
    };
    link_compact_tokenizer(&shared_compact_path, package_tokenizer_json, "kit")
}

fn link_compact_tokenizer(
    shared_compact_path: &Path,
    package_tokenizer_json: &Path,
    extension: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let package_compact_path = package_tokenizer_json
        .parent()
        .ok_or("NTDB tokenizer package path has no parent")?
        .join(format!("tokenizer.{extension}"));
    if shared_compact_path == package_compact_path {
        return Ok(());
    }
    link_shared_embedder_file(&shared_compact_path, &package_compact_path)
}

/// Return all runtime files referenced by an NTDB v2 package manifest.
pub fn ntdb_l2_package_manifest_files(
    manifest_json: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let manifest: PackageManifest = serde_json::from_str(manifest_json)?;
    ntdb_l2_package_manifest_files_from_manifest(&manifest)
}

fn ntdb_l2_package_manifest_files_from_manifest(
    manifest: &PackageManifest,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    let mut seen = HashSet::new();

    push_manifest_file(
        &mut files,
        &mut seen,
        &format!(
            "{}/tokenizer.json",
            manifest.tokenizer_dir.trim_end_matches('/')
        ),
    )?;
    push_manifest_file(
        &mut files,
        &mut seen,
        &format!("minilm/{}", manifest.minilm.embedding_matrix_file),
    )?;

    for head in &manifest.heads {
        for component in &head.static_components {
            push_manifest_file(&mut files, &mut seen, &component.path)?;
        }
        for classifier in &head.classifiers {
            collect_json_path_values(classifier, "path", &mut files, &mut seen)?;
        }
        if let Some(path) = &head.projection_onnx {
            push_manifest_file(&mut files, &mut seen, path)?;
        }
        push_manifest_file(&mut files, &mut seen, &head.ntdb_head_onnx)?;
    }

    for aggregator in &manifest.aggregators {
        push_manifest_file(&mut files, &mut seen, &aggregator.onnx)?;
        if let Some(router) = &aggregator.promote_router {
            push_manifest_file(&mut files, &mut seen, &router.onnx)?;
        }
    }

    files.sort();
    Ok(files)
}

fn ntdb_l2_shared_embedder_files(
    manifest: &PackageManifest,
    category_dir: &Path,
    package_dir: &Path,
) -> Result<Vec<SharedEmbedderFile>, Box<dyn std::error::Error>> {
    let shared_root = ntdb_l2_shared_embedder_dir(category_dir, manifest);
    let tokenizer_path = normalize_manifest_file_path(&format!(
        "{}/tokenizer.json",
        manifest.tokenizer_dir.trim_end_matches('/')
    ))?;
    let embedding_path =
        normalize_manifest_file_path(&format!("minilm/{}", manifest.minilm.embedding_matrix_file))?;

    Ok([tokenizer_path, embedding_path]
        .into_iter()
        .map(|relative_path| SharedEmbedderFile {
            shared_file: shared_root.join(&relative_path),
            package_file: package_dir.join(&relative_path),
            relative_path,
        })
        .collect())
}

fn ntdb_l2_shared_embedder_dir(category_dir: &Path, manifest: &PackageManifest) -> PathBuf {
    let model_root = category_dir.parent().unwrap_or(category_dir);
    model_root
        .join("l2_ntdb")
        .join("_shared")
        .join("encoders")
        .join(shared_embedder_dir_name(manifest))
}

fn shared_embedder_dir_name(manifest: &PackageManifest) -> String {
    let identity = manifest
        .minilm
        .shared_embedder_identity()
        .unwrap_or("manifest-local-embedder");
    format!(
        "{}__v{}_d{}",
        sanitize_shared_embedder_identity(identity),
        manifest.minilm.vocab_size,
        manifest.minilm.embedding_dim
    )
}

fn migrate_legacy_shared_embedder_files(
    manifest: &PackageManifest,
    files: &[SharedEmbedderFile],
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(shared_root) = files
        .first()
        .and_then(|file| file.shared_file.parent())
        .and_then(Path::parent)
    else {
        return Ok(());
    };
    let Some(encoders_dir) = shared_root.parent() else {
        return Ok(());
    };
    let Some(shared_name) = shared_root.file_name().and_then(|name| name.to_str()) else {
        return Ok(());
    };
    let mut legacy_names = vec![shared_name.to_string()];
    if let Some(source_identity) = manifest.minilm.source_model_path.as_deref() {
        let source_name = format!(
            "{}__v{}_d{}",
            sanitize_shared_embedder_identity(source_identity),
            manifest.minilm.vocab_size,
            manifest.minilm.embedding_dim
        );
        if source_name != shared_name {
            legacy_names.push(source_name);
        }
    }
    let current_legacy_name = format!(
        "{shared_name}_c{}",
        manifest.minilm.content_tokens_per_chunk
    );
    let mut legacy_roots = Vec::new();
    if encoders_dir.is_dir() {
        for entry in fs::read_dir(encoders_dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let is_legacy = legacy_names.iter().any(|legacy_name| {
                if name == legacy_name {
                    return name != shared_name;
                }
                name.strip_prefix(&format!("{legacy_name}_c"))
                    .is_some_and(|chunk| chunk.parse::<usize>().is_ok())
            });
            if is_legacy {
                legacy_roots.push((name != current_legacy_name, name.to_string(), entry.path()));
            }
        }
    }
    legacy_roots.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));

    let mut migration_files = files.to_vec();
    if let Some(tokenizer) = files
        .iter()
        .find(|file| file.relative_path.ends_with("/tokenizer.json"))
    {
        for name in [
            "tokenizer.kit",
            "tokenizer.kit.meta.json",
            "tokenizer.mmbpe",
            "tokenizer.mmbpe.meta.json",
        ] {
            migration_files.push(SharedEmbedderFile {
                relative_path: tokenizer.relative_path.replace("tokenizer.json", name),
                shared_file: tokenizer.shared_file.with_file_name(name),
                package_file: tokenizer.package_file.with_file_name(name),
            });
        }
    }

    for file in &migration_files {
        let legacy_files = legacy_roots
            .iter()
            .map(|(_, _, root)| root.join(&file.relative_path))
            .filter(|path| path.is_file())
            .collect::<Vec<_>>();
        let mut candidates = Vec::with_capacity(legacy_files.len() + 2);
        if file.shared_file.is_file() {
            candidates.push(file.shared_file.clone());
        }
        candidates.extend(legacy_files.iter().cloned());
        if file.package_file.is_file() {
            candidates.push(file.package_file.clone());
        }
        let Some(reference) = candidates.first() else {
            continue;
        };
        for candidate in candidates.iter().skip(1) {
            if !same_cached_file(reference, candidate)? {
                return Err(format!(
                    "conflicting cached NTDB shared embedder files for {}: {} and {}",
                    file.relative_path,
                    reference.display(),
                    candidate.display()
                )
                .into());
            }
        }

        if !file.shared_file.is_file() {
            clone_cached_file(reference, &file.shared_file)?;
        }
        for legacy_file in legacy_files {
            link_shared_embedder_file(&file.shared_file, &legacy_file)?;
        }
        if file.shared_file.is_file() {
            link_shared_embedder_file(&file.shared_file, &file.package_file)?;
        }
    }
    Ok(())
}

fn same_cached_file(left: &Path, right: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    if fs::canonicalize(left)? == fs::canonicalize(right)? {
        return Ok(true);
    }
    if fs::metadata(left)?.len() != fs::metadata(right)?.len() {
        return Ok(false);
    }
    Ok(blake3_file(left)? == blake3_file(right)?)
}

fn blake3_file(path: &Path) -> Result<blake3::Hash, Box<dyn std::error::Error>> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(File::open(path)?)?;
    Ok(hasher.finalize())
}

fn clone_cached_file(source: &Path, destination: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let source = fs::canonicalize(source)?;
    match fs::hard_link(&source, destination) {
        Ok(()) => Ok(()),
        Err(_) => {
            fs::copy(source, destination)?;
            Ok(())
        }
    }
}

fn sanitize_shared_embedder_identity(identity: &str) -> String {
    let sanitized = identity
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>()
        .trim_matches('_')
        .to_string();
    if sanitized.is_empty() {
        "manifest-local-embedder".to_string()
    } else {
        sanitized
    }
}

fn download_shared_embedder_file(
    token: Option<&str>,
    asset: NtdbL2PackageAssetSpec,
    file: &SharedEmbedderFile,
) -> Result<(), Box<dyn std::error::Error>> {
    let source_path = prefixed_source_path(asset.source_prefix, &file.relative_path);
    download_hf_file_at_revision(
        token,
        asset.repo,
        asset.revision,
        &source_path,
        &file.shared_file,
        asset.required,
        "NTDB v2 shared L2 embedder file",
    )?;
    link_shared_embedder_file(&file.shared_file, &file.package_file)
}

fn link_shared_embedder_file(
    shared_file: &Path,
    package_file: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = package_file.parent() {
        fs::create_dir_all(parent)?;
    }
    if fs::symlink_metadata(package_file).is_ok() {
        fs::remove_file(package_file)?;
    }
    symlink_or_link_file(shared_file, package_file)
}

#[cfg(unix)]
fn symlink_or_link_file(source: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::os::unix::fs::symlink(source, dest)?;
    Ok(())
}

#[cfg(windows)]
fn symlink_or_link_file(source: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    match fs::hard_link(source, dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::os::windows::fs::symlink_file(source, dest)?;
            Ok(())
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn symlink_or_link_file(source: &Path, dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::hard_link(source, dest)?;
    Ok(())
}

fn collect_json_path_values(
    value: &serde_json::Value,
    key: &str,
    files: &mut Vec<String>,
    seen: &mut HashSet<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    match value {
        serde_json::Value::Object(map) => {
            for (current_key, nested_value) in map {
                if current_key == key {
                    if let Some(path) = nested_value.as_str() {
                        push_manifest_file(files, seen, path)?;
                    }
                }
                collect_json_path_values(nested_value, key, files, seen)?;
            }
        }
        serde_json::Value::Array(values) => {
            for nested_value in values {
                collect_json_path_values(nested_value, key, files, seen)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn push_manifest_file(
    files: &mut Vec<String>,
    seen: &mut HashSet<String>,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = normalize_manifest_file_path(path)?;
    if seen.insert(path.clone()) {
        files.push(path);
    }
    Ok(())
}

fn normalize_manifest_file_path(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed.contains("://") {
        return Err(format!("invalid NTDB manifest file path: {path:?}").into());
    }

    let mut parts = Vec::new();
    for component in Path::new(trimmed).components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(format!("invalid NTDB manifest file path: {path:?}").into())
            }
        }
    }

    if parts.is_empty() {
        return Err(format!("invalid NTDB manifest file path: {path:?}").into());
    }
    Ok(parts.join("/"))
}

fn prefixed_source_path(prefix: &str, relative_path: &str) -> String {
    let prefix = prefix.trim_matches('/');
    if prefix.is_empty() {
        relative_path.to_string()
    } else {
        format!("{prefix}/{}", relative_path.trim_start_matches('/'))
    }
}

fn download_hf_file_at_revision(
    token: Option<&str>,
    repo: &str,
    revision: &str,
    source_path: &str,
    dest_file: &Path,
    required: bool,
    label: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some(parent) = dest_file.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_url = format!("https://huggingface.co/{repo}/resolve/{revision}/{source_path}");

    log::info!(
        "Downloading {label} {source_path} from Hugging Face -> {:?}",
        dest_file
    );

    let mut request = download_agent().get(&file_url);
    if let Some(tk) = token {
        request = request.set("Authorization", &format!("Bearer {}", tk));
    }

    let response = match request.call() {
        Ok(resp) => resp,
        Err(e) if !required => {
            log::warn!("optional asset {} unavailable: {}", file_url, e);
            return Ok(false);
        }
        Err(e) => return Err(format!("Request to {} failed: {}", file_url, e).into()),
    };

    if response.status() != 200 {
        if required {
            return Err(format!(
                "Failed to download {}: HTTP {}",
                file_url,
                response.status()
            )
            .into());
        }
        log::info!(
            "Optional asset {} returned HTTP {}",
            file_url,
            response.status()
        );
        return Ok(false);
    }

    let mut reader = response.into_reader();
    let mut out_file = File::create(dest_file)?;
    io::copy(&mut reader, &mut out_file)?;
    Ok(true)
}

fn hf_token() -> Option<String> {
    std::env::var("HF_TOKEN")
        .ok()
        .or_else(|| std::env::var("HUGGINGFACE_HUB_TOKEN").ok())
        .or_else(|| std::env::var("HUGGING_FACE_HUB_TOKEN").ok())
        .or_else(read_hf_token_file)
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
}

fn download_optional_assets() -> bool {
    std::env::var("PATRONUS_DOWNLOAD_OPTIONAL_ASSETS").as_deref() == Ok("1")
}

fn read_hf_token_file() -> Option<String> {
    let path = hf_token_path()?;
    fs::read_to_string(path).ok()
}

fn hf_token_path() -> Option<PathBuf> {
    if let Ok(hf_home) = std::env::var("HF_HOME") {
        return Some(PathBuf::from(hf_home).join("token"));
    }
    dirs::home_dir().map(|home| home.join(".cache").join("huggingface").join("token"))
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Arc, Mutex,
        },
        thread,
        time::Duration,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;
    use crate::assets::compact_tokenizer::ensure_granite_compact_tokenizer_with;

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "patronus_ntdb_download_{name}_{}_{}",
            std::process::id(),
            suffix
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn manifest_json(identity: &str) -> String {
        format!(
            r#"{{
                "format": "ntdb_model_package",
                "version": 2,
                "runtime_contract": "raw_text_to_ntdb_outputs",
                "task": {{"type": "binary", "labels": ["benign", "attack"]}},
                "chunk_size": 2,
                "tokenizer_dir": "tokenizer",
                "minilm": {{
                    "embedding_matrix_file": "embedding_matrix.f16",
                    "vocab_size": 1,
                    "embedding_dim": 1,
                    "content_tokens_per_chunk": 2,
                    "source_model_path": "{identity}",
                    "model": "ibm-granite/granite-embedding-97m-multilingual-r2",
                    "tokenizer_family": "ModernBERT"
                }},
                "feature_contract": {{
                    "local_feature_order": [],
                    "global_feature_order": []
                }},
                "runtime": {{
                    "shared_preprocessing": ["tokenization"],
                    "parallel_stages": [],
                    "ordering": "manifest_order"
                }},
                "heads": [{{
                    "id": "h",
                    "type": "binary",
                    "task": {{"type": "binary", "labels": ["other", "target"]}},
                    "classifiers": [],
                    "feature_order": [],
                    "static_dir": "heads/h",
                    "static_components": [],
                    "projection_onnx": null,
                    "ntdb_head_onnx": "heads/h/ntdb_head.onnx",
                    "model_type": "sequential_ntdb",
                    "reliability": {{
                        "enabled": false,
                        "hidden_dim": 0,
                        "execution": "inside_onnx_model"
                    }}
                }}],
                "aggregators": [{{
                    "id": "main",
                    "type": "binary_sequential_aggregator",
                    "task": {{"type": "binary", "labels": ["benign", "attack"]}},
                    "onnx": "aggregators/main/aggregator.onnx",
                    "model_type": "sequential_ntdb",
                    "input_feature_order": [],
                    "global_feature_order": [],
                    "reliability": {{
                        "enabled": false,
                        "hidden_dim": 0,
                        "execution": "inside_onnx_model"
                    }}
                }}]
            }}"#
        )
    }

    #[test]
    fn download_agent_is_reused() {
        assert!(std::ptr::eq(download_agent(), download_agent()));
    }

    #[test]
    fn asset_downloads_are_parallel_but_bounded_and_report_progress() {
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let reported = Arc::new(Mutex::new(Vec::new()));
        let callback_reported = reported.clone();
        let progress: SecurityAssetProgressCallback = Arc::new(move |progress| {
            callback_reported.lock().unwrap().push(progress);
        });
        let items = (0..12).collect::<Vec<_>>();
        let task_active = active.clone();
        let task_maximum = maximum.clone();

        run_downloads_in_parallel(
            &items,
            Some(&progress),
            SecurityCategory::Injection,
            "test-model",
            0,
            items.len(),
            move |_| {
                let current = task_active.fetch_add(1, Ordering::SeqCst) + 1;
                task_maximum.fetch_max(current, Ordering::SeqCst);
                thread::sleep(Duration::from_millis(10));
                task_active.fetch_sub(1, Ordering::SeqCst);
                Ok(())
            },
        )
        .unwrap();

        assert!(maximum.load(Ordering::SeqCst) > 1);
        assert!(maximum.load(Ordering::SeqCst) <= ASSET_DOWNLOAD_CONCURRENCY);
        let reported = reported.lock().unwrap();
        assert_eq!(reported.first().unwrap().completed_files, 0);
        assert_eq!(reported.last().unwrap().completed_files, items.len());
        assert!(reported
            .iter()
            .all(|progress| progress.total_files == items.len()));
    }

    #[test]
    fn ntdb_l2_shared_embedder_files_use_model_root_and_manifest_identity() {
        let root = temp_dir("shared_paths");
        let category_dir = root.join("injection");
        let package_dir = category_dir.join("l2_ntdb/injection_current");
        let manifest: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();

        let files = ntdb_l2_shared_embedder_files(&manifest, &category_dir, &package_dir).unwrap();
        let shared_dir = root
            .join("l2_ntdb/_shared/encoders")
            .join("ibm-granite_granite-embedding-97m-multilingual-r2__v1_d1");

        assert_eq!(
            files
                .iter()
                .map(|file| file.relative_path.as_str())
                .collect::<Vec<_>>(),
            vec!["tokenizer/tokenizer.json", "minilm/embedding_matrix.f16"]
        );
        assert_eq!(
            files[0].shared_file,
            shared_dir.join("tokenizer/tokenizer.json")
        );
        assert_eq!(
            files[1].shared_file,
            shared_dir.join("minilm/embedding_matrix.f16")
        );
        assert_eq!(
            files[0].package_file,
            package_dir.join("tokenizer/tokenizer.json")
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_embedder_directory_uses_canonical_model_over_export_path() {
        let root = temp_dir("canonical_shared_path");
        let category_dir = root.join("injection");
        let exported: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();
        let canonical: PackageManifest = serde_json::from_str(&manifest_json(
            "ibm-granite/granite-embedding-97m-multilingual-r2",
        ))
        .unwrap();

        assert_eq!(
            ntdb_l2_shared_embedder_dir(&category_dir, &exported),
            ntdb_l2_shared_embedder_dir(&category_dir, &canonical)
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn migrates_export_path_encoder_alias_to_canonical_model_cache() {
        let root = temp_dir("export_path_alias");
        let category_dir = root.join("injection");
        let package_dir = category_dir.join("l2_ntdb/injection_current");
        let manifest: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();
        let files = ntdb_l2_shared_embedder_files(&manifest, &category_dir, &package_dir).unwrap();
        let legacy_root = root
            .join("l2_ntdb/_shared/encoders")
            .join("ntdb_artifacts_granite_embedding_97m__v1_d1");
        fs::create_dir_all(legacy_root.join("tokenizer")).unwrap();
        fs::create_dir_all(legacy_root.join("minilm")).unwrap();
        fs::write(legacy_root.join("tokenizer/tokenizer.json"), "tokenizer").unwrap();
        fs::write(legacy_root.join("minilm/embedding_matrix.f16"), "matrix").unwrap();

        migrate_legacy_shared_embedder_files(&manifest, &files).unwrap();

        for file in &files {
            let legacy_file = legacy_root.join(&file.relative_path);
            assert!(file.shared_file.is_file());
            assert_eq!(
                fs::canonicalize(legacy_file).unwrap(),
                fs::canonicalize(&file.shared_file).unwrap()
            );
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_embedder_directory_does_not_depend_on_chunk_size() {
        let root = temp_dir("chunk_independent_shared_path");
        let category_dir = root.join("injection");
        let first: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();
        let mut second: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();
        second.chunk_size = 384;
        second.minilm.content_tokens_per_chunk = 384;

        assert_eq!(
            ntdb_l2_shared_embedder_dir(&category_dir, &first),
            ntdb_l2_shared_embedder_dir(&category_dir, &second)
        );

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn migrates_identical_chunk_keyed_encoder_files_to_one_shared_copy() {
        let root = temp_dir("legacy_chunk_keys");
        let category_dir = root.join("injection");
        let package_dir = category_dir.join("l2_ntdb/injection_current");
        let manifest: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();
        let files = ntdb_l2_shared_embedder_files(&manifest, &category_dir, &package_dir).unwrap();
        let encoders_dir = root.join("l2_ntdb/_shared/encoders");
        let legacy_roots = [
            encoders_dir.join("ibm-granite_granite-embedding-97m-multilingual-r2__v1_d1_c2"),
            encoders_dir.join("ibm-granite_granite-embedding-97m-multilingual-r2__v1_d1_c384"),
        ];
        for legacy_root in &legacy_roots {
            fs::create_dir_all(legacy_root.join("tokenizer")).unwrap();
            fs::create_dir_all(legacy_root.join("minilm")).unwrap();
            fs::write(legacy_root.join("tokenizer/tokenizer.json"), "tokenizer").unwrap();
            fs::write(legacy_root.join("tokenizer/tokenizer.kit"), "compact").unwrap();
            fs::write(
                legacy_root.join("tokenizer/tokenizer.kit.meta.json"),
                "metadata",
            )
            .unwrap();
            fs::write(legacy_root.join("minilm/embedding_matrix.f16"), "matrix").unwrap();
        }

        migrate_legacy_shared_embedder_files(&manifest, &files).unwrap();

        for file in &files {
            assert!(file.shared_file.is_file());
            for legacy_root in &legacy_roots {
                let legacy_file = legacy_root.join(&file.relative_path);
                assert_eq!(
                    fs::canonicalize(legacy_file).unwrap(),
                    fs::canonicalize(&file.shared_file).unwrap()
                );
            }
        }
        for relative_path in [
            "tokenizer/tokenizer.kit",
            "tokenizer/tokenizer.kit.meta.json",
        ] {
            let shared_file = root
                .join("l2_ntdb/_shared/encoders")
                .join("ibm-granite_granite-embedding-97m-multilingual-r2__v1_d1")
                .join(relative_path);
            assert!(shared_file.is_file());
            for legacy_root in &legacy_roots {
                assert_eq!(
                    fs::canonicalize(legacy_root.join(relative_path)).unwrap(),
                    fs::canonicalize(&shared_file).unwrap()
                );
            }
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_conflicting_files_for_the_same_shared_encoder_identity() {
        let root = temp_dir("conflicting_legacy_chunk_keys");
        let category_dir = root.join("injection");
        let package_dir = category_dir.join("l2_ntdb/injection_current");
        let manifest: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();
        let files = ntdb_l2_shared_embedder_files(&manifest, &category_dir, &package_dir).unwrap();
        let encoders_dir = root.join("l2_ntdb/_shared/encoders");
        let first = encoders_dir
            .join("ibm-granite_granite-embedding-97m-multilingual-r2__v1_d1_c2/minilm/embedding_matrix.f16");
        let second = encoders_dir
            .join("ibm-granite_granite-embedding-97m-multilingual-r2__v1_d1_c384/minilm/embedding_matrix.f16");
        fs::create_dir_all(first.parent().unwrap()).unwrap();
        fs::create_dir_all(second.parent().unwrap()).unwrap();
        fs::write(&first, "first").unwrap();
        fs::write(&second, "other").unwrap();

        let error = migrate_legacy_shared_embedder_files(&manifest, &files).unwrap_err();

        assert!(error
            .to_string()
            .contains("conflicting cached NTDB shared embedder files"));
        assert!(!files[1].shared_file.exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn link_shared_embedder_file_replaces_package_copy_with_symlink() {
        let root = temp_dir("shared_link");
        let shared_file = root.join("shared/tokenizer/tokenizer.json");
        let package_file = root.join("package/tokenizer/tokenizer.json");
        fs::create_dir_all(shared_file.parent().unwrap()).unwrap();
        fs::create_dir_all(package_file.parent().unwrap()).unwrap();
        fs::write(&shared_file, "shared").unwrap();
        fs::write(&package_file, "package-copy").unwrap();

        link_shared_embedder_file(&shared_file, &package_file).unwrap();

        assert_eq!(fs::read_link(&package_file).unwrap(), shared_file);
        assert_eq!(fs::read_to_string(&package_file).unwrap(), "shared");

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn downloaded_granite_package_links_generated_shared_kit_tokenizer() {
        let root = temp_dir("compact_link");
        let category_dir = root.join("injection");
        let package_dir = category_dir.join("l2_ntdb/injection_current");
        let manifest: PackageManifest = serde_json::from_str(&manifest_json(
            "ntdb/artifacts/granite_embedding_97m_multilingual_r2",
        ))
        .unwrap();
        let files = ntdb_l2_shared_embedder_files(&manifest, &category_dir, &package_dir).unwrap();
        let tokenizer_file = files
            .iter()
            .find(|file| file.relative_path.ends_with("/tokenizer.json"))
            .unwrap();
        fs::create_dir_all(tokenizer_file.shared_file.parent().unwrap()).unwrap();
        fs::write(
            &tokenizer_file.shared_file,
            br#"{"model":"test-tokenizer"}"#,
        )
        .unwrap();
        fn fake_converter(
            source: &Path,
            destination: &Path,
        ) -> crate::ml::ntdb_executor::NtdbResult<()> {
            fs::write(destination, blake3::hash(&fs::read(source)?).as_bytes())?;
            Ok(())
        }
        ensure_granite_compact_tokenizer_with(
            &manifest.minilm,
            &tokenizer_file.shared_file,
            fake_converter,
        )
        .unwrap();

        prepare_downloaded_compact_tokenizer(&manifest, &files).unwrap();

        let shared_kit = tokenizer_file
            .shared_file
            .parent()
            .unwrap()
            .join("tokenizer.kit");
        let package_kit = tokenizer_file
            .package_file
            .parent()
            .unwrap()
            .join("tokenizer.kit");
        assert!(shared_kit.is_file());
        assert_eq!(
            fs::read(&package_kit).unwrap(),
            fs::read(&shared_kit).unwrap()
        );
        assert!(shared_kit
            .parent()
            .unwrap()
            .join("tokenizer.kit.meta.json")
            .is_file());

        fs::remove_dir_all(root).unwrap();
    }

    fn write_supported_mmbpe_tokenizer(path: &Path) {
        let mut vocab = serde_json::Map::new();
        vocab.insert("<bos>".to_string(), 0.into());
        vocab.insert("<eos>".to_string(), 1.into());
        vocab.insert("<unk>".to_string(), 2.into());
        vocab.insert("▁".to_string(), 3.into());
        for byte in 0..=255 {
            vocab.insert(format!("<{byte:#04X}>"), (byte + 10).into());
        }
        let value = serde_json::json!({
            "added_tokens": [
                {"id": 0, "content": "<bos>", "lstrip": false},
                {"id": 1, "content": "<eos>", "lstrip": false}
            ],
            "model": {
                "type": "BPE",
                "byte_fallback": true,
                "vocab": vocab,
                "merges": []
            }
        });
        fs::write(path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
    }

    #[test]
    fn pipeline_model_prepare_generates_mmbpe_tokenizer() {
        let root = temp_dir("pipeline_mmbpe");
        let bundle_dir = root.join("pipeline");
        fs::create_dir_all(&bundle_dir).unwrap();
        write_supported_mmbpe_tokenizer(&bundle_dir.join("tokenizer.json"));
        let asset = PipelineModelAssetSpec {
            category: SecurityCategory::Injection,
            model: "mmbert-test",
            repo: "example/repo",
            revision: "rev",
            destination_path: "pipeline",
            files: &["tokenizer.json"],
        };

        prepare_pipeline_model_compact_tokenizer(asset, &bundle_dir);

        assert!(bundle_dir.join("tokenizer.mmbpe").is_file());
        assert!(bundle_dir.join("tokenizer.mmbpe.meta.json").is_file());

        fs::remove_dir_all(root).unwrap();
    }
}
