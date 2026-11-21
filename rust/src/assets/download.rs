// SPDX-License-Identifier: GPL-3.0-only
//! Ark's model table on Core's model mechanism: Core resolves, checks, fetches and
//! prepares each registered [`ModelSpec`]; this module keeps Ark's file selection,
//! the NTDB manifest-first package layout and its shared embedder links.
use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};

use patronus_ark_core::model_assets::{fetch_files, prepare_generated_files, ModelFile, Progress};

use crate::{
    SecurityAssetProgress, SecurityAssetProgressCallback, SecurityCategory, SecurityLevel,
};

use crate::ml::ntdb_executor::manifest::PackageManifest;

use super::{
    mmbert_tokenizer::ensure_mmbert_compact_tokenizer,
    specs::{
        AssetSpec, NtdbL2PackageAssetSpec, PipelineModelAssetSpec, ASSET_MANIFEST,
        DEDICATED_L3_ASSETS, NTDB_L2_PACKAGE_MANIFEST, UNIFIED_L3_ASSET,
    },
};

#[derive(Clone)]
struct SharedEmbedderFile {
    relative_path: String,
    shared_file: PathBuf,
    package_file: PathBuf,
}

/// Report Core's `(completed, total)` file progress as one model's asset progress.
pub(crate) fn progress_reporter<'a>(
    progress: Option<&'a SecurityAssetProgressCallback>,
    category: SecurityCategory,
    model: &'a str,
) -> Option<impl Fn(usize, usize) + Send + Sync + 'a> {
    progress.map(move |progress| {
        move |completed_files, total_files| {
            progress(SecurityAssetProgress {
                category,
                model: model.to_string(),
                completed_files,
                total_files,
            })
        }
    })
}

/// Return manifest entries needed for a category up to `max_level`.
pub fn category_assets(category: SecurityCategory, max_level: SecurityLevel) -> Vec<AssetSpec> {
    ASSET_MANIFEST
        .iter()
        .copied()
        .filter(|asset| asset.category == category && asset.level <= max_level)
        .collect()
}

/// Return NTDB L2 package entries needed for a category up to `max_level`.
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

/// Return the NTDB L2 package entry for a public model name.
pub fn ntdb_l2_package_asset(
    category: SecurityCategory,
    max_level: SecurityLevel,
    model: &str,
) -> Option<NtdbL2PackageAssetSpec> {
    ntdb_l2_package_assets(category, max_level)
        .into_iter()
        .find(|asset| asset.spec.id == model)
}

/// Check whether an official NTDB L2 package cache below the model cache `root` matches
/// its pinned revision.
pub fn ntdb_l2_package_assets_present(
    category: SecurityCategory,
    max_level: SecurityLevel,
    model: &str,
    root: &Path,
) -> bool {
    ntdb_l2_package_asset(category, max_level, model).is_some_and(|asset| {
        let package_dir = asset.spec.cache_dir(root);
        let manifest_path = package_dir.join("manifest.json");
        if !manifest_path.is_file() || !asset.spec.is_current(&package_dir) {
            return false;
        }
        let Ok(manifest_json) = fs::read_to_string(manifest_path) else {
            return false;
        };
        let Ok(manifest) =
            crate::ml::ntdb_executor::manifest::parse_package_manifest(&manifest_json)
        else {
            return false;
        };
        if manifest.validate().is_err() {
            return false;
        }
        let matrix = package_dir
            .join("minilm")
            .join(&manifest.minilm.embedding_matrix_file);
        let elements = manifest.minilm.vocab_size as u64 * manifest.minilm.embedding_dim as u64;
        fs::metadata(matrix)
            .is_ok_and(|metadata| metadata.len() == elements * 2 || metadata.len() == elements * 4)
            && l3_compatible_tokenizer_matches_unified(&manifest, &package_dir, root)
    })
}

fn l3_compatible_tokenizer_matches_unified(
    manifest: &PackageManifest,
    package_dir: &Path,
    root: &Path,
) -> bool {
    if !manifest.minilm.is_l3_tokenizer_compatible() {
        return true;
    }
    let unified_tokenizer = UNIFIED_L3_ASSET.spec.cache_dir(root).join("tokenizer.json");
    if !unified_tokenizer.is_file() {
        return true;
    }
    let Ok(relative_tokenizer) = normalize_manifest_file_path(&format!(
        "{}/tokenizer.json",
        manifest.tokenizer_dir.trim_end_matches('/')
    )) else {
        return false;
    };
    let package_tokenizer = package_dir.join(relative_tokenizer);
    package_tokenizer.is_file()
        && same_cached_file(&package_tokenizer, &unified_tokenizer).unwrap_or(false)
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

/// Return the revision-pinned dedicated L3 bundle for a classifier category.
pub fn dedicated_l3_asset(category: SecurityCategory) -> Option<PipelineModelAssetSpec> {
    DEDICATED_L3_ASSETS
        .iter()
        .copied()
        .find(|asset| asset.category == category)
}

impl PipelineModelAssetSpec {
    /// The bundle files this process loads: the fp16 graph replaces the quantized one
    /// when `PATRONUS_L3_PRECISION=fp16` and the bundle has one.
    pub fn selected_files(&self) -> Vec<&'static str> {
        let fp16 = prefer_fp16_l3();
        let fp16_path = if self.files.contains(&"onnx/onnx_fp16/model_fp16.onnx") {
            Some("onnx/onnx_fp16/model_fp16.onnx")
        } else if self.files.contains(&"onnx/fp16/model_fp16.onnx") {
            Some("onnx/fp16/model_fp16.onnx")
        } else {
            None
        };
        self.files
            .iter()
            .copied()
            .filter(|path| {
                if fp16 && fp16_path.is_some() {
                    *path != "onnx/int8_int4_embeddings/model.onnx"
                        && *path != "model_int4_embeddings_int8.onnx"
                } else {
                    Some(*path) != fp16_path
                }
            })
            .collect()
    }

    /// Whether the model cache `root` holds the complete pinned bundle.
    pub fn assets_present(&self, root: &Path) -> bool {
        self.spec
            .files_present(&self.spec.cache_dir(root), &self.selected_files())
    }

    /// Fetch the pinned bundle into the model cache `root` and prepare its generated files.
    pub fn download(
        &self,
        root: &Path,
        progress: Option<&SecurityAssetProgressCallback>,
    ) -> Result<PathBuf, Box<dyn std::error::Error>> {
        let files = self.selected_files();
        let report = progress_reporter(progress, self.category, self.spec.id);
        let dir = self.spec.fetch(
            root,
            &files,
            report.as_ref().map(|report| report as &Progress<'_>),
        )?;
        prepare_generated_files(self.spec.id, &dir, &files);
        Ok(dir)
    }

    /// Prepare the generated files of the cached bundle: the compact tokenizer and the
    /// external weight data of its selected ONNX graphs. An incomplete bundle stays as it is.
    pub(crate) fn prepare_cached(&self, root: &Path) {
        if self.assets_present(root) {
            prepare_generated_files(
                self.spec.id,
                &self.spec.cache_dir(root),
                &self.selected_files(),
            );
        }
    }
}

pub(crate) fn prefer_fp16_l3() -> bool {
    std::env::var("PATRONUS_L3_PRECISION").is_ok_and(|value| value.eq_ignore_ascii_case("fp16"))
}

/// Download missing manifest assets for a category into `target_dir`.
///
/// Required asset failures return an error. Optional asset failures are skipped.
pub fn download_category_assets(
    category: SecurityCategory,
    max_level: SecurityLevel,
    target_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let assets = category_assets(category, max_level)
        .into_iter()
        .filter(|asset| asset.required || download_optional_assets())
        .collect::<Vec<_>>();
    let missing = assets
        .iter()
        .filter(|asset| !target_dir.join(asset.destination_path).exists())
        .map(|asset| ModelFile {
            repository: asset.repo,
            revision: asset.revision.unwrap_or("main"),
            source: asset.source_path.to_owned(),
            dest: target_dir.join(asset.destination_path),
            required: asset.required,
            label: category.as_str(),
        })
        .collect::<Vec<_>>();
    fetch_files(&missing, assets.len(), None)?;
    Ok(())
}

/// Download a missing NTDB L2 package from Hugging Face below the model cache `root`.
///
/// The package is downloaded manifest-first: `manifest.json` is fetched from
/// the package prefix, then runtime files referenced by that manifest are
/// downloaded into the same local package tree.
pub fn download_ntdb_l2_package(
    category: SecurityCategory,
    max_level: SecurityLevel,
    model: &str,
    root: &Path,
    progress: Option<&SecurityAssetProgressCallback>,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let asset = ntdb_l2_package_asset(category, max_level, model).ok_or_else(|| {
        format!(
            "missing NTDB L2 asset spec for {}/{}",
            category.as_str(),
            model
        )
    })?;
    let spec = asset.spec;
    let report = progress_reporter(progress, asset.category, spec.id);
    let report = report.as_ref().map(|report| report as &Progress<'_>);
    let package_dir = spec.cache_dir(root);
    let manifest_dest = package_dir.join("manifest.json");
    let revision_matches = spec.is_current(&package_dir);
    let fetch = |relative: &str, dest: PathBuf| ModelFile {
        required: asset.required,
        ..spec.file(relative, dest)
    };

    if !revision_matches || !manifest_dest.exists() {
        fetch_files(&[fetch("manifest.json", manifest_dest.clone())], 1, report)?;
    }

    let manifest_json = fs::read_to_string(&manifest_dest).map_err(|err| {
        format!(
            "failed to read downloaded NTDB L2 manifest {}: {err}",
            manifest_dest.display()
        )
    })?;
    let manifest = crate::ml::ntdb_executor::manifest::parse_package_manifest(&manifest_json)?;
    let shared_embedder_files = ntdb_l2_shared_embedder_files(&manifest, root, &package_dir)?;
    migrate_legacy_shared_embedder_files(&manifest, &shared_embedder_files)?;
    let shared_relative_paths = shared_embedder_files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect::<HashSet<_>>();

    let manifest_files = ntdb_l2_package_manifest_files_from_manifest(&manifest)?;
    let mut fetches = Vec::new();
    let mut refreshed = Vec::new();
    for file in &shared_embedder_files {
        if shared_embedder_refresh_required(revision_matches, &manifest, file, root)? {
            fetches.push(fetch(&file.relative_path, file.shared_file.clone()));
            refreshed.push(file);
        } else {
            link_shared_embedder_file(&file.shared_file, &file.package_file)?;
        }
    }
    for relative_path in &manifest_files {
        if shared_relative_paths.contains(relative_path) {
            continue;
        }
        let dest_file = package_dir.join(relative_path);
        if revision_matches && dest_file.exists() {
            continue;
        }
        fetches.push(fetch(relative_path, dest_file));
    }

    fetch_files(&fetches, manifest_files.len() + 1, report)?;
    for file in refreshed {
        link_shared_embedder_file(&file.shared_file, &file.package_file)?;
    }
    spec.mark_current(&package_dir)?;

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
/// it first keeps one generated `.mmbpe` per shared mmBERT tokenizer. Local model
/// overrides are deliberately handled by the caller and are not modified here.
pub(crate) fn prepare_cached_ntdb_l2_compact_tokenizer(
    manifest: &PackageManifest,
    package_dir: &Path,
    root: &Path,
    prepared_shared_tokenizers: &mut HashSet<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let shared_embedder_files = ntdb_l2_shared_embedder_files(manifest, root, package_dir)?;
    migrate_legacy_shared_embedder_files(manifest, &shared_embedder_files)?;
    let Some(tokenizer_file) = shared_embedder_files
        .iter()
        .find(|file| file.relative_path.ends_with("/tokenizer.json"))
    else {
        return Ok(());
    };
    if prepared_shared_tokenizers.contains(&tokenizer_file.shared_file) {
        {
            let extension = "mmbpe";
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
    let source_model = manifest
        .minilm
        .shared_embedder_identity()
        .unwrap_or("manifest-local-embedder");
    let Some(shared_compact_path) =
        ensure_mmbert_compact_tokenizer(source_model, source_tokenizer_json)?
    else {
        return Ok(());
    };
    link_compact_tokenizer(&shared_compact_path, package_tokenizer_json, "mmbpe")
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
    link_shared_embedder_file(shared_compact_path, &package_compact_path)
}

/// Return all runtime files referenced by an NTDB v4 package manifest.
pub fn ntdb_l2_package_manifest_files(
    manifest_json: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let manifest = crate::ml::ntdb_executor::manifest::parse_package_manifest(manifest_json)?;
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

    manifest.validate().map_err(|error| error.to_string())?;
    let joint = manifest
        .joint_v3
        .as_ref()
        .ok_or("NTDB v4 joint_v3 is required")?;
    push_manifest_file(&mut files, &mut seen, &joint.neural_stack.onnx)?;
    for head in &joint.heads {
        push_manifest_file(&mut files, &mut seen, &head.frozen_lightgbm)?;
    }
    for gate in joint.promoter.models.values() {
        collect_json_path_values(gate, "lightgbm_model", &mut files, &mut seen)?;
        collect_json_path_values(gate, "metadata", &mut files, &mut seen)?;
    }
    files.sort();
    Ok(files)
}

fn ntdb_l2_shared_embedder_files(
    manifest: &PackageManifest,
    root: &Path,
    package_dir: &Path,
) -> Result<Vec<SharedEmbedderFile>, Box<dyn std::error::Error>> {
    let shared_root = ntdb_l2_shared_embedder_dir(root, manifest);
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

fn ntdb_l2_shared_embedder_dir(root: &Path, manifest: &PackageManifest) -> PathBuf {
    root.join("l2_ntdb")
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
        for name in ["tokenizer.mmbpe", "tokenizer.mmbpe.meta.json"] {
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
            .filter(|path| shared_embedder_candidate_is_valid(manifest, file, path))
            .collect::<Vec<_>>();
        let mut candidates = Vec::with_capacity(legacy_files.len() + 2);
        if shared_embedder_candidate_is_valid(manifest, file, &file.shared_file) {
            candidates.push(file.shared_file.clone());
        }
        candidates.extend(legacy_files.iter().cloned());
        if shared_embedder_candidate_is_valid(manifest, file, &file.package_file) {
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

fn shared_embedder_file_is_valid(
    manifest: &PackageManifest,
    file: &SharedEmbedderFile,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !file.shared_file.is_file() {
        return Ok(false);
    }
    if !file
        .relative_path
        .ends_with(&manifest.minilm.embedding_matrix_file)
    {
        return Ok(true);
    }
    let len = fs::metadata(&file.shared_file)?.len();
    let elements = manifest.minilm.vocab_size as u64 * manifest.minilm.embedding_dim as u64;
    Ok(len == elements * 2 || len == elements * 4)
}

fn shared_embedder_refresh_required(
    package_revision_matches: bool,
    manifest: &PackageManifest,
    file: &SharedEmbedderFile,
    root: &Path,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !package_revision_matches || !shared_embedder_file_is_valid(manifest, file)? {
        return Ok(true);
    }
    if !manifest.minilm.is_l3_tokenizer_compatible()
        || Path::new(&file.relative_path)
            .file_name()
            .and_then(|name| name.to_str())
            != Some("tokenizer.json")
    {
        return Ok(false);
    }
    let unified_tokenizer = UNIFIED_L3_ASSET.spec.cache_dir(root).join("tokenizer.json");
    if !unified_tokenizer.is_file() {
        return Ok(false);
    }
    Ok(!same_cached_file(&file.shared_file, &unified_tokenizer)?)
}

fn shared_embedder_candidate_is_valid(
    manifest: &PackageManifest,
    file: &SharedEmbedderFile,
    path: &Path,
) -> bool {
    if !path.is_file() {
        return false;
    }
    if !file
        .relative_path
        .ends_with(&manifest.minilm.embedding_matrix_file)
    {
        return true;
    }
    let elements = manifest.minilm.vocab_size as u64 * manifest.minilm.embedding_dim as u64;
    fs::metadata(path)
        .is_ok_and(|metadata| metadata.len() == elements * 2 || metadata.len() == elements * 4)
}

fn same_cached_file(left: &Path, right: &Path) -> Result<bool, Box<dyn std::error::Error>> {
    if fs::canonicalize(left)? == fs::canonicalize(right)? {
        return Ok(true);
    }
    if fs::metadata(left)?.len() != fs::metadata(right)?.len() {
        return Ok(false);
    }
    // Tokenizer compatibility needs exact equality, not a persistent digest.
    // These large shared files are checked for every classifier during startup.
    // Compare buffered bytes directly instead of hashing both files repeatedly.
    use std::io::BufRead;
    let mut left = io::BufReader::with_capacity(64 * 1024, File::open(left)?);
    let mut right = io::BufReader::with_capacity(64 * 1024, File::open(right)?);
    loop {
        let left_bytes = left.fill_buf()?;
        let right_bytes = right.fill_buf()?;
        if left_bytes.is_empty() || right_bytes.is_empty() {
            return Ok(left_bytes.is_empty() && right_bytes.is_empty());
        }
        let length = left_bytes.len().min(right_bytes.len());
        if left_bytes[..length] != right_bytes[..length] {
            return Ok(false);
        }
        left.consume(length);
        right.consume(length);
    }
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
                return Err(format!("invalid NTDB manifest file path: {path:?}").into());
            }
        }
    }

    if parts.is_empty() {
        return Err(format!("invalid NTDB manifest file path: {path:?}").into());
    }
    Ok(parts.join("/"))
}

fn download_optional_assets() -> bool {
    std::env::var("PATRONUS_DOWNLOAD_OPTIONAL_ASSETS").as_deref() == Ok("1")
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::*;

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
        let mut manifest: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/ntdb_v4.json")).unwrap();
        manifest["minilm"]["source_model_path"] = serde_json::json!(identity);
        manifest["minilm"]["model"] =
            serde_json::json!("ibm-granite/granite-embedding-97m-multilingual-r2");
        manifest["minilm"]["vocab_size"] = serde_json::json!(1);
        manifest["minilm"]["embedding_dim"] = serde_json::json!(1);
        manifest.to_string()
    }

    #[test]
    fn ntdb_l2_shared_embedder_files_use_model_root_and_manifest_identity() {
        let root = temp_dir("shared_paths");
        let category_dir = root.join("injection");
        let package_dir = category_dir.join("l2_ntdb/injection_current");
        let manifest: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();

        let files = ntdb_l2_shared_embedder_files(&manifest, &root, &package_dir).unwrap();
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
    fn ntdb_l2_revision_change_refreshes_an_existing_shared_tokenizer() {
        let root = temp_dir("shared_revision_refresh");
        let category_dir = root.join("injection");
        let package_dir = category_dir.join("l2_ntdb/injection_current");
        let mut manifest: PackageManifest =
            serde_json::from_str(&manifest_json("jhu-clsp/mmBERT-small")).unwrap();
        manifest.minilm.tokenizer_family = Some("mmBERT".to_string());
        let tokenizer = ntdb_l2_shared_embedder_files(&manifest, &root, &package_dir)
            .unwrap()
            .into_iter()
            .find(|file| file.relative_path.ends_with("/tokenizer.json"))
            .unwrap();
        fs::create_dir_all(tokenizer.shared_file.parent().unwrap()).unwrap();
        fs::write(
            &tokenizer.shared_file,
            b"stale tokenizer from previous revision",
        )
        .unwrap();

        assert!(shared_embedder_refresh_required(false, &manifest, &tokenizer, &root,).unwrap());
        assert!(!shared_embedder_refresh_required(true, &manifest, &tokenizer, &root,).unwrap());

        let unified_tokenizer = UNIFIED_L3_ASSET
            .spec
            .cache_dir(&root)
            .join("tokenizer.json");
        fs::create_dir_all(unified_tokenizer.parent().unwrap()).unwrap();
        fs::write(&unified_tokenizer, b"current shared tokenizer").unwrap();
        assert!(shared_embedder_refresh_required(true, &manifest, &tokenizer, &root,).unwrap());
        fs::copy(&unified_tokenizer, &tokenizer.shared_file).unwrap();
        assert!(!shared_embedder_refresh_required(true, &manifest, &tokenizer, &root,).unwrap());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn root_level_shared_tokenizer_is_checked_for_refresh() {
        let root = temp_dir("root_shared_tokenizer_refresh");
        let category_dir = root.join("injection");
        let package_dir = category_dir.join("l2_ntdb/injection_current");
        let mut manifest: PackageManifest =
            serde_json::from_str(&manifest_json("jhu-clsp/mmBERT-small")).unwrap();
        manifest.minilm.tokenizer_family = Some("mmBERT".to_string());
        manifest.tokenizer_dir = ".".to_string();
        let tokenizer = ntdb_l2_shared_embedder_files(&manifest, &root, &package_dir)
            .unwrap()
            .into_iter()
            .find(|file| file.relative_path == "tokenizer.json")
            .unwrap();
        fs::create_dir_all(tokenizer.shared_file.parent().unwrap()).unwrap();
        fs::write(&tokenizer.shared_file, b"stale tokenizer").unwrap();
        let unified_tokenizer = UNIFIED_L3_ASSET
            .spec
            .cache_dir(&root)
            .join("tokenizer.json");
        fs::create_dir_all(unified_tokenizer.parent().unwrap()).unwrap();
        fs::write(&unified_tokenizer, b"current tokenizer").unwrap();

        assert!(shared_embedder_refresh_required(true, &manifest, &tokenizer, &root).unwrap());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cached_file_equality_checks_every_chunk_and_current_contents() {
        let root = temp_dir("cached_file_equality");
        fs::create_dir_all(&root).unwrap();
        let left = root.join("left");
        let right = root.join("right");
        let original = vec![b'a'; 2 * 64 * 1024 + 17];
        fs::write(&left, &original).unwrap();
        fs::write(&right, &original).unwrap();
        assert!(same_cached_file(&left, &left).unwrap());
        assert!(same_cached_file(&left, &right).unwrap());
        for offset in [0, 64 * 1024, original.len() - 1] {
            let mut changed = original.clone();
            changed[offset] = b'b';
            fs::write(&right, changed).unwrap();
            assert!(!same_cached_file(&left, &right).unwrap());
        }
        fs::write(&right, &original[..original.len() - 1]).unwrap();
        assert!(!same_cached_file(&left, &right).unwrap());
        fs::write(&left, []).unwrap();
        fs::write(&right, []).unwrap();
        assert!(same_cached_file(&left, &right).unwrap());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn current_l2_revision_is_not_ready_when_its_shared_tokenizer_is_stale() {
        let root = temp_dir("stale_shared_tokenizer_presence");
        let asset = ntdb_l2_package_asset(
            SecurityCategory::Injection,
            SecurityLevel::L3,
            crate::assets::WOLF_PIPELINE_MODEL,
        )
        .unwrap();
        let package_dir = asset.spec.cache_dir(&root);
        fs::create_dir_all(package_dir.join("tokenizer")).unwrap();
        fs::create_dir_all(package_dir.join("minilm")).unwrap();
        fs::write(
            package_dir.join("manifest.json"),
            manifest_json("jhu-clsp/mmBERT-small").replace(
                "\"tokenizer_family\": \"ModernBERT\"",
                "\"tokenizer_family\": \"mmBERT\"",
            ),
        )
        .unwrap();
        fs::write(package_dir.join(".patronus-revision"), asset.spec.revision).unwrap();
        fs::write(package_dir.join("minilm/embedding_matrix.f16"), [0_u8; 2]).unwrap();
        fs::write(
            package_dir.join("tokenizer/tokenizer.json"),
            b"stale tokenizer",
        )
        .unwrap();
        let unified_tokenizer = UNIFIED_L3_ASSET
            .spec
            .cache_dir(&root)
            .join("tokenizer.json");
        fs::create_dir_all(unified_tokenizer.parent().unwrap()).unwrap();
        fs::write(&unified_tokenizer, b"current tokenizer").unwrap();

        assert!(!ntdb_l2_package_assets_present(
            SecurityCategory::Injection,
            SecurityLevel::L3,
            crate::assets::WOLF_PIPELINE_MODEL,
            &root,
        ));
        fs::copy(
            &unified_tokenizer,
            package_dir.join("tokenizer/tokenizer.json"),
        )
        .unwrap();
        assert!(ntdb_l2_package_assets_present(
            SecurityCategory::Injection,
            SecurityLevel::L3,
            crate::assets::WOLF_PIPELINE_MODEL,
            &root,
        ));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn shared_embedder_directory_uses_canonical_model_over_export_path() {
        let root = temp_dir("canonical_shared_path");
        let exported: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();
        let canonical: PackageManifest = serde_json::from_str(&manifest_json(
            "ibm-granite/granite-embedding-97m-multilingual-r2",
        ))
        .unwrap();

        assert_eq!(
            ntdb_l2_shared_embedder_dir(&root, &exported),
            ntdb_l2_shared_embedder_dir(&root, &canonical)
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
        let files = ntdb_l2_shared_embedder_files(&manifest, &root, &package_dir).unwrap();
        let legacy_root = root
            .join("l2_ntdb/_shared/encoders")
            .join("ntdb_artifacts_granite_embedding_97m__v1_d1");
        fs::create_dir_all(legacy_root.join("tokenizer")).unwrap();
        fs::create_dir_all(legacy_root.join("minilm")).unwrap();
        fs::write(legacy_root.join("tokenizer/tokenizer.json"), "tokenizer").unwrap();
        fs::write(legacy_root.join("minilm/embedding_matrix.f16"), [0_u8; 2]).unwrap();

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
        let first: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();
        let mut second: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();
        second.chunk_size = 384;
        second.minilm.content_tokens_per_chunk = 384;

        assert_eq!(
            ntdb_l2_shared_embedder_dir(&root, &first),
            ntdb_l2_shared_embedder_dir(&root, &second)
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
        let files = ntdb_l2_shared_embedder_files(&manifest, &root, &package_dir).unwrap();
        let encoders_dir = root.join("l2_ntdb/_shared/encoders");
        let legacy_roots = [
            encoders_dir.join("ibm-granite_granite-embedding-97m-multilingual-r2__v1_d1_c2"),
            encoders_dir.join("ibm-granite_granite-embedding-97m-multilingual-r2__v1_d1_c384"),
        ];
        for legacy_root in &legacy_roots {
            fs::create_dir_all(legacy_root.join("tokenizer")).unwrap();
            fs::create_dir_all(legacy_root.join("minilm")).unwrap();
            fs::write(legacy_root.join("tokenizer/tokenizer.json"), "tokenizer").unwrap();
            fs::write(legacy_root.join("minilm/embedding_matrix.f16"), [0_u8; 2]).unwrap();
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
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_conflicting_files_for_the_same_shared_encoder_identity() {
        let root = temp_dir("conflicting_legacy_chunk_keys");
        let category_dir = root.join("injection");
        let package_dir = category_dir.join("l2_ntdb/injection_current");
        let manifest: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();
        let files = ntdb_l2_shared_embedder_files(&manifest, &root, &package_dir).unwrap();
        let encoders_dir = root.join("l2_ntdb/_shared/encoders");
        let first = encoders_dir
            .join("ibm-granite_granite-embedding-97m-multilingual-r2__v1_d1_c2/minilm/embedding_matrix.f16");
        let second = encoders_dir
            .join("ibm-granite_granite-embedding-97m-multilingual-r2__v1_d1_c384/minilm/embedding_matrix.f16");
        fs::create_dir_all(first.parent().unwrap()).unwrap();
        fs::create_dir_all(second.parent().unwrap()).unwrap();
        fs::write(&first, [0_u8; 2]).unwrap();
        fs::write(&second, [1_u8; 2]).unwrap();

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
    fn cached_pipeline_model_prepare_moves_graph_weights_to_external_data() {
        use patronus_ark_core::onnx::{external_data_path, has_inline_weights, testing};
        let root = temp_dir("pipeline_external_data");
        let asset = PipelineModelAssetSpec {
            category: SecurityCategory::ToolClass,
            spec: patronus_ark_core::model_assets::ModelSpec::new(
                "external-data-test",
                "example/repo",
                "rev",
                "pipeline",
            ),
            files: &["onnx/int8_int4_embeddings/model.onnx"],
        };
        let graph = root.join("pipeline/onnx/int8_int4_embeddings/model.onnx");
        fs::create_dir_all(graph.parent().unwrap()).unwrap();
        fs::write(&graph, testing::model_with_weights()).unwrap();

        // Without its revision marker the bundle is not a cached model and stays as it is.
        asset.prepare_cached(&root);
        assert!(has_inline_weights(&graph).unwrap());

        fs::write(root.join("pipeline/.patronus-revision"), "rev").unwrap();
        asset.prepare_cached(&root);
        assert!(!has_inline_weights(&graph).unwrap());
        assert!(external_data_path(&graph).is_file());
        assert!(asset.assets_present(&root));

        fs::remove_dir_all(root).unwrap();
    }
}
