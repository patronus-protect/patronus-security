use std::collections::HashSet;
use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::{SecurityCategory, SecurityLevel};

use crate::ml::ntdb_executor::manifest::PackageManifest;

use super::specs::{AssetSpec, NtdbL2PackageAssetSpec, ASSET_MANIFEST, NTDB_L2_PACKAGE_MANIFEST};

struct SharedEmbedderFile {
    relative_path: String,
    shared_file: PathBuf,
    package_file: PathBuf,
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

/// Download missing manifest assets for a category into `target_dir`.
///
/// Required asset failures return an error. Optional asset failures are skipped.
pub fn download_category_assets(
    category: SecurityCategory,
    max_level: SecurityLevel,
    target_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let token = hf_token();

    for asset in category_assets(category, max_level) {
        if !asset.required && !download_optional_assets() {
            continue;
        }

        let dest_file = target_dir.join(asset.destination_path);
        if dest_file.exists() {
            continue;
        }

        download_hf_file(
            token.as_deref(),
            asset.repo,
            asset.source_path,
            &dest_file,
            asset.required,
            &format!("L{} asset", asset.level as u8),
        )?;
    }

    Ok(())
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
    download_ntdb_l2_package_asset(asset, target_dir)
}

/// Download a missing NTDB v2 L2 package described by `asset`.
pub fn download_ntdb_l2_package_asset(
    asset: NtdbL2PackageAssetSpec,
    target_dir: &Path,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let token = hf_token();
    let package_dir = target_dir.join(asset.destination_path);
    let manifest_dest = package_dir.join("manifest.json");
    let manifest_source = prefixed_source_path(asset.source_prefix, "manifest.json");

    if !manifest_dest.exists() {
        download_hf_file(
            token.as_deref(),
            asset.repo,
            &manifest_source,
            &manifest_dest,
            asset.required,
            "NTDB v2 L2 manifest",
        )?;
    }

    let manifest_json = fs::read_to_string(&manifest_dest).map_err(|err| {
        format!(
            "failed to read downloaded NTDB v2 L2 manifest {}: {err}",
            manifest_dest.display()
        )
    })?;
    let manifest: PackageManifest = serde_json::from_str(&manifest_json)?;
    let shared_embedder_files = ntdb_l2_shared_embedder_files(&manifest, target_dir, &package_dir)?;
    let shared_relative_paths = shared_embedder_files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect::<HashSet<_>>();

    for file in &shared_embedder_files {
        download_shared_embedder_file(token.as_deref(), asset, file)?;
    }

    for relative_path in ntdb_l2_package_manifest_files_from_manifest(&manifest)? {
        if shared_relative_paths.contains(&relative_path) {
            continue;
        }
        let dest_file = package_dir.join(&relative_path);
        if dest_file.exists() {
            continue;
        }
        let source_path = prefixed_source_path(asset.source_prefix, &relative_path);
        download_hf_file(
            token.as_deref(),
            asset.repo,
            &source_path,
            &dest_file,
            asset.required,
            "NTDB v2 L2 package file",
        )?;
    }

    Ok(package_dir)
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
        "{}__v{}_d{}_c{}",
        sanitize_shared_embedder_identity(identity),
        manifest.minilm.vocab_size,
        manifest.minilm.embedding_dim,
        manifest.minilm.content_tokens_per_chunk
    )
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
    if !file.shared_file.exists() {
        let source_path = prefixed_source_path(asset.source_prefix, &file.relative_path);
        download_hf_file(
            token,
            asset.repo,
            &source_path,
            &file.shared_file,
            asset.required,
            "NTDB v2 shared L2 embedder file",
        )?;
    }
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

fn download_hf_file(
    token: Option<&str>,
    repo: &str,
    source_path: &str,
    dest_file: &Path,
    required: bool,
    label: &str,
) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some(parent) = dest_file.parent() {
        fs::create_dir_all(parent)?;
    }

    let file_url = format!("https://huggingface.co/{repo}/resolve/main/{source_path}");

    log::info!(
        "Downloading {label} {source_path} from Hugging Face -> {:?}",
        dest_file
    );

    let mut request = ureq::get(&file_url);
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
                    "model": "ibm-granite/granite-embedding-97m-multilingual-r2"
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
    fn ntdb_l2_shared_embedder_files_use_model_root_and_manifest_identity() {
        let root = temp_dir("shared_paths");
        let category_dir = root.join("injection");
        let package_dir = category_dir.join("l2_ntdb/injection_current");
        let manifest: PackageManifest =
            serde_json::from_str(&manifest_json("ntdb/artifacts/granite_embedding_97m")).unwrap();

        let files = ntdb_l2_shared_embedder_files(&manifest, &category_dir, &package_dir).unwrap();
        let shared_dir = root
            .join("l2_ntdb/_shared/encoders")
            .join("ntdb_artifacts_granite_embedding_97m__v1_d1_c2");

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
}
