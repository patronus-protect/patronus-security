//! Resolve local Wolf exports and validate their integrity metadata.
use super::{asset, BundleFile, LogitOutput, Published, WolfManifest, WolfModel, WolfPrecision};
use crate::ScanError;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub(super) fn verified_file(base: &Path, file: &BundleFile) -> Result<PathBuf, ScanError> {
    let root = base.canonicalize().map_err(asset)?;
    let path = root.join(&file.path).canonicalize().map_err(asset)?;
    if !path.starts_with(&root) || !path.is_file() {
        return Err(asset("bundle file must be inside bundle directory"));
    }
    let mut reader = fs::File::open(&path).map_err(asset)?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let size = reader.read(&mut buffer).map_err(asset)?;
        if size == 0 {
            break;
        }
        hasher.update(&buffer[..size]);
    }
    if hasher.finalize().to_hex().as_str() != file.blake3 {
        return Err(asset(format!("checksum mismatch: {}", file.path)));
    }
    Ok(path)
}

fn validate_manifest(manifest: &WolfManifest, model: WolfModel) -> Result<(), ScanError> {
    if manifest.schema_version != 1
        || manifest.model_id != model.spec().id
        || manifest.revision.is_empty()
        || !WolfPrecision::parse(&manifest.precision).is_some_and(|p| p != WolfPrecision::Auto)
        || manifest.reference.is_empty()
        || !matches!(
            (manifest.content_tokens, manifest.sequence_tokens),
            (254, 256) | (256, 258)
        )
        || manifest.parity_cases.is_empty()
        || manifest.model.blake3.is_empty()
        || manifest.tokenizer.blake3.is_empty()
        || !manifest.logit_tolerance.is_finite()
        || !(0.0..=0.05).contains(&manifest.logit_tolerance)
        || !manifest.relative_tolerance.is_finite()
        || !(0.0..=0.005).contains(&manifest.relative_tolerance)
        || !manifest.probability_tolerance.is_finite()
        || !(0.0..=0.005).contains(&manifest.probability_tolerance)
    {
        return Err(asset("invalid optional Wolf integrity manifest"));
    }
    Ok(())
}

pub(crate) fn asset_manifest_at(
    bundle_dir: &Path,
    model: WolfModel,
    precision: WolfPrecision,
) -> Result<WolfManifest, ScanError> {
    let manifest_path = bundle_dir.join("wolf.manifest.json");
    let supplied_manifest = match fs::File::open(&manifest_path) {
        Ok(file) => {
            if file.metadata().map_err(asset)?.len() > 1024 * 1024 {
                return Err(asset("Wolf manifest exceeds 1 MiB"));
            }
            let manifest: WolfManifest = serde_json::from_reader(file).map_err(asset)?;
            validate_manifest(&manifest, model)?;
            Some(manifest)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(asset(error)),
    };
    existing_assets(bundle_dir, model, precision, supplied_manifest.as_ref())
}

/// The published graph path first, then file names of older local exports.
pub(crate) fn model_paths(model: WolfModel, precision: WolfPrecision) -> Vec<&'static str> {
    let legacy: &[&str] = match precision {
        WolfPrecision::Fp16 => &["onnx/fp16/model_fp16.onnx", "model_fp16.onnx"],
        WolfPrecision::Int8Int4 => &["model_int4_embeddings_int8.onnx"],
        _ => &[],
    };
    model
        .spec()
        .graph(precision)
        .into_iter()
        .chain(legacy.iter().copied())
        .collect()
}

/// Explicit precisions are strict. `auto` starts with its resolved precision and
/// falls back to other exports a local bundle may hold, smallest first.
pub(crate) fn precision_order(requested: WolfPrecision) -> Result<Vec<WolfPrecision>, ScanError> {
    let first = requested.resolve()?;
    if requested != WolfPrecision::Auto {
        return Ok(vec![first]);
    }
    let mut order = vec![first];
    for precision in [
        WolfPrecision::platform_default(),
        WolfPrecision::Int8Int4,
        WolfPrecision::Int8Int4X86,
        WolfPrecision::Fp16,
        WolfPrecision::Mixed,
        WolfPrecision::MixedX86,
        WolfPrecision::Fp32,
    ] {
        if !order.contains(&precision) {
            order.push(precision);
        }
    }
    Ok(order)
}

/// Bundle-relative graph paths to try for a request, in preference order.
pub fn graph_candidates(
    model: WolfModel,
    precision: WolfPrecision,
) -> Result<Vec<&'static str>, ScanError> {
    Ok(precision_order(precision)?
        .into_iter()
        .flat_map(|precision| model_paths(model, precision))
        .collect())
}

/// Pick the first requested precision whose export exists locally.
pub(super) fn existing_assets(
    base: &Path,
    model: WolfModel,
    requested: WolfPrecision,
    supplied: Option<&WolfManifest>,
) -> Result<WolfManifest, ScanError> {
    let mut selected = None;
    for precision in precision_order(requested)? {
        if let Some(manifest) = supplied.filter(|m| m.precision == precision.as_str()) {
            // A supplied contract remains authoritative for its own precision:
            // missing or corrupt declared files must not silently bypass integrity.
            return Ok(manifest.clone());
        }
        if let Some(path) = model_paths(model, precision)
            .into_iter()
            .find(|path| base.join(path).is_file())
        {
            selected = Some((path, precision));
            break;
        }
    }
    let (graph, precision) =
        selected.ok_or_else(|| asset("requested Wolf ONNX precision is unavailable"))?;
    let tokenizer = ["tokenizer.mmbpe", "tokenizer.json"]
        .into_iter()
        .find(|name| base.join(name).is_file())
        .ok_or_else(|| asset("Wolf tokenizer is missing"))?;
    let config: serde_json::Value = match fs::File::open(base.join("config.json")) {
        Ok(file) => serde_json::from_reader(file).map_err(asset)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
        Err(error) => return Err(asset(error)),
    };
    let scalar = config["num_labels"].as_u64() == Some(1)
        || config["id2label"]
            .as_object()
            .is_some_and(|labels| labels.len() == 1);
    if !scalar {
        if let Some(labels) = config["id2label"].as_object() {
            // v2.1 spells its labels BENIGN/INJECTION; the indices are unchanged.
            let label = |index: &str, name: &str| {
                labels
                    .get(index)
                    .and_then(|v| v.as_str())
                    .is_some_and(|v| v.eq_ignore_ascii_case(name))
            };
            if !label("0", "benign") || !label("1", "injection") || labels.len() != 2 {
                return Err(asset("Wolf binary labels must be [benign, injection]"));
            }
        }
    }
    let revision = match fs::read_to_string(base.join(".patronus-revision")) {
        Ok(revision) => revision.trim().to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "local".to_owned(),
        Err(error) => return Err(asset(error)),
    };
    // All models share graph paths, so a managed marker is the only proof of identity.
    if let Some(owner) = WolfModel::of_revision(&revision).filter(|&owner| owner != model) {
        return Err(asset(format!(
            "Wolf bundle holds {}, not the configured {}",
            owner.spec().id,
            model.spec().id
        )));
    }
    let pad_id = match config.get("pad_token_id").filter(|v| !v.is_null()) {
        Some(value) => value
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| asset("invalid Wolf pad_token_id"))?,
        None => 0,
    };
    Ok(WolfManifest {
        schema_version: 1,
        model_id: model.spec().id.into(),
        revision,
        precision: precision.as_str().into(),
        model: BundleFile {
            path: graph.into(),
            blake3: String::new(),
        },
        tokenizer: BundleFile {
            path: tokenizer.into(),
            blake3: String::new(),
        },
        output_name: "logits".into(),
        output: if scalar {
            LogitOutput::Scalar
        } else {
            LogitOutput::BinaryMargin
        },
        // No references: the window fields only describe the model's own profile.
        content_tokens: Published::MODEL.window_tokens - 2,
        sequence_tokens: Published::MODEL.window_tokens,
        overlap_tokens: Published::MODEL.overlap_tokens,
        dynamic_sequence: true,
        pad_id,
        reference: String::new(),
        parity_cases: Vec::new(),
        document_cases: Vec::new(),
        logit_tolerance: 0.02,
        relative_tolerance: 0.005,
        probability_tolerance: 0.005,
    })
}
