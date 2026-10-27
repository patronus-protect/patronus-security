//! Resolve local Wolf exports and validate their integrity metadata.
use super::{
    asset, BundleFile, LogitOutput, WolfConfig, WolfManifest, WolfPrecision, CONTENT_TOKENS,
    SEQUENCE_TOKENS,
};
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

fn validate_manifest(manifest: &WolfManifest) -> Result<(), ScanError> {
    if manifest.schema_version != 1
        || manifest.model_id != "wolf-defender-small"
        || manifest.revision.is_empty()
        || !matches!(manifest.precision.as_str(), "fp16" | "int8_int4")
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

pub(crate) fn asset_manifest(config: &WolfConfig) -> Result<WolfManifest, ScanError> {
    asset_manifest_at(&config.bundle_dir, config.precision)
}

pub(crate) fn asset_manifest_at(
    bundle_dir: &Path,
    precision: WolfPrecision,
) -> Result<WolfManifest, ScanError> {
    let manifest_path = bundle_dir.join("wolf.manifest.json");
    let supplied_manifest = match fs::File::open(&manifest_path) {
        Ok(file) => {
            if file.metadata().map_err(asset)?.len() > 1024 * 1024 {
                return Err(asset("Wolf manifest exceeds 1 MiB"));
            }
            let manifest: WolfManifest = serde_json::from_reader(file).map_err(asset)?;
            validate_manifest(&manifest)?;
            Some(manifest)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(asset(error)),
    };
    existing_assets(bundle_dir, precision, supplied_manifest.as_ref())
}

pub(crate) fn model_paths(precision: WolfPrecision) -> &'static [&'static str] {
    match precision {
        WolfPrecision::Fp16 => &[
            crate::warmup::WOLF_FP16_FILE,
            "onnx/fp16/model_fp16.onnx",
            "model_fp16.onnx",
        ],
        WolfPrecision::Int8Int4 => &[
            crate::warmup::WOLF_QUANTIZED_FILE,
            "model_int4_embeddings_int8.onnx",
        ],
        WolfPrecision::Auto => &[],
    }
}

pub(crate) fn precision_order(
    requested: WolfPrecision,
    prefer_fp16: bool,
) -> &'static [WolfPrecision] {
    match requested {
        WolfPrecision::Fp16 => &[WolfPrecision::Fp16],
        WolfPrecision::Int8Int4 => &[WolfPrecision::Int8Int4],
        WolfPrecision::Auto if prefer_fp16 => &[WolfPrecision::Fp16, WolfPrecision::Int8Int4],
        WolfPrecision::Auto => &[WolfPrecision::Int8Int4, WolfPrecision::Fp16],
    }
}

/// Precision selection preserves the legacy environment preference and available assets.
pub(super) fn existing_assets(
    base: &Path,
    requested: WolfPrecision,
    supplied: Option<&WolfManifest>,
) -> Result<WolfManifest, ScanError> {
    let prefer_fp16 = std::env::var("PATRONUS_L3_PRECISION")
        .is_ok_and(|value| value.eq_ignore_ascii_case("fp16"));
    let priorities = precision_order(requested, prefer_fp16);
    let mut selected = None;
    for &precision in priorities {
        if let Some(manifest) = supplied.filter(|m| m.precision == precision.as_str()) {
            // A supplied contract remains authoritative for its own precision:
            // missing or corrupt declared files must not silently bypass integrity.
            return Ok(manifest.clone());
        }
        let paths = model_paths(precision);
        if let Some(path) = paths.iter().find(|path| base.join(path).is_file()) {
            selected = Some((*path, precision));
            break;
        }
    }
    let (model, precision) =
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
            if labels.get("0").and_then(|v| v.as_str()) != Some("benign")
                || labels.get("1").and_then(|v| v.as_str()) != Some("injection")
                || labels.len() != 2
            {
                return Err(asset("Wolf binary labels must be [benign, injection]"));
            }
        }
    }
    let revision = match fs::read_to_string(base.join(".patronus-revision")) {
        Ok(revision) => revision.trim().to_owned(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => "local".to_owned(),
        Err(error) => return Err(asset(error)),
    };
    let pad_id = match config.get("pad_token_id").filter(|v| !v.is_null()) {
        Some(value) => value
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| asset("invalid Wolf pad_token_id"))?,
        None => 0,
    };
    Ok(WolfManifest {
        schema_version: 1,
        model_id: "wolf-defender-small".into(),
        revision,
        precision: precision.as_str().into(),
        model: BundleFile {
            path: model.into(),
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
        content_tokens: CONTENT_TOKENS,
        sequence_tokens: SEQUENCE_TOKENS,
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
