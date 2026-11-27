// SPDX-License-Identifier: MIT OR Apache-2.0
//! A downloaded `cat-shell-risk-commander` release, read only after it is
//! verified.
//!
//! - `manifest.json` lists the sha256 of every release file. With a pin (the
//!   sha256 of `manifest.json` that the runtime embeds next to the release
//!   revision) the manifest itself must match, so the trust anchor is the
//!   binary: a changed manifest, and with it any changed file, is refused.
//! - `config.json`, `model.json` and `policy_levels.json` are read only after
//!   their sha256 matches the manifest.
//! - The release's reference `dc_rules.json` and shell vocabulary must equal
//!   the copies compiled into this runtime.
//!
//! The core-tier policies are compiled in, so they need no signature.

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

use super::model::SHELL_MODEL;
use super::policies::DC_RULES_JSON;
use super::vocab::VOCAB_CSV;
use crate::detectors::facts_common::block::BlockFile;
use crate::detectors::facts_common::bundle::VerifiedBundle;
use crate::detectors::facts_common::model::TfidfLrModel;

#[cfg(any(test, feature = "test-util"))]
pub(crate) use crate::detectors::facts_common::bundle::sha256_hex;

const EMBEDDED_FILES: [(&str, &str); 2] = [
    ("shellrisk/policies/dc_rules.json", DC_RULES_JSON),
    ("shellrisk/facts/shell_vocab_v1.csv", VOCAB_CSV),
];

/// `config.json`: which files hold the model and the gated policy levels.
#[derive(Deserialize)]
struct Config {
    model_file: String,
    policy_levels_file: String,
}

/// The verified contents of a bundle directory.
pub(crate) struct Bundle {
    pub model: TfidfLrModel,
    /// Policy id -> `block` | `ask` | `rejected`, from the release's gate.
    pub levels: HashMap<String, String>,
}

/// Load the bundle in `dir`; `manifest_sha256` pins the release manifest.
/// A file is read as a `cat-shell` block (`block.safetensors`), the pin then
/// being the file's sha256.
pub(crate) fn load(dir: &Path, manifest_sha256: Option<&str>) -> Result<Bundle, String> {
    if dir.is_file() {
        return load_block(&BlockFile::open(dir, manifest_sha256)?);
    }
    let bundle = VerifiedBundle::open(dir, manifest_sha256)?;
    for (name, embedded) in EMBEDDED_FILES {
        bundle.require_embedded(name, embedded)?;
    }
    let config: Config = serde_json::from_slice(&bundle.read("config.json")?)
        .map_err(|error| format!("invalid config.json: {error}"))?;
    let levels = serde_json::from_slice(&bundle.read(&config.policy_levels_file)?)
        .map_err(|error| format!("invalid {}: {error}", config.policy_levels_file))?;
    let model = TfidfLrModel::from_json_slice(&bundle.read(&config.model_file)?, SHELL_MODEL)?;
    Ok(Bundle { model, levels })
}

/// A `cat-shell` block: the model JSON without its weights and the policy
/// levels as metadata, the weights as an `F64` tensor. The rules and the
/// vocabulary its `block.py` embeds must be the copies compiled in here.
pub(crate) fn load_block(block: &BlockFile) -> Result<Bundle, String> {
    block.require_kind("cat-shell")?;
    block.require_embedded("dc_rules_sha256", DC_RULES_JSON)?;
    block.require_embedded("shell_vocab_sha256", VOCAB_CSV)?;
    let mut model: serde_json::Value = serde_json::from_str(block.meta("model")?)
        .map_err(|error| format!("block model: {error}"))?;
    let (weights, _) = block.f64s("weights")?;
    model["weights"] = serde_json::Value::from(weights);
    let bytes = serde_json::to_vec(&model).map_err(|error| error.to_string())?;
    let levels = serde_json::from_str(block.meta("policy_levels")?)
        .map_err(|error| format!("block policy levels: {error}"))?;
    Ok(Bundle {
        model: TfidfLrModel::from_json_slice(&bytes, SHELL_MODEL)?,
        levels,
    })
}
