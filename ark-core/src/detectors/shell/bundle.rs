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
use std::fs;
use std::path::Path;

use serde::Deserialize;

use super::model::ShellRiskModel;
use super::policies::DC_RULES_JSON;
use super::vocab::VOCAB_CSV;

const EMBEDDED_FILES: [(&str, &str); 2] = [
    ("shellrisk/policies/dc_rules.json", DC_RULES_JSON),
    ("shellrisk/facts/shell_vocab_v1.csv", VOCAB_CSV),
];

#[derive(Deserialize)]
struct Manifest {
    files: HashMap<String, String>,
}

/// `config.json`: which files hold the model and the gated policy levels.
#[derive(Deserialize)]
struct Config {
    model_file: String,
    policy_levels_file: String,
}

/// The verified contents of a bundle directory.
pub(crate) struct Bundle {
    pub model: ShellRiskModel,
    /// Policy id -> `block` | `ask` | `rejected`, from the release's gate.
    pub levels: HashMap<String, String>,
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, bytes)
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn read(path: &Path) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))
}

/// Load the bundle in `dir`; `manifest_sha256` pins the release manifest.
pub(crate) fn load(dir: &Path, manifest_sha256: Option<&str>) -> Result<Bundle, String> {
    let manifest_path = dir.join("manifest.json");
    let manifest_bytes = read(&manifest_path)?;
    if let Some(pin) = manifest_sha256 {
        let actual = sha256_hex(&manifest_bytes);
        if !actual.eq_ignore_ascii_case(pin) {
            return Err(format!(
                "{} sha256 {actual} is not the pinned release manifest {pin}",
                manifest_path.display()
            ));
        }
    }
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("invalid {}: {error}", manifest_path.display()))?;
    for (name, embedded) in EMBEDDED_FILES {
        if let Some(sha) = manifest.files.get(name) {
            if !sha256_hex(embedded.as_bytes()).eq_ignore_ascii_case(sha) {
                return Err(format!(
                    "{} lists a {name} that differs from the one this runtime embeds",
                    manifest_path.display()
                ));
            }
        }
    }
    let verified = |name: &str| -> Result<Vec<u8>, String> {
        let expected = manifest
            .files
            .get(name)
            .ok_or_else(|| format!("{} does not list {name}", manifest_path.display()))?;
        let path = dir.join(name);
        let bytes = read(&path)?;
        let actual = sha256_hex(&bytes);
        if !actual.eq_ignore_ascii_case(expected) {
            return Err(format!(
                "{} sha256 {actual} does not match manifest {expected}",
                path.display()
            ));
        }
        Ok(bytes)
    };
    let config: Config = serde_json::from_slice(&verified("config.json")?)
        .map_err(|error| format!("invalid config.json: {error}"))?;
    let levels = serde_json::from_slice(&verified(&config.policy_levels_file)?)
        .map_err(|error| format!("invalid {}: {error}", config.policy_levels_file))?;
    let model = ShellRiskModel::from_json_slice(&verified(&config.model_file)?)?;
    Ok(Bundle { model, levels })
}
