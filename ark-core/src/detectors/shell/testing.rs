// SPDX-License-Identifier: MIT OR Apache-2.0
//! A synthetic K26 bundle for tests: a tiny model, the release's gated policy
//! levels, `config.json`, `LICENSE` and a matching `manifest.json`.

use std::path::Path;

use super::bundle::sha256_hex;

/// Gated policy levels of the K26 release (`policy_levels.json`).
pub const POLICY_LEVELS_JSON: &str = include_str!("testdata/policy_levels.json");
const SYNTHETIC_MODEL_JSON: &str = include_str!("testdata/synthetic_model.json");

/// Write the synthetic bundle into `dir` and return the sha256 of its
/// `manifest.json`, the pin to load it with. `model_sha` replaces the manifest
/// entry of `model.json` (to test a tampered file).
pub fn write_synthetic_bundle(dir: &Path, model_sha: Option<&str>) -> std::io::Result<String> {
    std::fs::create_dir_all(dir)?;
    let files: [(&str, &[u8]); 4] = [
        ("model.json", SYNTHETIC_MODEL_JSON.as_bytes()),
        ("policy_levels.json", POLICY_LEVELS_JSON.as_bytes()),
        (
            "config.json",
            br#"{"model_file":"model.json","policy_levels_file":"policy_levels.json"}"#,
        ),
        ("LICENSE", b"Apache-2.0"),
    ];
    let mut manifest = serde_json::Map::new();
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes)?;
        let sha = match (name, model_sha) {
            ("model.json", Some(sha)) => sha.to_string(),
            _ => sha256_hex(bytes),
        };
        manifest.insert(name.to_string(), sha.into());
    }
    let manifest = serde_json::json!({ "files": manifest }).to_string();
    std::fs::write(dir.join("manifest.json"), &manifest)?;
    Ok(sha256_hex(manifest.as_bytes()))
}
