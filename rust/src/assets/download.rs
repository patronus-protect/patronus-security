use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use crate::{SecurityCategory, SecurityLevel};

use super::specs::{AssetSpec, ASSET_MANIFEST};

/// Return manifest entries needed for a category up to `max_level`.
pub fn category_assets(category: SecurityCategory, max_level: SecurityLevel) -> Vec<AssetSpec> {
    ASSET_MANIFEST
        .iter()
        .copied()
        .filter(|asset| asset.category == category && asset.level <= max_level)
        .collect()
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

        if let Some(parent) = dest_file.parent() {
            fs::create_dir_all(parent)?;
        }

        let file_url = format!(
            "https://huggingface.co/{}/resolve/main/{}",
            asset.repo, asset.source_path
        );

        println!(
            "Downloading L{} asset {} from Hugging Face -> {:?}",
            asset.level as u8, asset.source_path, dest_file
        );

        let mut request = ureq::get(&file_url);
        if let Some(ref tk) = token {
            request = request.set("Authorization", &format!("Bearer {}", tk));
        }

        let response = match request.call() {
            Ok(resp) => resp,
            Err(e) if !asset.required => {
                println!("Optional asset {} unavailable: {}", file_url, e);
                continue;
            }
            Err(e) => return Err(format!("Request to {} failed: {}", file_url, e).into()),
        };

        if response.status() != 200 {
            if asset.required {
                return Err(format!(
                    "Failed to download {}: HTTP {}",
                    file_url,
                    response.status()
                )
                .into());
            }
            println!(
                "Optional asset {} returned HTTP {}",
                file_url,
                response.status()
            );
            continue;
        }

        let mut reader = response.into_reader();
        let mut out_file = File::create(&dest_file)?;
        io::copy(&mut reader, &mut out_file)?;
    }

    Ok(())
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
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "patronus_downloader_{}_{}_{}",
            name,
            std::process::id(),
            suffix
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn manifest_has_no_wolf_l1_assets() {
        let l1_assets = category_assets(SecurityCategory::Injection, SecurityLevel::L1);
        assert!(l1_assets.is_empty());

        let l2_assets = category_assets(SecurityCategory::Injection, SecurityLevel::L2);
        assert!(l2_assets
            .iter()
            .all(|asset| asset.level == SecurityLevel::L2));
        assert!(l2_assets
            .iter()
            .all(|asset| asset.repo == "patronus-studio/wolf-defender-prompt-injection-small"));
    }

    #[test]
    fn manifest_uses_new_hf_paths_and_fp16_l3() {
        let injection_assets = category_assets(SecurityCategory::Injection, SecurityLevel::L3);
        assert!(injection_assets.iter().any(|asset| asset.source_path
            == "onnx/onnx_fp16/model_fp16.onnx"
            && asset.destination_path == "l3/onnx/onnx_fp16/model_fp16.onnx"
            && asset.required));

        let tool_assets = category_assets(SecurityCategory::ToolClassifier, SecurityLevel::L3);
        assert!(tool_assets
            .iter()
            .any(|asset| asset.source_path == "l1/l1_rules.json"
                && asset.destination_path == "prompts/l1_rules.json"));
        assert!(tool_assets
            .iter()
            .any(|asset| asset.source_path == "l2/l2_config.json"
                && asset.destination_path == "prompts/l2_config.json"));
        assert!(tool_assets
            .iter()
            .any(|asset| asset.source_path == "cascade/cascade_config.json"
                && asset.destination_path == "prompts/cascade_config.json"));
        assert!(tool_assets
            .iter()
            .any(|asset| asset.source_path == "onnx/model_fp16.onnx"
                && asset.destination_path == "prompts/onnx/model_fp16.onnx"
                && asset.required));
        assert!(tool_assets
            .iter()
            .any(|asset| asset.source_path == "onnx/model.onnx"
                && asset.destination_path == "prompts/onnx/model.onnx"
                && !asset.required));

        let sensitive_document_assets =
            category_assets(SecurityCategory::SensitiveDocuments, SecurityLevel::L3);
        assert!(sensitive_document_assets
            .iter()
            .any(
                |asset| asset.source_path == "onnx/onnx_fp16/model_fp16.onnx"
                    && asset.destination_path == "prompts/onnx/model_fp16.onnx"
                    && asset.required
            ));
    }

    #[test]
    fn optional_assets_do_not_block_presence_check() {
        let dir = temp_dir("optional");
        let required_assets: Vec<_> =
            category_assets(SecurityCategory::Injection, SecurityLevel::L3)
                .into_iter()
                .filter(|asset| asset.required)
                .collect();

        for asset in required_assets {
            let path = dir.join(asset.destination_path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"test").unwrap();
        }

        assert!(required_assets_present(
            SecurityCategory::Injection,
            SecurityLevel::L3,
            &dir
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_required_asset_blocks_presence_check() {
        let dir = temp_dir("missing_required");
        let assets = category_assets(SecurityCategory::Injection, SecurityLevel::L3);
        for asset in assets
            .into_iter()
            .filter(|asset| asset.required && asset.destination_path != "l3/tokenizer.json")
        {
            let path = dir.join(asset.destination_path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"test").unwrap();
        }

        assert!(!required_assets_present(
            SecurityCategory::Injection,
            SecurityLevel::L3,
            &dir
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pii_has_no_l3_assets_even_when_l3_is_requested() {
        let pii_assets = category_assets(SecurityCategory::Pii, SecurityLevel::L3);
        assert!(!pii_assets.is_empty());
        assert!(pii_assets
            .iter()
            .all(|asset| asset.level <= SecurityLevel::L2));
        assert!(pii_assets
            .iter()
            .all(|asset| !asset.destination_path.contains("onnx")));
    }
}
