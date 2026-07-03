use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use patronus_security::{
    assets::{category_assets, required_assets_present},
    SecurityCategory, SecurityLevel,
};

fn temp_dir(name: &str) -> std::path::PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "patronus_assets_test_{}_{}_{}",
        name,
        std::process::id(),
        suffix
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn all_model_categories_except_pii_have_l3_required_assets() {
    for category in [
        SecurityCategory::Injection,
        SecurityCategory::ToolClassifier,
        SecurityCategory::UserIntent,
        SecurityCategory::SensitiveDocuments,
    ] {
        let assets = category_assets(category, SecurityLevel::L3);
        assert!(
            assets
                .iter()
                .any(|asset| asset.level == SecurityLevel::L3 && asset.required),
            "{category:?} should include required L3 assets"
        );
    }

    assert!(category_assets(SecurityCategory::Pii, SecurityLevel::L3)
        .iter()
        .all(|asset| asset.level <= SecurityLevel::L2));
}

#[test]
fn asset_manifest_has_unique_destination_paths_per_category() {
    for category in [
        SecurityCategory::Injection,
        SecurityCategory::ToolClassifier,
        SecurityCategory::UserIntent,
        SecurityCategory::SensitiveDocuments,
        SecurityCategory::Pii,
    ] {
        let mut seen = HashSet::new();
        for asset in category_assets(category, SecurityLevel::L3) {
            assert!(
                seen.insert(asset.destination_path),
                "duplicate destination for {category:?}: {}",
                asset.destination_path
            );
        }
    }
}

#[test]
fn only_required_assets_are_needed_for_presence_check() {
    let dir = temp_dir("required_only");
    let required: Vec<_> = category_assets(SecurityCategory::ToolClassifier, SecurityLevel::L3)
        .into_iter()
        .filter(|asset| asset.required)
        .collect();

    for asset in required {
        let path = dir.join(asset.destination_path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"asset").unwrap();
    }

    assert!(required_assets_present(
        SecurityCategory::ToolClassifier,
        SecurityLevel::L3,
        &dir
    ));

    std::fs::remove_dir_all(dir).unwrap();
}
