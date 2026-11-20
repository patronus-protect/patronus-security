use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use patronus_ark::{
    assets::category_assets, assets::dedicated_l3_asset, assets::ntdb_l2_package_assets,
    assets::ntdb_l2_package_assets_present, assets::required_assets_present,
    assets::DEDICATED_L3_ASSETS, assets::DYNAMIC_PII_ASSET, assets::NTDB_L2_PACKAGE_MANIFEST,
    assets::UNIFIED_L3_ASSET,
};

use patronus_ark_core::{cascade::SecurityLevel, SecurityCategory};

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
fn dynamic_pii_bundle_is_complete_and_revision_pinned() {
    assert_eq!(DYNAMIC_PII_ASSET.category, SecurityCategory::DynamicPii);
    assert_eq!(
        DYNAMIC_PII_ASSET.spec.repository,
        "patronus-studio/gliner_small-v2.5-edge"
    );
    assert_eq!(DYNAMIC_PII_ASSET.spec.revision.len(), 40);
    assert!(DYNAMIC_PII_ASSET
        .spec
        .revision
        .chars()
        .all(|ch| ch.is_ascii_hexdigit()));
    assert!(DYNAMIC_PII_ASSET
        .files
        .contains(&"model_int4_embeddings_int8.onnx"));
    assert!(DYNAMIC_PII_ASSET
        .files
        .contains(&"onnx/fp16/model_fp16.onnx"));
    assert!(DYNAMIC_PII_ASSET
        .files
        .contains(&"quantization_manifest.json"));
    assert!(DYNAMIC_PII_ASSET.files.contains(&"spm.model"));
    assert!(DYNAMIC_PII_ASSET.files.contains(&"tokenizer.json"));

    let dir = temp_dir("dynamic_pii");
    assert!(!DYNAMIC_PII_ASSET.assets_present(&dir));
    for file in DYNAMIC_PII_ASSET.files {
        let path = dir.join(DYNAMIC_PII_ASSET.spec.cache_subdir).join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"asset").unwrap();
    }
    std::fs::write(
        dir.join(DYNAMIC_PII_ASSET.spec.cache_subdir)
            .join(".patronus-revision"),
        DYNAMIC_PII_ASSET.spec.revision,
    )
    .unwrap();
    assert!(DYNAMIC_PII_ASSET.assets_present(&dir));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unified_l3_bundle_and_dedicated_models_are_revision_pinned() {
    assert_eq!(
        UNIFIED_L3_ASSET.spec.repository,
        "patronus-studio/lion-warden-ai-security-classifier"
    );
    assert_eq!(
        UNIFIED_L3_ASSET.spec.revision,
        "77888f617584758f904faefd6f38d4cf926f6d5d"
    );
    assert!(UNIFIED_L3_ASSET
        .files
        .contains(&"onnx/int8_int4_embeddings/model.onnx"));
    assert!(UNIFIED_L3_ASSET
        .files
        .contains(&"onnx/onnx_fp16/model_fp16.onnx"));
    assert_eq!(DEDICATED_L3_ASSETS.len(), 6);
    // Injection L3 is Wolf: Core pins, prepares and caches it, so ARK holds no entry.
    assert!(dedicated_l3_asset(SecurityCategory::Injection).is_none());
    for (category, revision) in [
        (
            SecurityCategory::SensitiveDocument,
            "c038771b10b00b8da67d31e2b0280f85e13b808c",
        ),
        (
            SecurityCategory::ToolClass,
            "68e58725282dcdda106d8388fca47e0802335bc4",
        ),
        (
            SecurityCategory::ToolAction,
            "326adc8edfcaa5c65986cab2896c2e69bc3d36cc",
        ),
        (
            SecurityCategory::ToolTags,
            "4619a3c2c14c36f2e4c8ee5c9d65b1ea7b962cbd",
        ),
        (
            SecurityCategory::Routing,
            "ef7f1e20afda64f06be0e656184ab67c14061e6a",
        ),
        (
            SecurityCategory::UnsafeAction,
            "6520c1f43c716d1210321aecc7681446dd5ce317",
        ),
    ] {
        let asset = dedicated_l3_asset(category).expect("dedicated L3 asset");
        assert_eq!(asset.spec.revision, revision);
        assert!(asset
            .files
            .contains(&"onnx/int8_int4_embeddings/model.onnx"));
        if matches!(
            category,
            SecurityCategory::SensitiveDocument | SecurityCategory::UnsafeAction
        ) {
            assert!(asset.files.contains(&"onnx/onnx_fp16/model_fp16.onnx"));
        }
    }
}

#[test]
fn classifier_assets_use_the_public_hub_repositories() {
    for (category, l3_repo, l2_repo, revision) in [
        (
            SecurityCategory::ToolClass,
            "patronus-studio/husky-sight-tool-type-classifier-edge",
            "patronus-studio/husky-sight-tool-type-classifier",
            "68e58725282dcdda106d8388fca47e0802335bc4",
        ),
        (
            SecurityCategory::ToolAction,
            "patronus-studio/husky-paw-tool-action-classifier-edge",
            "patronus-studio/husky-paw-tool-action-classifier",
            "326adc8edfcaa5c65986cab2896c2e69bc3d36cc",
        ),
        (
            SecurityCategory::ToolTags,
            "patronus-studio/husky-nose-tool-security-properties-classifier-edge",
            "patronus-studio/husky-nose-tool-security-properties-classifier",
            "4619a3c2c14c36f2e4c8ee5c9d65b1ea7b962cbd",
        ),
        (
            SecurityCategory::Routing,
            "patronus-studio/panther-read-intent-classifier-edge",
            "patronus-studio/panther-read-intent-classifier",
            "ef7f1e20afda64f06be0e656184ab67c14061e6a",
        ),
        (
            SecurityCategory::UnsafeAction,
            "patronus-studio/wolf-defender-threat-classifier",
            "patronus-studio/wolf-defender-threat-classifier",
            "6520c1f43c716d1210321aecc7681446dd5ce317",
        ),
    ] {
        let l3 = dedicated_l3_asset(category).expect("dedicated L3 asset");
        assert_eq!(l3.spec.repository, l3_repo);
        assert_eq!(l3.spec.revision, revision);

        let l2 = ntdb_l2_package_assets(category, SecurityLevel::L2);
        assert_eq!(
            l2.len(),
            if category == SecurityCategory::ToolTags {
                3
            } else {
                1
            }
        );
        assert!(l2.iter().all(|asset| asset.spec.repository == l2_repo));
        assert!(l2
            .iter()
            .all(|asset| asset.spec.source_prefix == "l2"
                || asset.spec.source_prefix.starts_with("l2/")));
    }
}

#[test]
fn migrated_l3_models_do_not_reference_removed_edge_repositories() {
    let migrated = [
        UNIFIED_L3_ASSET,
        dedicated_l3_asset(SecurityCategory::SensitiveDocument).unwrap(),
        dedicated_l3_asset(SecurityCategory::UnsafeAction).unwrap(),
    ];

    assert!(migrated
        .iter()
        .all(|asset| !asset.spec.repository.ends_with("-edge")));
    assert_eq!(
        migrated.map(|asset| asset.spec.repository),
        [
            "patronus-studio/lion-warden-ai-security-classifier",
            "patronus-studio/orca-sonar-document-classifier",
            "patronus-studio/wolf-defender-threat-classifier",
        ]
    );
}

#[test]
fn l3_model_categories_have_required_l3_assets() {
    let assets = category_assets(SecurityCategory::SensitiveDocument, SecurityLevel::L3);
    assert!(assets
        .iter()
        .any(|asset| asset.level == SecurityLevel::L3 && asset.required));
    // Injection L3 is Wolf: Core prepares the configured model.
    assert!(
        category_assets(SecurityCategory::Injection, SecurityLevel::L3)
            .iter()
            .all(|asset| asset.level != SecurityLevel::L3)
    );
    assert!(dedicated_l3_asset(SecurityCategory::Injection).is_none());

    for category in [
        SecurityCategory::ToolClass,
        SecurityCategory::Routing,
        SecurityCategory::Pii,
    ] {
        assert!(category_assets(category, SecurityLevel::L3)
            .iter()
            .all(|asset| asset.level == SecurityLevel::L1));
    }
}

#[test]
fn static_manifest_has_no_legacy_l2_file_assets() {
    for category in [
        SecurityCategory::Injection,
        SecurityCategory::SensitiveDocument,
        SecurityCategory::ToolClass,
        SecurityCategory::ToolAction,
        SecurityCategory::ToolTags,
        SecurityCategory::Routing,
        SecurityCategory::UnsafeAction,
        SecurityCategory::Pii,
    ] {
        assert!(category_assets(category, SecurityLevel::L3)
            .iter()
            .all(|asset| asset.level != SecurityLevel::L2));
    }
}

#[test]
fn ntdb_l2_package_manifest_has_available_model_specs() {
    assert_eq!(
        ntdb_l2_package_assets(SecurityCategory::Injection, SecurityLevel::L2)
            .iter()
            .map(|asset| asset.spec.cache_subdir)
            .collect::<Vec<_>>(),
        vec!["injection/l2_ntdb/injection_current"]
    );
    assert_eq!(
        ntdb_l2_package_assets(SecurityCategory::SensitiveDocument, SecurityLevel::L2)
            .iter()
            .map(|asset| asset.spec.cache_subdir)
            .collect::<Vec<_>>(),
        vec!["sensitive_document/l2_ntdb/sensitive_document_current"]
    );
    assert_eq!(
        ntdb_l2_package_assets(SecurityCategory::ToolClass, SecurityLevel::L2)
            .iter()
            .map(|asset| asset.spec.cache_subdir)
            .collect::<Vec<_>>(),
        vec!["tool_class/l2_ntdb/tool_class_current"]
    );
    for (category, model, destination) in [
        (
            SecurityCategory::ToolAction,
            "unified-v3-tool-action",
            "tool_action/l2_ntdb/tool_action_current",
        ),
        (
            SecurityCategory::Routing,
            "unified-v3-routing",
            "routing/l2_ntdb/routing_current",
        ),
        (
            SecurityCategory::UnsafeAction,
            "unified-v3-threat",
            "threat/l2_ntdb/threat_current",
        ),
    ] {
        let assets = ntdb_l2_package_assets(category, SecurityLevel::L2);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].spec.id, model);
        assert_eq!(assets[0].spec.cache_subdir, destination);
        if category == SecurityCategory::ToolTags {
            assert_eq!(
                assets[0].spec.repository,
                "patronus-studio/husky-nose-tool-security-properties-classifier"
            );
        }
    }
    let tool_tags = ntdb_l2_package_assets(SecurityCategory::ToolTags, SecurityLevel::L2);
    assert_eq!(tool_tags.len(), 3);
    assert_eq!(
        tool_tags
            .iter()
            .map(|asset| asset.spec.id)
            .collect::<Vec<_>>(),
        vec![
            "tool_tags_sink_external",
            "tool_tags_source_sensitive",
            "tool_tags_source_untrusted",
        ]
    );
    assert!(tool_tags.iter().all(|asset| {
        asset.spec.repository == "patronus-studio/husky-nose-tool-security-properties-classifier"
            && asset.spec.revision == "f5736c09bcb6f75f1af3604706a1ee5c7e39d745"
    }));
    assert!(ntdb_l2_package_assets(SecurityCategory::Dlp, SecurityLevel::L2).is_empty());
    assert!(ntdb_l2_package_assets(SecurityCategory::Pii, SecurityLevel::L2).is_empty());
}

#[test]
fn ntdb_l2_package_cache_requires_the_pinned_revision() {
    let dir = temp_dir("ntdb_revision");
    let asset = ntdb_l2_package_assets(SecurityCategory::Injection, SecurityLevel::L2)[0];
    let package_dir = dir.join(asset.spec.cache_subdir);
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::create_dir_all(package_dir.join("minilm")).unwrap();
    let mut manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ntdb_v4.json")).unwrap();
    manifest["minilm"]["vocab_size"] = serde_json::json!(1);
    manifest["minilm"]["embedding_dim"] = serde_json::json!(1);
    std::fs::write(package_dir.join("manifest.json"), manifest.to_string()).unwrap();
    std::fs::write(package_dir.join("minilm/embedding_matrix.f16"), [0_u8; 2]).unwrap();

    assert!(!ntdb_l2_package_assets_present(
        SecurityCategory::Injection,
        SecurityLevel::L2,
        asset.spec.id,
        &dir,
    ));
    std::fs::write(package_dir.join(".patronus-revision"), asset.spec.revision).unwrap();
    assert!(ntdb_l2_package_assets_present(
        SecurityCategory::Injection,
        SecurityLevel::L2,
        asset.spec.id,
        &dir,
    ));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn asset_manifest_has_unique_destination_paths_per_category() {
    for category in [
        SecurityCategory::Injection,
        SecurityCategory::SensitiveDocument,
        SecurityCategory::ToolClass,
        SecurityCategory::ToolAction,
        SecurityCategory::ToolTags,
        SecurityCategory::Routing,
        SecurityCategory::UnsafeAction,
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
fn ntdb_l2_package_manifest_has_unique_destination_paths_per_category() {
    for category in [
        SecurityCategory::Injection,
        SecurityCategory::SensitiveDocument,
        SecurityCategory::ToolClass,
        SecurityCategory::ToolAction,
        SecurityCategory::ToolTags,
        SecurityCategory::Routing,
        SecurityCategory::UnsafeAction,
        SecurityCategory::Pii,
    ] {
        let mut seen = HashSet::new();
        for asset in ntdb_l2_package_assets(category, SecurityLevel::L3) {
            assert!(
                seen.insert(asset.spec.cache_subdir),
                "duplicate NTDB package destination for {category:?}: {}",
                asset.spec.cache_subdir
            );
            assert!(
                asset.spec.source_prefix == "l2" || asset.spec.source_prefix.starts_with("l2/")
            );
            assert!(asset.required);
        }
    }
}

#[test]
fn only_required_assets_are_needed_for_presence_check() {
    let dir = temp_dir("required_only");
    let required: Vec<_> = category_assets(SecurityCategory::ToolClass, SecurityLevel::L3)
        .into_iter()
        .filter(|asset| asset.required)
        .collect();

    for asset in required {
        let path = dir.join(asset.destination_path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"asset").unwrap();
    }

    assert!(required_assets_present(
        SecurityCategory::ToolClass,
        SecurityLevel::L3,
        &dir
    ));

    std::fs::remove_dir_all(dir).unwrap();
}

mod asset_downloads {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use patronus_ark::assets::{
        category_assets, ntdb_l2_package_assets, ntdb_l2_package_manifest_files,
        required_assets_present, ASSET_MANIFEST,
    };
    use patronus_ark_core::{cascade::SecurityLevel, SecurityCategory};

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
    fn static_manifest_has_no_legacy_l2_assets() {
        let l1_assets = category_assets(SecurityCategory::Injection, SecurityLevel::L1);
        assert!(l1_assets.is_empty());

        let l2_assets = category_assets(SecurityCategory::Injection, SecurityLevel::L2);
        assert!(l2_assets.is_empty());
        assert!(ASSET_MANIFEST
            .iter()
            .all(|asset| asset.level != SecurityLevel::L2));
    }

    #[test]
    fn ntdb_l2_package_specs_cover_available_models() {
        let injection = ntdb_l2_package_assets(SecurityCategory::Injection, SecurityLevel::L2);
        assert_eq!(injection.len(), 1);
        assert_eq!(injection[0].spec.id, "wolf-defender-small");
        assert_eq!(injection[0].spec.source_prefix, "l2");
        assert_eq!(
            injection[0].spec.cache_subdir,
            "injection/l2_ntdb/injection_current"
        );

        let sensitive =
            ntdb_l2_package_assets(SecurityCategory::SensitiveDocument, SecurityLevel::L2);
        assert_eq!(sensitive.len(), 1);
        assert_eq!(sensitive[0].spec.id, "orca-sonar-document-classifier");
        assert_eq!(
            sensitive[0].spec.cache_subdir,
            "sensitive_document/l2_ntdb/sensitive_document_current"
        );

        for (category, model) in [
            (SecurityCategory::ToolClass, "unified-v3-tool-class"),
            (SecurityCategory::ToolAction, "unified-v3-tool-action"),
            (SecurityCategory::Routing, "unified-v3-routing"),
            (SecurityCategory::UnsafeAction, "unified-v3-threat"),
        ] {
            let assets = ntdb_l2_package_assets(category, SecurityLevel::L2);
            assert_eq!(assets.len(), 1);
            assert_eq!(assets[0].spec.id, model);
        }
        let tool_tags = ntdb_l2_package_assets(SecurityCategory::ToolTags, SecurityLevel::L2);
        assert_eq!(tool_tags.len(), 3);
        assert!(tool_tags
            .iter()
            .all(|asset| asset.spec.id.starts_with("tool_tags_")));
        assert!(ntdb_l2_package_assets(SecurityCategory::Dlp, SecurityLevel::L2).is_empty());
        assert!(ntdb_l2_package_assets(SecurityCategory::Pii, SecurityLevel::L2).is_empty());
    }

    #[test]
    fn manifest_excludes_legacy_l1_rules_and_keeps_l3_assets() {
        let injection_assets = category_assets(SecurityCategory::Injection, SecurityLevel::L3);
        assert!(injection_assets
            .iter()
            .all(|asset| !asset.destination_path.starts_with("l3/")));

        let tool_assets = category_assets(SecurityCategory::ToolClass, SecurityLevel::L3);
        assert!(tool_assets.is_empty());

        let user_intent_assets = category_assets(SecurityCategory::Routing, SecurityLevel::L3);
        assert!(user_intent_assets.is_empty());

        let sensitive_document_assets =
            category_assets(SecurityCategory::SensitiveDocument, SecurityLevel::L3);
        assert!(sensitive_document_assets
            .iter()
            .any(
                |asset| asset.source_path == "onnx/int8_int4_embeddings/model.onnx"
                    && asset.destination_path == "prompts/onnx/int8_int4_embeddings/model.onnx"
                    && asset.required
            ));
        assert!(sensitive_document_assets
            .iter()
            .all(|asset| asset.level == SecurityLevel::L3));
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
        let category = SecurityCategory::SensitiveDocument;
        let assets = category_assets(category, SecurityLevel::L3);
        // Every required file except the first one.
        for asset in assets.into_iter().filter(|asset| asset.required).skip(1) {
            let path = dir.join(asset.destination_path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"test").unwrap();
        }

        assert!(!required_assets_present(category, SecurityLevel::L3, &dir));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn pii_has_no_l3_assets_even_when_l3_is_requested() {
        let pii_assets = category_assets(SecurityCategory::Pii, SecurityLevel::L3);
        assert!(pii_assets.is_empty());
    }

    #[test]
    fn ntdb_manifest_files_include_runtime_references() {
        let manifest = include_str!("fixtures/ntdb_v4.json");
        let files = ntdb_l2_package_manifest_files(manifest).unwrap();
        assert!(files.contains(&"neural/joint_v3_neural_stack.onnx".to_string()));
        assert!(files.contains(&"minilm/embedding_matrix.f16".to_string()));
        assert!(files.contains(&"tokenizer/tokenizer.json".to_string()));
        assert!(files.iter().any(|file| file.ends_with(".txt")));
        assert!(!files.iter().any(|file| file.starts_with("aggregators/")));
    }

    #[test]
    fn ntdb_manifest_files_reject_parent_paths() {
        let manifest =
            include_str!("fixtures/ntdb_v4.json").replace("\"tokenizer\"", "\"../tokenizer\"");
        let err = ntdb_l2_package_manifest_files(&manifest).unwrap_err();
        assert!(err.to_string().contains("invalid NTDB manifest file path"));
    }
}

#[test]
fn injection_l2_package_uses_cores_wolf_small_pin() {
    // One pin per shared model: the L2 package comes from Core's Wolf Small release.
    let small = patronus_ark_core::wolf::WolfModel::Small.spec();
    let package = NTDB_L2_PACKAGE_MANIFEST
        .iter()
        .find(|asset| asset.category == SecurityCategory::Injection)
        .unwrap();
    assert_eq!(
        (package.spec.repository, package.spec.revision),
        (small.repository, small.revision)
    );
}

#[test]
fn ntdb_l2_packages_keep_their_local_export_overrides() {
    // Core resolves `PATRONUS_NTDB_*_DIR` from each registered package.
    assert_eq!(
        NTDB_L2_PACKAGE_MANIFEST
            .iter()
            .map(|asset| asset.spec.env_override)
            .collect::<Vec<_>>(),
        [
            "PATRONUS_NTDB_INJECTION_DIR",
            "PATRONUS_NTDB_SENSITIVE_DOCUMENTS_DIR",
            "PATRONUS_NTDB_TOOL_CLASS_DIR",
            "PATRONUS_NTDB_TOOL_ACTION_DIR",
            "PATRONUS_NTDB_TOOL_TAGS_SINK_EXTERNAL_DIR",
            "PATRONUS_NTDB_TOOL_TAGS_SOURCE_SENSITIVE_DIR",
            "PATRONUS_NTDB_TOOL_TAGS_SOURCE_UNTRUSTED_DIR",
            "PATRONUS_NTDB_ROUTING_DIR",
            "PATRONUS_NTDB_THREAT_DIR",
        ]
        .map(Some)
    );
    let threat = NTDB_L2_PACKAGE_MANIFEST.last().unwrap().spec;
    let root = std::path::Path::new("/models");
    assert_eq!(
        threat.cache_dir(root),
        root.join("threat/l2_ntdb/threat_current")
    );
}
