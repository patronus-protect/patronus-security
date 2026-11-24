use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use patronus_ark::assets::{
    dedicated_l3_asset, ntdb_l2_package_current, PipelineModelAssetSpec, DEDICATED_L3_ASSETS,
    DYNAMIC_PII_ASSET, NTDB_L2_PACKAGE_MANIFEST, UNIFIED_L3_ASSET,
};

use patronus_ark_core::{warmup::DownloadPolicy, SecurityCategory};

/// The NTDB L2 packages of `category`.
fn ntdb_packages(category: SecurityCategory) -> Vec<PipelineModelAssetSpec> {
    NTDB_L2_PACKAGE_MANIFEST
        .iter()
        .copied()
        .filter(|asset| asset.category == category)
        .collect()
}

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
    let offline =
        |dir: &std::path::Path| DYNAMIC_PII_ASSET.prepare(dir, DownloadPolicy::Never, false, None);
    assert!(offline(&dir).is_err());
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
    assert_eq!(
        offline(&dir).unwrap(),
        DYNAMIC_PII_ASSET.spec.cache_dir(&dir)
    );
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

        let l2 = ntdb_packages(category);
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
fn sensitive_document_l3_bundle_lands_where_its_l3_model_loads() {
    let sensitive = dedicated_l3_asset(SecurityCategory::SensitiveDocument).unwrap();
    // The dedicated L3 model loads `prompts/` below the category cache directory.
    assert_eq!(sensitive.spec.cache_subdir, "sensitive_document/prompts");
    for file in [
        "onnx/int8_int4_embeddings/model.onnx",
        "config.json",
        "tokenizer.json",
        "tokenizer_config.json",
    ] {
        assert!(sensitive.selected_files().contains(&file), "{file}");
    }
    // Injection L3 is Wolf: Core prepares the configured model.
    assert!(dedicated_l3_asset(SecurityCategory::Injection).is_none());
    assert!(dedicated_l3_asset(SecurityCategory::Pii).is_none());
}

#[test]
fn ntdb_l2_package_manifest_has_available_model_specs() {
    assert_eq!(
        ntdb_packages(SecurityCategory::Injection)
            .iter()
            .map(|asset| asset.spec.cache_subdir)
            .collect::<Vec<_>>(),
        vec![
            "injection/l2_ntdb/injection_current",
            "injection/l2_ntdb/injection_lion"
        ]
    );
    assert_eq!(
        ntdb_packages(SecurityCategory::SensitiveDocument)
            .iter()
            .map(|asset| asset.spec.cache_subdir)
            .collect::<Vec<_>>(),
        vec!["sensitive_document/l2_ntdb/sensitive_document_current"]
    );
    assert_eq!(
        ntdb_packages(SecurityCategory::ToolClass)
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
        let assets = ntdb_packages(category);
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
    let tool_tags = ntdb_packages(SecurityCategory::ToolTags);
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
    assert!(ntdb_packages(SecurityCategory::Dlp).is_empty());
    assert!(ntdb_packages(SecurityCategory::Pii).is_empty());
}

#[test]
fn ntdb_l2_package_cache_requires_the_pinned_revision() {
    let dir = temp_dir("ntdb_revision");
    let asset = ntdb_packages(SecurityCategory::Injection)[0];
    let package_dir = dir.join(asset.spec.cache_subdir);
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::create_dir_all(package_dir.join("minilm")).unwrap();
    let mut manifest: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/ntdb_v4.json")).unwrap();
    manifest["minilm"]["vocab_size"] = serde_json::json!(1);
    manifest["minilm"]["embedding_dim"] = serde_json::json!(1);
    std::fs::write(package_dir.join("manifest.json"), manifest.to_string()).unwrap();
    std::fs::write(package_dir.join("minilm/embedding_matrix.f16"), [0_u8; 2]).unwrap();

    assert!(!ntdb_l2_package_current(&asset.spec, &dir));
    std::fs::write(package_dir.join(".patronus-revision"), asset.spec.revision).unwrap();
    assert!(ntdb_l2_package_current(&asset.spec, &dir));
    std::fs::remove_dir_all(dir).unwrap();
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
        for asset in ntdb_packages(category) {
            assert!(
                seen.insert(asset.spec.cache_subdir),
                "duplicate NTDB package destination for {category:?}: {}",
                asset.spec.cache_subdir
            );
            assert!(
                asset.spec.source_prefix == "l2" || asset.spec.source_prefix.starts_with("l2/")
            );
        }
    }
}

mod asset_downloads {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::ntdb_packages;
    use patronus_ark::assets::{dedicated_l3_asset, ntdb_l2_package_manifest_files};
    use patronus_ark_core::{warmup::DownloadPolicy, SecurityCategory};

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
    fn ntdb_l2_package_specs_cover_available_models() {
        let injection = ntdb_packages(SecurityCategory::Injection);
        assert_eq!(
            injection
                .iter()
                .map(|asset| (
                    asset.spec.id,
                    asset.spec.source_prefix,
                    asset.spec.cache_subdir
                ))
                .collect::<Vec<_>>(),
            [
                (
                    "wolf-defender-small",
                    "l2",
                    "injection/l2_ntdb/injection_current"
                ),
                (
                    "wolf-defender-small",
                    "l2",
                    "injection/l2_ntdb/injection_lion"
                ),
            ]
        );

        let sensitive = ntdb_packages(SecurityCategory::SensitiveDocument);
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
            let assets = ntdb_packages(category);
            assert_eq!(assets.len(), 1);
            assert_eq!(assets[0].spec.id, model);
        }
        let tool_tags = ntdb_packages(SecurityCategory::ToolTags);
        assert_eq!(tool_tags.len(), 3);
        assert!(tool_tags
            .iter()
            .all(|asset| asset.spec.id.starts_with("tool_tags_")));
        assert!(ntdb_packages(SecurityCategory::Dlp).is_empty());
        assert!(ntdb_packages(SecurityCategory::Pii).is_empty());
    }

    #[test]
    fn a_missing_bundle_file_blocks_offline_preparation() {
        let dir = temp_dir("missing_required");
        let asset = dedicated_l3_asset(SecurityCategory::SensitiveDocument).unwrap();
        let bundle = asset.spec.cache_dir(&dir);
        // Every selected file except the first one, at the pinned revision.
        for file in asset.selected_files().into_iter().skip(1) {
            let path = bundle.join(file);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"test").unwrap();
        }
        fs::write(bundle.join(".patronus-revision"), asset.spec.revision).unwrap();

        let error = asset
            .prepare(&dir, DownloadPolicy::Never, false, None)
            .unwrap_err();
        assert!(error.to_string().contains("downloads disabled"), "{error}");
        fs::remove_dir_all(dir).unwrap();
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
fn ntdb_l2_packages_keep_their_local_export_overrides() {
    // Core resolves `PATRONUS_NTDB_*_DIR` from each registered package.
    assert_eq!(
        NTDB_L2_PACKAGE_MANIFEST
            .iter()
            .map(|asset| asset.spec.env_override)
            .collect::<Vec<_>>(),
        [
            "PATRONUS_NTDB_INJECTION_DIR",
            "PATRONUS_NTDB_INJECTION_LION_DIR",
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
