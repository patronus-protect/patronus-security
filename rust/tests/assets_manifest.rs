use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use patronus_ark::{
    assets::{
        category_assets, dedicated_l3_asset, dynamic_pii_assets_present, ntdb_l2_package_assets,
        ntdb_l2_package_assets_present, required_assets_present, DEDICATED_L3_ASSETS,
        DYNAMIC_PII_ASSET, UNIFIED_L3_ASSET,
    },
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
fn dynamic_pii_bundle_is_complete_and_revision_pinned() {
    assert_eq!(DYNAMIC_PII_ASSET.category, SecurityCategory::DynamicPii);
    assert_eq!(
        DYNAMIC_PII_ASSET.repo,
        "patronus-studio/gliner_small-v2.5-edge"
    );
    assert_eq!(DYNAMIC_PII_ASSET.revision.len(), 40);
    assert!(DYNAMIC_PII_ASSET
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
    assert!(!dynamic_pii_assets_present(&dir));
    for file in DYNAMIC_PII_ASSET.files {
        let path = dir.join(DYNAMIC_PII_ASSET.destination_path).join(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, b"asset").unwrap();
    }
    std::fs::write(
        dir.join(DYNAMIC_PII_ASSET.destination_path)
            .join(".patronus-revision"),
        DYNAMIC_PII_ASSET.revision,
    )
    .unwrap();
    assert!(dynamic_pii_assets_present(&dir));
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn unified_l3_bundle_and_dedicated_models_are_revision_pinned() {
    assert_eq!(
        UNIFIED_L3_ASSET.repo,
        "patronus-studio/lion-warden-ai-security-classifier"
    );
    assert_eq!(
        UNIFIED_L3_ASSET.revision,
        "30ea449339d1075a31fcffa9199ebee4f2cfaf9a"
    );
    assert!(UNIFIED_L3_ASSET
        .files
        .contains(&"onnx/int8_int4_embeddings/model.onnx"));
    assert!(UNIFIED_L3_ASSET
        .files
        .contains(&"onnx/onnx_fp16/model_fp16.onnx"));
    assert_eq!(DEDICATED_L3_ASSETS.len(), 7);
    for (category, revision) in [
        (
            SecurityCategory::Injection,
            "142fadc5474163d4c483cb761d5a6b02e3aa1741",
        ),
        (
            SecurityCategory::SensitiveDocument,
            "c038771b10b00b8da67d31e2b0280f85e13b808c",
        ),
        (
            SecurityCategory::ToolClass,
            "0f425da68608af007dceb56b35ef51992477877e",
        ),
        (
            SecurityCategory::ToolAction,
            "8c224609ed22841be6a53ac94e3dc20ee2c73757",
        ),
        (
            SecurityCategory::ToolTags,
            "374f97cb202ce3097ae0c7844f7ac0febb8f4fec",
        ),
        (
            SecurityCategory::Routing,
            "7a638cdefebd7f8a815cda3428ab98e57bf1fb08",
        ),
        (
            SecurityCategory::Threat,
            "f186c09846c325256a262babcd8558d4e5f93dc9",
        ),
    ] {
        let asset = dedicated_l3_asset(category).expect("dedicated L3 asset");
        assert_eq!(asset.revision, revision);
        assert!(asset
            .files
            .contains(&"onnx/int8_int4_embeddings/model.onnx"));
        if matches!(
            category,
            SecurityCategory::Injection
                | SecurityCategory::SensitiveDocument
                | SecurityCategory::Threat
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
            "0f425da68608af007dceb56b35ef51992477877e",
        ),
        (
            SecurityCategory::ToolAction,
            "patronus-studio/husky-paw-tool-action-classifier-edge",
            "patronus-studio/husky-paw-tool-action-classifier",
            "8c224609ed22841be6a53ac94e3dc20ee2c73757",
        ),
        (
            SecurityCategory::ToolTags,
            "patronus-studio/husky-nose-tool-security-properties-classifier-edge",
            "patronus-studio/husky-nose-tool-security-properties-classifier",
            "374f97cb202ce3097ae0c7844f7ac0febb8f4fec",
        ),
        (
            SecurityCategory::Routing,
            "patronus-studio/panther-read-intent-classifier-edge",
            "patronus-studio/panther-read-intent-classifier",
            "7a638cdefebd7f8a815cda3428ab98e57bf1fb08",
        ),
        (
            SecurityCategory::Threat,
            "patronus-studio/wolf-defender-threat-classifier",
            "patronus-studio/wolf-defender-threat-classifier",
            "f186c09846c325256a262babcd8558d4e5f93dc9",
        ),
    ] {
        let l3 = dedicated_l3_asset(category).expect("dedicated L3 asset");
        assert_eq!(l3.repo, l3_repo);
        assert_eq!(l3.revision, revision);

        let l2 = ntdb_l2_package_assets(category, SecurityLevel::L2);
        assert_eq!(
            l2.len(),
            if category == SecurityCategory::ToolTags {
                3
            } else {
                1
            }
        );
        assert!(l2.iter().all(|asset| asset.repo == l2_repo));
        assert!(l2
            .iter()
            .all(|asset| asset.source_prefix == "l2" || asset.source_prefix.starts_with("l2/")));
    }
}

#[test]
fn migrated_l3_models_do_not_reference_removed_edge_repositories() {
    let migrated = [
        UNIFIED_L3_ASSET,
        dedicated_l3_asset(SecurityCategory::Injection).unwrap(),
        dedicated_l3_asset(SecurityCategory::SensitiveDocument).unwrap(),
        dedicated_l3_asset(SecurityCategory::Threat).unwrap(),
    ];

    assert!(migrated.iter().all(|asset| !asset.repo.ends_with("-edge")));
    assert_eq!(
        migrated.map(|asset| asset.repo),
        [
            "patronus-studio/lion-warden-ai-security-classifier",
            "patronus-studio/wolf-defender-prompt-injection-small",
            "patronus-studio/orca-sonar-document-classifier",
            "patronus-studio/wolf-defender-threat-classifier",
        ]
    );
}

#[test]
fn l3_model_categories_have_required_l3_assets() {
    for category in [
        SecurityCategory::Injection,
        SecurityCategory::SensitiveDocument,
    ] {
        let assets = category_assets(category, SecurityLevel::L3);
        assert!(
            assets
                .iter()
                .any(|asset| asset.level == SecurityLevel::L3 && asset.required),
            "{category:?} should include required L3 assets"
        );
    }

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
        SecurityCategory::Threat,
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
            .map(|asset| asset.destination_path)
            .collect::<Vec<_>>(),
        vec!["l2_ntdb/injection_current"]
    );
    assert_eq!(
        ntdb_l2_package_assets(SecurityCategory::SensitiveDocument, SecurityLevel::L2)
            .iter()
            .map(|asset| asset.destination_path)
            .collect::<Vec<_>>(),
        vec!["l2_ntdb/sensitive_document_current"]
    );
    assert_eq!(
        ntdb_l2_package_assets(SecurityCategory::ToolClass, SecurityLevel::L2)
            .iter()
            .map(|asset| asset.destination_path)
            .collect::<Vec<_>>(),
        vec!["l2_ntdb/tool_class_current"]
    );
    for (category, model, destination) in [
        (
            SecurityCategory::ToolAction,
            "unified-v3-tool-action",
            "l2_ntdb/tool_action_current",
        ),
        (
            SecurityCategory::Routing,
            "unified-v3-routing",
            "l2_ntdb/routing_current",
        ),
        (
            SecurityCategory::Threat,
            "unified-v3-threat",
            "l2_ntdb/threat_current",
        ),
    ] {
        let assets = ntdb_l2_package_assets(category, SecurityLevel::L2);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].model, model);
        assert_eq!(assets[0].destination_path, destination);
        if category == SecurityCategory::ToolTags {
            assert_eq!(
                assets[0].repo,
                "patronus-studio/husky-nose-tool-security-properties-classifier"
            );
        }
    }
    let tool_tags = ntdb_l2_package_assets(SecurityCategory::ToolTags, SecurityLevel::L2);
    assert_eq!(tool_tags.len(), 3);
    assert_eq!(
        tool_tags
            .iter()
            .map(|asset| asset.model)
            .collect::<Vec<_>>(),
        vec![
            "tool_tags_sink_external",
            "tool_tags_source_sensitive",
            "tool_tags_source_untrusted",
        ]
    );
    assert!(tool_tags.iter().all(|asset| {
        asset.repo == "patronus-studio/husky-nose-tool-security-properties-classifier"
            && asset.revision == "66bb4bdd76f57aacba7a4e39e0368e35701b2244"
    }));
    assert!(ntdb_l2_package_assets(SecurityCategory::Dlp, SecurityLevel::L2).is_empty());
    assert!(ntdb_l2_package_assets(SecurityCategory::Pii, SecurityLevel::L2).is_empty());
}

#[test]
fn ntdb_l2_package_cache_requires_the_pinned_revision() {
    let dir = temp_dir("ntdb_revision");
    let asset = ntdb_l2_package_assets(SecurityCategory::Injection, SecurityLevel::L2)[0];
    let package_dir = dir.join(asset.destination_path);
    std::fs::create_dir_all(&package_dir).unwrap();
    std::fs::create_dir_all(package_dir.join("minilm")).unwrap();
    std::fs::write(
        package_dir.join("manifest.json"),
        r#"{
            "format":"ntdb_model_package","version":2,
            "runtime_contract":"raw_text_to_ntdb_outputs",
            "task":{"type":"binary","labels":["benign","attack"]},
            "chunk_size":1,"tokenizer_dir":"tokenizer",
            "minilm":{"embedding_matrix_file":"embedding_matrix.f16","vocab_size":1,
                "embedding_dim":1,"content_tokens_per_chunk":1,"tokenizer_family":"test"},
            "runtime":{"shared_preprocessing":["tokenization"],"parallel_stages":[],
                "ordering":"manifest_order"}
        }"#,
    )
    .unwrap();
    std::fs::write(package_dir.join("minilm/embedding_matrix.f16"), [0_u8; 2]).unwrap();

    assert!(!ntdb_l2_package_assets_present(
        SecurityCategory::Injection,
        SecurityLevel::L2,
        asset.model,
        &dir,
    ));
    std::fs::write(package_dir.join(".patronus-revision"), asset.revision).unwrap();
    assert!(ntdb_l2_package_assets_present(
        SecurityCategory::Injection,
        SecurityLevel::L2,
        asset.model,
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
        SecurityCategory::Threat,
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
        SecurityCategory::Threat,
        SecurityCategory::Pii,
    ] {
        let mut seen = HashSet::new();
        for asset in ntdb_l2_package_assets(category, SecurityLevel::L3) {
            assert!(
                seen.insert(asset.destination_path),
                "duplicate NTDB package destination for {category:?}: {}",
                asset.destination_path
            );
            assert!(asset.source_prefix == "l2" || asset.source_prefix.starts_with("l2/"));
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
    use patronus_ark::{SecurityCategory, SecurityLevel};

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
        assert_eq!(injection[0].model, "wolf-defender-small");
        assert_eq!(injection[0].source_prefix, "l2");
        assert_eq!(injection[0].destination_path, "l2_ntdb/injection_current");

        let sensitive =
            ntdb_l2_package_assets(SecurityCategory::SensitiveDocument, SecurityLevel::L2);
        assert_eq!(sensitive.len(), 1);
        assert_eq!(sensitive[0].model, "orca-sonar-document-classifier");
        assert_eq!(
            sensitive[0].destination_path,
            "l2_ntdb/sensitive_document_current"
        );

        for (category, model) in [
            (SecurityCategory::ToolClass, "unified-v3-tool-class"),
            (SecurityCategory::ToolAction, "unified-v3-tool-action"),
            (SecurityCategory::Routing, "unified-v3-routing"),
            (SecurityCategory::Threat, "unified-v3-threat"),
        ] {
            let assets = ntdb_l2_package_assets(category, SecurityLevel::L2);
            assert_eq!(assets.len(), 1);
            assert_eq!(assets[0].model, model);
        }
        let tool_tags = ntdb_l2_package_assets(SecurityCategory::ToolTags, SecurityLevel::L2);
        assert_eq!(tool_tags.len(), 3);
        assert!(tool_tags
            .iter()
            .all(|asset| asset.model.starts_with("tool_tags_")));
        assert!(ntdb_l2_package_assets(SecurityCategory::Dlp, SecurityLevel::L2).is_empty());
        assert!(ntdb_l2_package_assets(SecurityCategory::Pii, SecurityLevel::L2).is_empty());
    }

    #[test]
    fn manifest_excludes_legacy_l1_rules_and_keeps_l3_assets() {
        let injection_assets = category_assets(SecurityCategory::Injection, SecurityLevel::L3);
        assert!(injection_assets.iter().any(|asset| asset.source_path
            == "onnx/int8_int4_embeddings/model.onnx"
            && asset.destination_path == "l3/onnx/int8_int4_embeddings/model.onnx"
            && asset.required));

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
        assert!(pii_assets.is_empty());
    }

    #[test]
    fn ntdb_manifest_files_include_runtime_references() {
        let manifest = r#"{
            "format": "ntdb_model_package",
            "version": 2,
            "runtime_contract": "raw_text_to_ntdb_outputs",
            "task": {"type": "binary", "labels": ["benign", "attack"]},
            "chunk_size": 2,
            "tokenizer_dir": "tokenizer",
            "minilm": {
                "embedding_matrix_file": "embedding_matrix.f16",
                "vocab_size": 1,
                "embedding_dim": 1,
                "content_tokens_per_chunk": 2
            },
            "feature_contract": {
                "local_feature_order": [],
                "global_feature_order": []
            },
            "runtime": {
                "shared_preprocessing": ["tokenization"],
                "parallel_stages": [],
                "ordering": "manifest_order"
            },
            "heads": [{
                "id": "h",
                "type": "binary",
                "task": {"type": "binary", "labels": ["other", "target"]},
                "classifiers": [{"type": "custom", "path": "heads/h/custom.json"}],
                "feature_order": [],
                "static_dir": "heads/h",
                "static_components": [
                    {"type": "lightgbm", "path": "heads/h/lightgbm_model.txt"}
                ],
                "projection_onnx": "heads/h/projection.onnx",
                "ntdb_head_onnx": "heads/h/ntdb_head.onnx",
                "model_type": "sequential_ntdb",
                "reliability": {
                    "enabled": false,
                    "hidden_dim": 0,
                    "execution": "inside_onnx_model"
                }
            }],
            "aggregators": [{
                "id": "main",
                "type": "binary_sequential_aggregator",
                "task": {"type": "binary", "labels": ["benign", "attack"]},
                "onnx": "aggregators/main/aggregator.onnx",
                "model_type": "sequential_ntdb",
                "input_feature_order": [],
                "global_feature_order": [],
                "reliability": {
                    "enabled": false,
                    "hidden_dim": 0,
                    "execution": "inside_onnx_model"
                },
                "promote_router": {
                    "type": "layered_promote_router",
                    "onnx": "aggregators/main/promote_router.onnx",
                    "model_type": "sequential_ntdb",
                    "input_feature_order": [],
                    "global_feature_order": [],
                    "reliability": {
                        "enabled": false,
                        "hidden_dim": 0,
                        "execution": "inside_onnx_model"
                    }
                }
            }]
        }"#;

        let files = ntdb_l2_package_manifest_files(manifest).unwrap();
        assert_eq!(
            files,
            vec![
                "aggregators/main/aggregator.onnx",
                "aggregators/main/promote_router.onnx",
                "heads/h/custom.json",
                "heads/h/lightgbm_model.txt",
                "heads/h/ntdb_head.onnx",
                "heads/h/projection.onnx",
                "minilm/embedding_matrix.f16",
                "tokenizer/tokenizer.json"
            ]
        );
    }

    #[test]
    fn ntdb_manifest_files_reject_parent_paths() {
        let manifest = r#"{
            "format": "ntdb_model_package",
            "version": 2,
            "runtime_contract": "raw_text_to_ntdb_outputs",
            "task": {"type": "binary", "labels": ["benign", "attack"]},
            "chunk_size": 2,
            "tokenizer_dir": "../tokenizer",
            "minilm": {
                "embedding_matrix_file": "embedding_matrix.f16",
                "vocab_size": 1,
                "embedding_dim": 1,
                "content_tokens_per_chunk": 2
            },
            "feature_contract": {
                "local_feature_order": [],
                "global_feature_order": []
            },
            "runtime": {
                "shared_preprocessing": ["tokenization"],
                "parallel_stages": [],
                "ordering": "manifest_order"
            },
            "heads": [{
                "id": "h",
                "type": "binary",
                "task": {"type": "binary", "labels": ["other", "target"]},
                "classifiers": [],
                "feature_order": [],
                "static_dir": "heads/h",
                "static_components": [],
                "projection_onnx": null,
                "ntdb_head_onnx": "heads/h/ntdb_head.onnx",
                "model_type": "sequential_ntdb",
                "reliability": {
                    "enabled": false,
                    "hidden_dim": 0,
                    "execution": "inside_onnx_model"
                }
            }],
            "aggregators": [{
                "id": "main",
                "type": "binary_sequential_aggregator",
                "task": {"type": "binary", "labels": ["benign", "attack"]},
                "onnx": "aggregators/main/aggregator.onnx",
                "model_type": "sequential_ntdb",
                "input_feature_order": [],
                "global_feature_order": [],
                "reliability": {
                    "enabled": false,
                    "hidden_dim": 0,
                    "execution": "inside_onnx_model"
                }
            }]
        }"#;

        let err = ntdb_l2_package_manifest_files(manifest).unwrap_err();
        assert!(err.to_string().contains("invalid NTDB manifest file path"));
    }
}
