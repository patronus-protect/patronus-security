// SPDX-License-Identifier: GPL-3.0-only
use std::path::{Path, PathBuf};

use crate::{SecurityAssetProgressCallback, SecurityCategory, SecurityLevel};
use patronus_ark_core::{
    model_assets::{ModelSpec, PrepareOptions, Progress},
    warmup::DownloadPolicy,
    ScanError,
};

#[derive(Debug, Clone, Copy)]
/// A manifest-first NTDB L2 package declared for Hugging Face download.
pub struct NtdbL2PackageAssetSpec {
    /// Scanner category that owns this package.
    pub category: SecurityCategory,
    /// Minimum security level that needs this package.
    pub level: SecurityLevel,
    /// The pinned package: its id is the public model identifier used by gates and scan
    /// results, its source prefix the package directory inside the repository, and its
    /// environment override a local export that replaces the cached package.
    pub spec: ModelSpec,
    /// Whether missing or failed downloads should block `warmup`.
    pub required: bool,
}

#[derive(Debug, Clone, Copy)]
/// A revision-pinned model bundle used by a standalone pipeline.
pub struct PipelineModelAssetSpec {
    /// Scanner category that owns this pipeline model.
    pub category: SecurityCategory,
    /// The pinned bundle below the model cache; its id is the public model name.
    pub spec: ModelSpec,
    /// Files required to load and validate the bundle.
    pub files: &'static [&'static str],
}

pub const DYNAMIC_PII_ASSET: PipelineModelAssetSpec = PipelineModelAssetSpec {
    category: SecurityCategory::DynamicPii,
    spec: ModelSpec::new(
        "gliner_small-v2.5-edge",
        "patronus-studio/gliner_small-v2.5-edge",
        "6cfcbd93d7fc6f5e1658f80afa38f73891b91693",
        "dynamic_pii/gliner_small_v2_5",
    ),
    files: &[
        "gliner_config.json",
        "gliner_onnx_config.json",
        "model_int4_embeddings_int8.onnx",
        "onnx/fp16/model_fp16.onnx",
        "quantization_manifest.json",
        "special_tokens_map.json",
        "spm.model",
        "tokenizer.json",
        "tokenizer_config.json",
    ],
};

pub const UNIFIED_L3_ASSET: PipelineModelAssetSpec = PipelineModelAssetSpec {
    category: SecurityCategory::Injection,
    spec: ModelSpec::new(
        "unified-multitask-model-augmented-v3",
        "patronus-studio/lion-warden-ai-security-classifier",
        "77888f617584758f904faefd6f38d4cf926f6d5d",
        "unified_multitask_v3",
    ),
    files: &[
        "onnx/int8_int4_embeddings/model.onnx",
        "onnx/onnx_fp16/model_fp16.onnx",
        "onnx/quantization_manifest.json",
        "config.json",
        "tokenizer.json",
        "tokenizer_config.json",
    ],
};

impl PipelineModelAssetSpec {
    /// The bundle files this process loads: the fp16 graph replaces the quantized one
    /// when `PATRONUS_L3_PRECISION=fp16` and the bundle has one.
    pub fn selected_files(&self) -> Vec<&'static str> {
        let fp16 = prefer_fp16_l3();
        let fp16_path = if self.files.contains(&"onnx/onnx_fp16/model_fp16.onnx") {
            Some("onnx/onnx_fp16/model_fp16.onnx")
        } else if self.files.contains(&"onnx/fp16/model_fp16.onnx") {
            Some("onnx/fp16/model_fp16.onnx")
        } else {
            None
        };
        self.files
            .iter()
            .copied()
            .filter(|path| {
                if fp16 && fp16_path.is_some() {
                    *path != "onnx/int8_int4_embeddings/model.onnx"
                        && *path != "model_int4_embeddings_int8.onnx"
                } else {
                    Some(*path) != fp16_path
                }
            })
            .collect()
    }

    /// Prepare the selected bundle files below the model cache `root` with Core's
    /// [`ModelSpec::prepare`], reporting fetch progress as this model's asset progress.
    pub fn prepare(
        &self,
        root: &Path,
        download: DownloadPolicy,
        generate: bool,
        progress: Option<&SecurityAssetProgressCallback>,
    ) -> Result<PathBuf, ScanError> {
        let report = super::progress_reporter(progress, self.category, self.spec.id);
        self.spec.prepare(
            root,
            &self.selected_files(),
            &PrepareOptions {
                download,
                generate,
                progress: report.as_ref().map(|report| report as &Progress<'_>),
            },
        )
    }
}

pub(crate) fn prefer_fp16_l3() -> bool {
    std::env::var("PATRONUS_L3_PRECISION").is_ok_and(|value| value.eq_ignore_ascii_case("fp16"))
}

const WOLF_SMALL: &patronus_ark_core::wolf::WolfModelSpec =
    &patronus_ark_core::wolf::WOLF_MODELS[patronus_ark_core::wolf::WolfModel::Small as usize];
/// Injection's Wolf pipeline key in results, gates, policies and caches: Core's
/// Wolf Small id, whose repository holds the L2 package. It stays the same for
/// every configured Wolf size; the dedicated L3 runs the Wolf model Core
/// prepares and reports its id as the `wolf_model` metadata.
pub const WOLF_PIPELINE_MODEL: &str = WOLF_SMALL.id;

/// Return the revision-pinned dedicated L3 bundle for a classifier category.
pub fn dedicated_l3_asset(category: SecurityCategory) -> Option<PipelineModelAssetSpec> {
    DEDICATED_L3_ASSETS
        .iter()
        .copied()
        .find(|asset| asset.category == category)
}

/// Injection has no entry: Core prepares and pins the configured Wolf model.
pub const DEDICATED_L3_ASSETS: &[PipelineModelAssetSpec] = &[
    PipelineModelAssetSpec {
        category: SecurityCategory::SensitiveDocument,
        spec: ModelSpec::new(
            "orca-sonar-document-classifier",
            "patronus-studio/orca-sonar-document-classifier",
            "c038771b10b00b8da67d31e2b0280f85e13b808c",
            "sensitive_document/prompts",
        ),
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "onnx/onnx_fp16/model_fp16.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
    PipelineModelAssetSpec {
        category: SecurityCategory::ToolClass,
        spec: ModelSpec::new(
            "unified-v3-tool-class",
            "patronus-studio/husky-sight-tool-type-classifier-edge",
            "68e58725282dcdda106d8388fca47e0802335bc4",
            "tool_class/l3",
        ),
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
    PipelineModelAssetSpec {
        category: SecurityCategory::ToolAction,
        spec: ModelSpec::new(
            "unified-v3-tool-action",
            "patronus-studio/husky-paw-tool-action-classifier-edge",
            "326adc8edfcaa5c65986cab2896c2e69bc3d36cc",
            "tool_action/l3",
        ),
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
    PipelineModelAssetSpec {
        category: SecurityCategory::ToolTags,
        spec: ModelSpec::new(
            "unified-v3-tool-tags",
            "patronus-studio/husky-nose-tool-security-properties-classifier-edge",
            "4619a3c2c14c36f2e4c8ee5c9d65b1ea7b962cbd",
            "tool_tags/l3",
        ),
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
    PipelineModelAssetSpec {
        category: SecurityCategory::Routing,
        spec: ModelSpec::new(
            "unified-v3-routing",
            "patronus-studio/panther-read-intent-classifier-edge",
            "ef7f1e20afda64f06be0e656184ab67c14061e6a",
            "routing/l3",
        ),
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
    PipelineModelAssetSpec {
        category: SecurityCategory::UnsafeAction,
        spec: ModelSpec::new(
            "unified-v3-threat",
            "patronus-studio/wolf-defender-threat-classifier",
            "6520c1f43c716d1210321aecc7681446dd5ce317",
            "threat/l3",
        ),
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "onnx/onnx_fp16/model_fp16.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
];

pub const NTDB_INJECTION: NtdbL2PackageAssetSpec = NtdbL2PackageAssetSpec {
    category: SecurityCategory::Injection,
    level: SecurityLevel::L2,
    spec: ModelSpec::new(
        WOLF_PIPELINE_MODEL,
        WOLF_SMALL.repository,
        WOLF_SMALL.revision,
        "injection/l2_ntdb/injection_current",
    )
    .with_source_prefix("l2")
    .with_env_override("PATRONUS_NTDB_INJECTION_DIR"),
    required: true,
};

pub const NTDB_SENSITIVE_DOCUMENT: NtdbL2PackageAssetSpec = NtdbL2PackageAssetSpec {
    category: SecurityCategory::SensitiveDocument,
    level: SecurityLevel::L2,
    spec: ModelSpec::new(
        "orca-sonar-document-classifier",
        "patronus-studio/orca-sonar-document-classifier",
        "efa2b1724946fb2de5a22ce58ef99d7b246c2798",
        "sensitive_document/l2_ntdb/sensitive_document_current",
    )
    .with_source_prefix("l2")
    .with_env_override("PATRONUS_NTDB_SENSITIVE_DOCUMENTS_DIR"),
    required: true,
};

pub const NTDB_TOOL_CLASS: NtdbL2PackageAssetSpec = NtdbL2PackageAssetSpec {
    category: SecurityCategory::ToolClass,
    level: SecurityLevel::L2,
    spec: ModelSpec::new(
        "unified-v3-tool-class",
        "patronus-studio/husky-sight-tool-type-classifier",
        "de43b66056fc6b41e5f5c170712770ae805a4850",
        "tool_class/l2_ntdb/tool_class_current",
    )
    .with_source_prefix("l2")
    .with_env_override("PATRONUS_NTDB_TOOL_CLASS_DIR"),
    required: true,
};

pub const NTDB_TOOL_ACTION: NtdbL2PackageAssetSpec = NtdbL2PackageAssetSpec {
    category: SecurityCategory::ToolAction,
    level: SecurityLevel::L2,
    spec: ModelSpec::new(
        "unified-v3-tool-action",
        "patronus-studio/husky-paw-tool-action-classifier",
        "b2f4a556e7c9b02606589c5c587e096503f274c5",
        "tool_action/l2_ntdb/tool_action_current",
    )
    .with_source_prefix("l2")
    .with_env_override("PATRONUS_NTDB_TOOL_ACTION_DIR"),
    required: true,
};

pub const NTDB_TOOL_TAGS_SINK_EXTERNAL: NtdbL2PackageAssetSpec = NtdbL2PackageAssetSpec {
    category: SecurityCategory::ToolTags,
    level: SecurityLevel::L2,
    spec: ModelSpec::new(
        "tool_tags_sink_external",
        "patronus-studio/husky-nose-tool-security-properties-classifier",
        "f5736c09bcb6f75f1af3604706a1ee5c7e39d745",
        "tool_tags/l2_ntdb/tool_tags_sink_external_current",
    )
    .with_source_prefix("l2/sink_external")
    .with_env_override("PATRONUS_NTDB_TOOL_TAGS_SINK_EXTERNAL_DIR"),
    required: true,
};

pub const NTDB_TOOL_TAGS_SOURCE_SENSITIVE: NtdbL2PackageAssetSpec = NtdbL2PackageAssetSpec {
    category: SecurityCategory::ToolTags,
    level: SecurityLevel::L2,
    spec: ModelSpec::new(
        "tool_tags_source_sensitive",
        "patronus-studio/husky-nose-tool-security-properties-classifier",
        "f5736c09bcb6f75f1af3604706a1ee5c7e39d745",
        "tool_tags/l2_ntdb/tool_tags_source_sensitive_current",
    )
    .with_source_prefix("l2/source_sensitive")
    .with_env_override("PATRONUS_NTDB_TOOL_TAGS_SOURCE_SENSITIVE_DIR"),
    required: true,
};

pub const NTDB_TOOL_TAGS_SOURCE_UNTRUSTED: NtdbL2PackageAssetSpec = NtdbL2PackageAssetSpec {
    category: SecurityCategory::ToolTags,
    level: SecurityLevel::L2,
    spec: ModelSpec::new(
        "tool_tags_source_untrusted",
        "patronus-studio/husky-nose-tool-security-properties-classifier",
        "f5736c09bcb6f75f1af3604706a1ee5c7e39d745",
        "tool_tags/l2_ntdb/tool_tags_source_untrusted_current",
    )
    .with_source_prefix("l2/source_untrusted")
    .with_env_override("PATRONUS_NTDB_TOOL_TAGS_SOURCE_UNTRUSTED_DIR"),
    required: true,
};

pub const NTDB_ROUTING: NtdbL2PackageAssetSpec = NtdbL2PackageAssetSpec {
    category: SecurityCategory::Routing,
    level: SecurityLevel::L2,
    spec: ModelSpec::new(
        "unified-v3-routing",
        "patronus-studio/panther-read-intent-classifier",
        "74ec1d568bdddc34d408d4e96ce52b5dd7789cbe",
        "routing/l2_ntdb/routing_current",
    )
    .with_source_prefix("l2")
    .with_env_override("PATRONUS_NTDB_ROUTING_DIR"),
    required: true,
};

pub const NTDB_THREAT: NtdbL2PackageAssetSpec = NtdbL2PackageAssetSpec {
    category: SecurityCategory::UnsafeAction,
    level: SecurityLevel::L2,
    spec: ModelSpec::new(
        "unified-v3-threat",
        "patronus-studio/wolf-defender-threat-classifier",
        "6520c1f43c716d1210321aecc7681446dd5ce317",
        "threat/l2_ntdb/threat_current",
    )
    .with_source_prefix("l2")
    .with_env_override("PATRONUS_NTDB_THREAT_DIR"),
    required: true,
};

/// Every NTDB L2 package; packages live below `<category dir>/l2_ntdb` of the model cache.
pub const NTDB_L2_PACKAGE_MANIFEST: &[NtdbL2PackageAssetSpec] = &[
    NTDB_INJECTION,
    NTDB_SENSITIVE_DOCUMENT,
    NTDB_TOOL_CLASS,
    NTDB_TOOL_ACTION,
    NTDB_TOOL_TAGS_SINK_EXTERNAL,
    NTDB_TOOL_TAGS_SOURCE_SENSITIVE,
    NTDB_TOOL_TAGS_SOURCE_UNTRUSTED,
    NTDB_ROUTING,
    NTDB_THREAT,
];

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn preparing_a_cached_bundle_moves_its_graph_weights_only_when_asked_and_pinned() {
        use patronus_ark_core::onnx::{external_data_path, has_inline_weights, testing};
        let root =
            std::env::temp_dir().join(format!("patronus_pipeline_prepare_{}", std::process::id()));
        let asset = PipelineModelAssetSpec {
            category: SecurityCategory::ToolClass,
            spec: ModelSpec::new("external-data-test", "example/repo", "rev", "pipeline"),
            files: &["onnx/int8_int4_embeddings/model.onnx"],
        };
        let graph = root.join("pipeline/onnx/int8_int4_embeddings/model.onnx");
        fs::create_dir_all(graph.parent().unwrap()).unwrap();
        fs::write(&graph, testing::model_with_weights()).unwrap();

        // Without its revision marker the bundle is not the cached pin: offline
        // preparation fails and leaves it as it is.
        let error = asset
            .prepare(&root, DownloadPolicy::Never, true, None)
            .unwrap_err();
        assert!(error.to_string().contains("downloads disabled"), "{error}");
        assert!(has_inline_weights(&graph).unwrap());

        fs::write(root.join("pipeline/.patronus-revision"), "rev").unwrap();
        asset
            .prepare(&root, DownloadPolicy::Never, false, None)
            .unwrap();
        assert!(has_inline_weights(&graph).unwrap());
        let dir = asset
            .prepare(&root, DownloadPolicy::Never, true, None)
            .unwrap();
        assert_eq!(dir, root.join("pipeline"));
        assert!(!has_inline_weights(&graph).unwrap());
        assert!(external_data_path(&graph).is_file());

        fs::remove_dir_all(root).unwrap();
    }
}
