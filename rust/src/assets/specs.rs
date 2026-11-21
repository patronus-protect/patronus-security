// SPDX-License-Identifier: GPL-3.0-only
use crate::{SecurityCategory, SecurityLevel};
use patronus_ark_core::model_assets::ModelSpec;

#[derive(Debug, Clone, Copy)]
/// A model asset declared in the static download manifest.
pub struct AssetSpec {
    /// Scanner category that owns this asset.
    pub category: SecurityCategory,
    /// Minimum security level that needs this asset.
    pub level: SecurityLevel,
    /// Hugging Face repository identifier.
    pub repo: &'static str,
    /// Immutable Hugging Face commit revision, when the asset is pinned.
    pub revision: Option<&'static str>,
    /// File path inside the Hugging Face repository.
    pub source_path: &'static str,
    /// Relative path below the category cache directory.
    pub destination_path: &'static str,
    /// Whether missing or failed downloads should block `warmup`.
    pub required: bool,
}

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

const WOLF_SMALL: &patronus_ark_core::wolf::WolfModelSpec =
    &patronus_ark_core::wolf::WOLF_MODELS[patronus_ark_core::wolf::WolfModel::Small as usize];
/// Injection's Wolf pipeline key in results, gates, policies and caches: Core's
/// Wolf Small id, whose repository holds the L2 package. It stays the same for
/// every configured Wolf size; the dedicated L3 runs the Wolf model Core
/// prepares and reports its id as the `wolf_model` metadata.
pub const WOLF_PIPELINE_MODEL: &str = WOLF_SMALL.id;

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

pub const ASSET_MANIFEST: &[AssetSpec] = &[
    AssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        revision: Some("c038771b10b00b8da67d31e2b0280f85e13b808c"),
        source_path: "config.json",
        destination_path: "prompts/config.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        revision: Some("c038771b10b00b8da67d31e2b0280f85e13b808c"),
        source_path: "tokenizer.json",
        destination_path: "prompts/tokenizer.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        revision: Some("c038771b10b00b8da67d31e2b0280f85e13b808c"),
        source_path: "tokenizer_config.json",
        destination_path: "prompts/tokenizer_config.json",
        required: false,
    },
    AssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        revision: Some("c038771b10b00b8da67d31e2b0280f85e13b808c"),
        source_path: "onnx/int8_int4_embeddings/model.onnx",
        destination_path: "prompts/onnx/int8_int4_embeddings/model.onnx",
        required: true,
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
