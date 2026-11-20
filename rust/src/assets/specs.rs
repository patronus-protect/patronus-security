// SPDX-License-Identifier: GPL-3.0-only
use crate::{SecurityCategory, SecurityLevel};

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
    /// Public model identifier used by gates and scan results.
    pub model: &'static str,
    /// Hugging Face repository identifier.
    pub repo: &'static str,
    /// Immutable Hugging Face commit revision.
    pub revision: &'static str,
    /// Directory prefix inside the Hugging Face repository.
    pub source_prefix: &'static str,
    /// Relative package directory below the category cache directory.
    pub destination_path: &'static str,
    /// Whether missing or failed downloads should block `warmup`.
    pub required: bool,
}

#[derive(Debug, Clone, Copy)]
/// A revision-pinned model bundle used by a standalone pipeline.
pub struct PipelineModelAssetSpec {
    /// Scanner category that owns this pipeline model.
    pub category: SecurityCategory,
    /// Public model name.
    pub model: &'static str,
    /// Hugging Face repository identifier.
    pub repo: &'static str,
    /// Immutable Hugging Face commit revision.
    pub revision: &'static str,
    /// Relative bundle directory below the model cache.
    pub destination_path: &'static str,
    /// Files required to load and validate the bundle.
    pub files: &'static [&'static str],
}

pub const DYNAMIC_PII_ASSET: PipelineModelAssetSpec = PipelineModelAssetSpec {
    category: SecurityCategory::DynamicPii,
    model: "gliner_small-v2.5-edge",
    repo: "patronus-studio/gliner_small-v2.5-edge",
    revision: "6cfcbd93d7fc6f5e1658f80afa38f73891b91693",
    destination_path: "dynamic_pii/gliner_small_v2_5",
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
    model: "unified-multitask-model-augmented-v3",
    repo: "patronus-studio/lion-warden-ai-security-classifier",
    revision: "77888f617584758f904faefd6f38d4cf926f6d5d",
    destination_path: "unified_multitask_v3",
    files: &[
        "onnx/int8_int4_embeddings/model.onnx",
        "onnx/onnx_fp16/model_fp16.onnx",
        "onnx/quantization_manifest.json",
        "config.json",
        "tokenizer.json",
        "tokenizer_config.json",
    ],
};

/// Injection's public model: its L2 package lives in Core's pinned Wolf Small
/// repository, and its dedicated L3 is the Wolf model Core prepares.
pub const WOLF_PIPELINE_MODEL: &str = "wolf-defender-small";
const WOLF_SMALL: &patronus_ark_core::wolf::WolfModelSpec =
    &patronus_ark_core::wolf::WOLF_MODELS[patronus_ark_core::wolf::WolfModel::Small as usize];

/// Injection has no entry: Core prepares and pins the configured Wolf model.
pub const DEDICATED_L3_ASSETS: &[PipelineModelAssetSpec] = &[
    PipelineModelAssetSpec {
        category: SecurityCategory::SensitiveDocument,
        model: "orca-sonar-document-classifier",
        repo: "patronus-studio/orca-sonar-document-classifier",
        revision: "c038771b10b00b8da67d31e2b0280f85e13b808c",
        destination_path: "sensitive_document/prompts",
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
        model: "unified-v3-tool-class",
        repo: "patronus-studio/husky-sight-tool-type-classifier-edge",
        revision: "68e58725282dcdda106d8388fca47e0802335bc4",
        destination_path: "tool_class/l3",
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
    PipelineModelAssetSpec {
        category: SecurityCategory::ToolAction,
        model: "unified-v3-tool-action",
        repo: "patronus-studio/husky-paw-tool-action-classifier-edge",
        revision: "326adc8edfcaa5c65986cab2896c2e69bc3d36cc",
        destination_path: "tool_action/l3",
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
    PipelineModelAssetSpec {
        category: SecurityCategory::ToolTags,
        model: "unified-v3-tool-tags",
        repo: "patronus-studio/husky-nose-tool-security-properties-classifier-edge",
        revision: "4619a3c2c14c36f2e4c8ee5c9d65b1ea7b962cbd",
        destination_path: "tool_tags/l3",
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
    PipelineModelAssetSpec {
        category: SecurityCategory::Routing,
        model: "unified-v3-routing",
        repo: "patronus-studio/panther-read-intent-classifier-edge",
        revision: "ef7f1e20afda64f06be0e656184ab67c14061e6a",
        destination_path: "routing/l3",
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
    PipelineModelAssetSpec {
        category: SecurityCategory::UnsafeAction,
        model: "unified-v3-threat",
        repo: "patronus-studio/wolf-defender-threat-classifier",
        revision: "6520c1f43c716d1210321aecc7681446dd5ce317",
        destination_path: "threat/l3",
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

pub const NTDB_L2_PACKAGE_MANIFEST: &[NtdbL2PackageAssetSpec] = &[
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::Injection,
        level: SecurityLevel::L2,
        model: WOLF_PIPELINE_MODEL,
        repo: WOLF_SMALL.repository,
        revision: WOLF_SMALL.revision,
        source_prefix: "l2",
        destination_path: "l2_ntdb/injection_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L2,
        model: "orca-sonar-document-classifier",
        repo: "patronus-studio/orca-sonar-document-classifier",
        revision: "efa2b1724946fb2de5a22ce58ef99d7b246c2798",
        source_prefix: "l2",
        destination_path: "l2_ntdb/sensitive_document_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolClass,
        level: SecurityLevel::L2,
        model: "unified-v3-tool-class",
        repo: "patronus-studio/husky-sight-tool-type-classifier",
        revision: "de43b66056fc6b41e5f5c170712770ae805a4850",
        source_prefix: "l2",
        destination_path: "l2_ntdb/tool_class_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolAction,
        level: SecurityLevel::L2,
        model: "unified-v3-tool-action",
        repo: "patronus-studio/husky-paw-tool-action-classifier",
        revision: "b2f4a556e7c9b02606589c5c587e096503f274c5",
        source_prefix: "l2",
        destination_path: "l2_ntdb/tool_action_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolTags,
        level: SecurityLevel::L2,
        model: "tool_tags_sink_external",
        repo: "patronus-studio/husky-nose-tool-security-properties-classifier",
        revision: "f5736c09bcb6f75f1af3604706a1ee5c7e39d745",
        source_prefix: "l2/sink_external",
        destination_path: "l2_ntdb/tool_tags_sink_external_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolTags,
        level: SecurityLevel::L2,
        model: "tool_tags_source_sensitive",
        repo: "patronus-studio/husky-nose-tool-security-properties-classifier",
        revision: "f5736c09bcb6f75f1af3604706a1ee5c7e39d745",
        source_prefix: "l2/source_sensitive",
        destination_path: "l2_ntdb/tool_tags_source_sensitive_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolTags,
        level: SecurityLevel::L2,
        model: "tool_tags_source_untrusted",
        repo: "patronus-studio/husky-nose-tool-security-properties-classifier",
        revision: "f5736c09bcb6f75f1af3604706a1ee5c7e39d745",
        source_prefix: "l2/source_untrusted",
        destination_path: "l2_ntdb/tool_tags_source_untrusted_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::Routing,
        level: SecurityLevel::L2,
        model: "unified-v3-routing",
        repo: "patronus-studio/panther-read-intent-classifier",
        revision: "74ec1d568bdddc34d408d4e96ce52b5dd7789cbe",
        source_prefix: "l2",
        destination_path: "l2_ntdb/routing_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::UnsafeAction,
        level: SecurityLevel::L2,
        model: "unified-v3-threat",
        repo: "patronus-studio/wolf-defender-threat-classifier",
        revision: "6520c1f43c716d1210321aecc7681446dd5ce317",
        source_prefix: "l2",
        destination_path: "l2_ntdb/threat_current",
        required: true,
    },
];
