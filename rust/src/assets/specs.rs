// SPDX-License-Identifier: AGPL-3.0-only
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
    /// File path inside the Hugging Face repository.
    pub source_path: &'static str,
    /// Relative path below the category cache directory.
    pub destination_path: &'static str,
    /// Whether missing or failed downloads should block `warmup`.
    pub required: bool,
}

#[derive(Debug, Clone, Copy)]
/// A manifest-first NTDB v2 L2 package declared for Hugging Face download.
pub struct NtdbL2PackageAssetSpec {
    /// Scanner category that owns this package.
    pub category: SecurityCategory,
    /// Minimum security level that needs this package.
    pub level: SecurityLevel,
    /// Public model identifier used by gates and scan results.
    pub model: &'static str,
    /// Hugging Face repository identifier.
    pub repo: &'static str,
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
    revision: "1319787d9247f854b7bcf13299d66ab13aec762a",
    destination_path: "dynamic_pii/gliner_small_v2_5",
    files: &[
        "gliner_config.json",
        "gliner_onnx_config.json",
        "model_int4_embeddings_int8.onnx",
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
    revision: "5711c4169442da12f0f4ec20e32f90d940684d20",
    destination_path: "unified_multitask_v3",
    files: &[
        "onnx/int8_int4_embeddings/model.onnx",
        "onnx/quantization_manifest.json",
        "config.json",
        "tokenizer.json",
        "tokenizer_config.json",
    ],
};

pub const DEDICATED_L3_ASSETS: &[PipelineModelAssetSpec] = &[
    PipelineModelAssetSpec {
        category: SecurityCategory::ToolClass,
        model: "unified-v3-tool-class",
        repo: "patronus-studio/husky-sight-tool-type-classifier",
        revision: "d2e21547d9690f72d33b7852b65b16e14706e5d6",
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
        repo: "patronus-studio/husky-paw-tool-action-classifier",
        revision: "75a94e7651b812839b53fc52909b74120b965ff5",
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
        repo: "patronus-studio/husky-nose-tool-security-properties-classifier",
        revision: "5d1ecc7cd0c441284a86dc0dfecb0cc8c1180f49",
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
        repo: "patronus-studio/panther-read-intent-classifier",
        revision: "509b548cf3f87d9f4aaf83d5ed34e15b62f03b11",
        destination_path: "routing/l3",
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
    PipelineModelAssetSpec {
        category: SecurityCategory::Threat,
        model: "unified-v3-threat",
        repo: "patronus-studio/wolf-defender-threat-classifier",
        revision: "f7233204ce14185f4cbb4dc0b42ae43c88242c03",
        destination_path: "threat/l3",
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
];

pub const ASSET_MANIFEST: &[AssetSpec] = &[
    // Injection L2 is NTDB-local-only in Phase 5. These are L3 assets only.
    AssetSpec {
        category: SecurityCategory::Injection,
        level: SecurityLevel::L3,
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        source_path: "config.json",
        destination_path: "l3/config.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::Injection,
        level: SecurityLevel::L3,
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        source_path: "tokenizer.json",
        destination_path: "l3/tokenizer.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::Injection,
        level: SecurityLevel::L3,
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        source_path: "tokenizer_config.json",
        destination_path: "l3/tokenizer_config.json",
        required: false,
    },
    AssetSpec {
        category: SecurityCategory::Injection,
        level: SecurityLevel::L3,
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        source_path: "special_tokens_map.json",
        destination_path: "l3/special_tokens_map.json",
        required: false,
    },
    AssetSpec {
        category: SecurityCategory::Injection,
        level: SecurityLevel::L3,
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        source_path: "onnx/onnx_mixed/model_mixed.onnx",
        destination_path: "l3/onnx/onnx_mixed/model_mixed.onnx",
        required: true,
    },
    // Sensitive Documents L2 is NTDB-local-only in Phase 5. L3 assets stay.
    AssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        source_path: "tokenizer.json",
        destination_path: "prompts/tokenizer.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        source_path: "tokenizer_config.json",
        destination_path: "prompts/tokenizer_config.json",
        required: false,
    },
    AssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        source_path: "special_tokens_map.json",
        destination_path: "prompts/special_tokens_map.json",
        required: false,
    },
    AssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        source_path: "onnx/onnx_fp16/model_fp16.onnx",
        destination_path: "prompts/onnx/model_fp16.onnx",
        required: true,
    },
];

pub const NTDB_L2_PACKAGE_MANIFEST: &[NtdbL2PackageAssetSpec] = &[
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::Injection,
        level: SecurityLevel::L2,
        model: "wolf-defender-small",
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        source_prefix: "l2",
        destination_path: "l2_ntdb/injection_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L2,
        model: "orca-sonar-document-classifier",
        repo: "patronus-studio/orca-sonar-document-classifier",
        source_prefix: "l2",
        destination_path: "l2_ntdb/sensitive_document_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolClass,
        level: SecurityLevel::L2,
        model: "unified-v3-tool-class",
        repo: "patronus-studio/husky-sight-tool-type-classifier",
        source_prefix: "l2",
        destination_path: "l2_ntdb/tool_class_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolAction,
        level: SecurityLevel::L2,
        model: "unified-v3-tool-action",
        repo: "patronus-studio/husky-paw-tool-action-classifier",
        source_prefix: "l2",
        destination_path: "l2_ntdb/tool_action_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolTags,
        level: SecurityLevel::L2,
        model: "unified-v3-tool-tags",
        repo: "patronus-studio/husky-nose-tool-security-properties-classifier",
        source_prefix: "l2",
        destination_path: "l2_ntdb/tool_tags_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::Routing,
        level: SecurityLevel::L2,
        model: "unified-v3-routing",
        repo: "patronus-studio/panther-read-intent-classifier",
        source_prefix: "l2",
        destination_path: "l2_ntdb/routing_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::Threat,
        level: SecurityLevel::L2,
        model: "unified-v3-threat",
        repo: "patronus-studio/wolf-defender-threat-classifier",
        source_prefix: "l2",
        destination_path: "l2_ntdb/threat_current",
        required: true,
    },
];
