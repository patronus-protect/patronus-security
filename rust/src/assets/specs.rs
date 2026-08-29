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
    revision: "0057606351626290b6b73d82aeb2ee566b69451f",
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
    revision: "30ea449339d1075a31fcffa9199ebee4f2cfaf9a",
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

pub const DEDICATED_L3_ASSETS: &[PipelineModelAssetSpec] = &[
    PipelineModelAssetSpec {
        category: SecurityCategory::Injection,
        model: "wolf-defender-small",
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        revision: "142fadc5474163d4c483cb761d5a6b02e3aa1741",
        destination_path: "injection/l3",
        files: &[
            "onnx/int8_int4_embeddings/model.onnx",
            "onnx/onnx_fp16/model_fp16.onnx",
            "config.json",
            "tokenizer.json",
            "tokenizer_config.json",
        ],
    },
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
        revision: "0f425da68608af007dceb56b35ef51992477877e",
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
        revision: "8c224609ed22841be6a53ac94e3dc20ee2c73757",
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
        revision: "374f97cb202ce3097ae0c7844f7ac0febb8f4fec",
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
        revision: "7a638cdefebd7f8a815cda3428ab98e57bf1fb08",
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
        revision: "f186c09846c325256a262babcd8558d4e5f93dc9",
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
        category: SecurityCategory::Injection,
        level: SecurityLevel::L3,
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        revision: Some("142fadc5474163d4c483cb761d5a6b02e3aa1741"),
        source_path: "config.json",
        destination_path: "l3/config.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::Injection,
        level: SecurityLevel::L3,
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        revision: Some("142fadc5474163d4c483cb761d5a6b02e3aa1741"),
        source_path: "tokenizer.json",
        destination_path: "l3/tokenizer.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::Injection,
        level: SecurityLevel::L3,
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        revision: Some("142fadc5474163d4c483cb761d5a6b02e3aa1741"),
        source_path: "tokenizer_config.json",
        destination_path: "l3/tokenizer_config.json",
        required: false,
    },
    AssetSpec {
        category: SecurityCategory::Injection,
        level: SecurityLevel::L3,
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        revision: Some("142fadc5474163d4c483cb761d5a6b02e3aa1741"),
        source_path: "onnx/int8_int4_embeddings/model.onnx",
        destination_path: "l3/onnx/int8_int4_embeddings/model.onnx",
        required: true,
    },
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
        model: "wolf-defender-small",
        repo: "patronus-studio/wolf-defender-prompt-injection-small",
        revision: "142fadc5474163d4c483cb761d5a6b02e3aa1741",
        source_prefix: "l2",
        destination_path: "l2_ntdb/injection_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::SensitiveDocument,
        level: SecurityLevel::L2,
        model: "orca-sonar-document-classifier",
        repo: "patronus-studio/orca-sonar-document-classifier",
        revision: "dd51a00ec62b99eb0efc77300679676508f8e583",
        source_prefix: "l2",
        destination_path: "l2_ntdb/sensitive_document_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolClass,
        level: SecurityLevel::L2,
        model: "unified-v3-tool-class",
        repo: "patronus-studio/husky-sight-tool-type-classifier",
        revision: "286be0dae164ac189bb79cfcb4f60cedd81aaa58",
        source_prefix: "l2",
        destination_path: "l2_ntdb/tool_class_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolAction,
        level: SecurityLevel::L2,
        model: "unified-v3-tool-action",
        repo: "patronus-studio/husky-paw-tool-action-classifier",
        revision: "54a95e983d0df6d13ceb2ce675bde7200238170b",
        source_prefix: "l2",
        destination_path: "l2_ntdb/tool_action_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolTags,
        level: SecurityLevel::L2,
        model: "tool_tags_sink_external",
        repo: "patronus-studio/husky-nose-tool-security-properties-classifier",
        revision: "66bb4bdd76f57aacba7a4e39e0368e35701b2244",
        source_prefix: "l2/sink_external",
        destination_path: "l2_ntdb/tool_tags_sink_external_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolTags,
        level: SecurityLevel::L2,
        model: "tool_tags_source_sensitive",
        repo: "patronus-studio/husky-nose-tool-security-properties-classifier",
        revision: "66bb4bdd76f57aacba7a4e39e0368e35701b2244",
        source_prefix: "l2/source_sensitive",
        destination_path: "l2_ntdb/tool_tags_source_sensitive_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolTags,
        level: SecurityLevel::L2,
        model: "tool_tags_source_untrusted",
        repo: "patronus-studio/husky-nose-tool-security-properties-classifier",
        revision: "66bb4bdd76f57aacba7a4e39e0368e35701b2244",
        source_prefix: "l2/source_untrusted",
        destination_path: "l2_ntdb/tool_tags_source_untrusted_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::Routing,
        level: SecurityLevel::L2,
        model: "unified-v3-routing",
        repo: "patronus-studio/panther-read-intent-classifier",
        revision: "3e997999c05a3a8be8ea6b3e23dd97126ca10d70",
        source_prefix: "l2",
        destination_path: "l2_ntdb/routing_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::Threat,
        level: SecurityLevel::L2,
        model: "unified-v3-threat",
        repo: "patronus-studio/wolf-defender-threat-classifier",
        revision: "ef87add2834a1a257754fbf9d7ba69df48aea733",
        source_prefix: "l2",
        destination_path: "l2_ntdb/threat_current",
        required: true,
    },
];
