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
    // Tool Classifier keeps L1 rules. The three Tool L2 models are NTDB packages.
    AssetSpec {
        category: SecurityCategory::ToolClassifier,
        level: SecurityLevel::L1,
        repo: "patronus-studio/tool-prompts-model",
        source_path: "l1/l1_rules.json",
        destination_path: "prompts/l1_rules.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::ToolClassifier,
        level: SecurityLevel::L1,
        repo: "patronus-studio/tool-executions-model",
        source_path: "l1/l1_rules.json",
        destination_path: "executions/l1_rules.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::ToolClassifier,
        level: SecurityLevel::L1,
        repo: "patronus-studio/tool-description-model",
        source_path: "l1/l1_rules.json",
        destination_path: "descriptions/l1_rules.json",
        required: true,
    },
    // User Intent has no NTDB L2 mapping yet. L1 rules may still be used at L1 only.
    AssetSpec {
        category: SecurityCategory::UserIntent,
        level: SecurityLevel::L1,
        repo: "patronus-studio/user-intent-model",
        source_path: "l1/l1_rules.json",
        destination_path: "prompts/l1_rules.json",
        required: true,
    },
    // Sensitive Documents L2 is NTDB-local-only in Phase 5. L1 rules and L3 stay.
    AssetSpec {
        category: SecurityCategory::SensitiveDocuments,
        level: SecurityLevel::L1,
        repo: "patronus-studio/orca-sonar-document-classifier",
        source_path: "l1/l1_rules.json",
        destination_path: "prompts/l1_rules.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::SensitiveDocuments,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        source_path: "tokenizer.json",
        destination_path: "prompts/tokenizer.json",
        required: true,
    },
    AssetSpec {
        category: SecurityCategory::SensitiveDocuments,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        source_path: "tokenizer_config.json",
        destination_path: "prompts/tokenizer_config.json",
        required: false,
    },
    AssetSpec {
        category: SecurityCategory::SensitiveDocuments,
        level: SecurityLevel::L3,
        repo: "patronus-studio/orca-sonar-document-classifier",
        source_path: "special_tokens_map.json",
        destination_path: "prompts/special_tokens_map.json",
        required: false,
    },
    AssetSpec {
        category: SecurityCategory::SensitiveDocuments,
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
        category: SecurityCategory::SensitiveDocuments,
        level: SecurityLevel::L2,
        model: "orca-sonar-document-classifier",
        repo: "patronus-studio/orca-sonar-document-classifier",
        source_prefix: "l2",
        destination_path: "l2_ntdb/sensitive_documents_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolClassifier,
        level: SecurityLevel::L2,
        model: "tool-prompts-model",
        repo: "patronus-studio/tool-prompts-model",
        source_prefix: "l2",
        destination_path: "l2_ntdb/tool_prompts_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolClassifier,
        level: SecurityLevel::L2,
        model: "tool-executions-model",
        repo: "patronus-studio/tool-executions-model",
        source_prefix: "l2",
        destination_path: "l2_ntdb/tool_executions_current",
        required: true,
    },
    NtdbL2PackageAssetSpec {
        category: SecurityCategory::ToolClassifier,
        level: SecurityLevel::L2,
        model: "tool-classifier-descriptions-model",
        repo: "patronus-studio/tool-description-model",
        source_prefix: "l2",
        destination_path: "l2_ntdb/tool_descriptions_current",
        required: true,
    },
];
