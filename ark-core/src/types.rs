use serde::{Deserialize, Serialize};
use std::collections::HashMap;
#[derive(Debug, Clone)]
/// A single classifier decision before it is wrapped in a public scan result.
pub struct EvaluationResult {
    /// Stable class label returned by the scanner.
    pub class_name: String,
    /// Confidence score in the inclusive range `0.0..=1.0` when available.
    pub confidence: f64,
    /// Security level that produced the decision.
    pub level: String,
}

#[derive(Debug, Clone)]
/// Per-layer evidence for a scan result.
pub struct LayerResult {
    /// Security level for this layer, for example `L1` or `L2`.
    pub level: String,
    /// Layer implementation type such as `native`, `l2`, or `l3`.
    pub layer_type: String,
    /// Stable class label returned by this layer.
    pub class_name: String,
    /// Confidence score in the inclusive range `0.0..=1.0` when available.
    pub confidence: f64,
    /// Whether the layer produced a matched decision.
    pub matched: bool,
    /// Wall-clock time spent in this layer, in milliseconds.
    pub duration_ms: f64,
    /// Threshold values that were applied by the layer.
    pub thresholds: HashMap<String, f64>,
    /// Layer-specific metadata, kept as JSON values for forward compatibility.
    pub details: HashMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Stable classifier decision envelope for downstream policy evaluation.
pub struct DecisionEnvelope {
    pub schema_version: String,
    pub final_result: DecisionResult,
    pub decision_candidate: Option<DecisionCandidate>,
    pub recommendation: DecisionRecommendation,
    pub candidates: Vec<DecisionCandidate>,
    pub terminality: DecisionTerminality,
    pub provenance: DecisionProvenance,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Final Ark verdict recorded inside a decision envelope.
pub struct DecisionResult {
    pub class_name: String,
    pub confidence: f64,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// One typed classifier candidate considered by final-decision arbitration.
pub struct DecisionCandidate {
    pub source: String,
    pub class_name: String,
    pub confidence: f64,
    pub acceptance_threshold: f64,
    pub accepted: bool,
    pub evidence: Option<HashMap<String, f64>>,
    /// Chunk-level evidence for the single final document decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_evidence: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Ark's calibrated default recommendation for a classifier result.
pub struct DecisionRecommendation {
    pub accepted: bool,
    pub final_arbitration: String,
    pub operating_point: String,
    pub acceptance_threshold: Option<f64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Terminal request state relevant to decision consumers.
pub struct DecisionTerminality {
    pub completion: String,
    pub degraded: bool,
    pub degradation_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Minimal provenance for a classifier decision envelope.
pub struct DecisionProvenance {
    pub ark_version: String,
    pub schema_version: String,
    pub model: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// One scored label returned by a multi-label classifier head.
pub struct LabelScore {
    pub label: String,
    pub confidence: f64,
    pub matched: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Supported scanner category.
pub enum SecurityCategory {
    /// Prompt injection and instruction hierarchy attacks.
    Injection,
    /// Data-loss-prevention checks for secrets and sensitive material.
    Dlp,
    /// Personally identifiable information checks.
    Pii,
    /// Dynamic zero-shot entity extraction in the L3 worker.
    DynamicPii,
    /// Sensitive document classification.
    SensitiveDocument,
    /// Tool type classification.
    ToolClass,
    /// Tool operation classification.
    ToolAction,
    /// Multi-label tool source and sink tags.
    ToolTags,
    /// Operational request routing.
    Routing,
    /// Security threat classification.
    Threat,
    /// Risk scoring for shell commands and scripts (POSIX, PowerShell, CMD).
    ShellCommand,
}

impl SecurityCategory {
    /// Return the canonical snake_case category string.
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityCategory::Injection => "injection",
            SecurityCategory::Dlp => "dlp",
            SecurityCategory::Pii => "pii",
            SecurityCategory::DynamicPii => "dynamic-pii",
            SecurityCategory::SensitiveDocument => "sensitive_document",
            SecurityCategory::ToolClass => "tool_class",
            SecurityCategory::ToolAction => "tool_action",
            SecurityCategory::ToolTags => "tool_tags",
            SecurityCategory::Routing => "routing",
            SecurityCategory::Threat => "threat",
            SecurityCategory::ShellCommand => "shell_command",
        }
    }

    /// Return whether this category is backed by one head of the unified classifier.
    pub fn is_unified_classifier(self) -> bool {
        matches!(
            self,
            Self::Injection
                | Self::SensitiveDocument
                | Self::ToolClass
                | Self::ToolAction
                | Self::ToolTags
                | Self::Routing
                | Self::Threat
        )
    }
}

impl std::str::FromStr for SecurityCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "injection" => Ok(SecurityCategory::Injection),
            "dlp" => Ok(SecurityCategory::Dlp),
            "pii" => Ok(SecurityCategory::Pii),
            "dynamic-pii" | "dynamic_pii" => Ok(SecurityCategory::DynamicPii),
            "sensitive_document" => Ok(SecurityCategory::SensitiveDocument),
            "tool_class" => Ok(SecurityCategory::ToolClass),
            "tool_action" => Ok(SecurityCategory::ToolAction),
            "tool_tags" => Ok(SecurityCategory::ToolTags),
            "routing" => Ok(SecurityCategory::Routing),
            "threat" => Ok(SecurityCategory::Threat),
            "shell_command" | "shell-command" => Ok(SecurityCategory::ShellCommand),
            _ => Err(format!("Unknown security category: {}", s)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
/// Exact evidence span returned by an entity-producing pipeline.
pub struct EvidenceSpan {
    pub label: String,
    pub text: String,
    pub score: f64,
    pub start_byte: usize,
    pub end_byte: usize,
    pub start_char: usize,
    pub end_char: usize,
}

#[derive(Debug, Clone)]
/// Public scan result returned by `SecurityGateway` methods.
pub struct NativeResult {
    /// Category that was scanned, for example `injection` or `dlp`.
    pub category: String,
    /// Stable class label for the final decision.
    pub class_name: String,
    /// Final confidence score in the inclusive range `0.0..=1.0` when available.
    pub confidence: f64,
    /// Highest layer that contributed the final decision.
    pub level: String,
    /// Model or native scanner name that produced the final decision.
    pub model: String,
    /// Sum of recorded layer durations, in milliseconds.
    pub duration_ms: f64,
    /// Ordered layer evidence that explains the final decision.
    pub layers: Vec<LayerResult>,
    /// Exact entity evidence returned by span-producing pipelines.
    pub evidence_spans: Vec<EvidenceSpan>,
    /// Per-label scores for multi-label classifier outputs.
    pub label_scores: Vec<LabelScore>,
    /// Structured classifier decision contract for policy consumers.
    pub decision: Option<DecisionEnvelope>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Runtime backend profile used to choose default L3 execution behavior.
pub enum ExecutionBackend {
    /// Keep conservative CPU defaults unless a caller overrides execution mode.
    #[default]
    Auto,
    /// CPU execution: prefer lazy L3 execution and low concurrency.
    Cpu,
    /// Platform GPU alias: DirectML on Windows, CUDA on Linux, unsupported on macOS.
    Gpu,
    /// CoreML execution provider.
    #[serde(rename = "coreml", alias = "core_ml")]
    CoreMl,
    /// CUDA execution provider.
    Cuda,
    /// DirectML execution provider.
    DirectMl,
    /// TensorRT execution provider.
    #[serde(rename = "tensorrt", alias = "tensor_rt")]
    TensorRt,
}

impl ExecutionBackend {
    /// Return the canonical snake_case backend string.
    pub fn as_str(self) -> &'static str {
        match self {
            ExecutionBackend::Auto => "auto",
            ExecutionBackend::Cpu => "cpu",
            ExecutionBackend::Gpu => "gpu",
            ExecutionBackend::CoreMl => "coreml",
            ExecutionBackend::Cuda => "cuda",
            ExecutionBackend::DirectMl => "directml",
            ExecutionBackend::TensorRt => "tensorrt",
        }
    }
}

impl std::str::FromStr for ExecutionBackend {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "auto" => Ok(ExecutionBackend::Auto),
            "cpu" => Ok(ExecutionBackend::Cpu),
            "gpu" => Ok(ExecutionBackend::Gpu),
            "coreml" | "core_ml" => Ok(ExecutionBackend::CoreMl),
            "cuda" => Ok(ExecutionBackend::Cuda),
            "directml" | "direct_ml" => Ok(ExecutionBackend::DirectMl),
            "tensorrt" | "tensor_rt" => Ok(ExecutionBackend::TensorRt),
            _ => Err(format!("Unknown execution backend: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
/// Caller-provided ONNX Runtime session options.
pub struct OnnxRuntimeOptions {
    pub intra_threads: Option<usize>,
    pub inter_threads: Option<usize>,
    pub spinning: Option<bool>,
}

impl OnnxRuntimeOptions {
    pub const fn constrained_cpu() -> Self {
        Self {
            intra_threads: Some(1),
            inter_threads: Some(1),
            spinning: Some(false),
        }
    }

    pub fn normalized(self) -> Self {
        Self {
            intra_threads: self.intra_threads.filter(|value| *value > 0),
            inter_threads: self.inter_threads.filter(|value| *value > 0),
            spinning: self.spinning,
        }
    }
}

impl Default for OnnxRuntimeOptions {
    fn default() -> Self {
        Self::constrained_cpu()
    }
}
