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

#[derive(Debug, Clone)]
/// Public scan result returned by `SecurityGateway` methods.
pub struct SecurityScanResult {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// Maximum scanner depth to run.
pub enum SecurityLevel {
    /// Native rule-based checks only.
    L1 = 1,
    /// Native checks plus L2 model-backed classifiers when assets are available.
    L2 = 2,
    /// Native, L2, and L3 model-backed classifiers when assets are available.
    L3 = 3,
}

impl SecurityLevel {
    /// Return the canonical uppercase level string.
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityLevel::L1 => "L1",
            SecurityLevel::L2 => "L2",
            SecurityLevel::L3 => "L3",
        }
    }
}

impl std::str::FromStr for SecurityLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "1" | "l1" => Ok(SecurityLevel::L1),
            "2" | "l2" => Ok(SecurityLevel::L2),
            "3" | "l3" => Ok(SecurityLevel::L3),
            _ => Err(format!("Unknown security level: {}", s)),
        }
    }
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
    /// Agentic tool prompt and execution risk checks.
    ToolClassifier,
    /// User-intent classification.
    UserIntent,
    /// Sensitive document classification.
    SensitiveDocuments,
    /// Tool description risk classification.
    ToolDescription,
}

impl SecurityCategory {
    /// Return the canonical snake_case category string.
    pub fn as_str(self) -> &'static str {
        match self {
            SecurityCategory::Injection => "injection",
            SecurityCategory::Dlp => "dlp",
            SecurityCategory::Pii => "pii",
            SecurityCategory::ToolClassifier => "tool_classifier",
            SecurityCategory::UserIntent => "user_intent",
            SecurityCategory::SensitiveDocuments => "sensitive_documents",
            SecurityCategory::ToolDescription => "tool_description",
        }
    }
}

impl std::str::FromStr for SecurityCategory {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "injection" => Ok(SecurityCategory::Injection),
            "dlp" => Ok(SecurityCategory::Dlp),
            "pii" => Ok(SecurityCategory::Pii),
            "tool_classifier" => Ok(SecurityCategory::ToolClassifier),
            "user_intent" => Ok(SecurityCategory::UserIntent),
            "sensitive_documents" => Ok(SecurityCategory::SensitiveDocuments),
            "tool_description" => Ok(SecurityCategory::ToolDescription),
            _ => Err(format!("Unknown security category: {}", s)),
        }
    }
}
