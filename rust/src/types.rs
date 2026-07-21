// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;

pub type RequestId = String;

/// Lifecycle state for an accepted queued request until its terminal event is consumed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityRequestState {
    /// At least one planned scanner or promoted L3 job can still publish an event.
    Running,
    /// All planned work has reached a terminal outcome.
    Finished(SecurityRequestCompletion),
}

/// Terminal outcome for one accepted queued request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityRequestCompletion {
    /// Every planned scanner completed without a failure.
    Complete,
    /// At least one usable result and at least one failure were produced.
    Degraded { failures: Vec<SecurityFailure> },
    /// No planned scanner produced a usable result.
    Failed { failures: Vec<SecurityFailure> },
}

/// Typed failure attached to one scanner stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFailure {
    pub stage: SecurityFailureStage,
    pub level: Option<SecurityLevel>,
    pub detector_id: Option<String>,
    pub kind: SecurityFailureKind,
    pub retryable: bool,
    pub message: String,
}

/// Runtime stage at which a security operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityFailureStage {
    Warmup,
    Asset,
    Scanner,
    Inference,
    Queue,
    Worker,
}

/// Stable failure classification for product logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityFailureKind {
    NotReady,
    MissingAsset,
    IntegrityFailure,
    InitializationFailure,
    InferenceFailure,
    Timeout,
    WorkerUnavailable,
    Internal,
}

/// Readiness of the configured scanner runtime by security level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityRuntimeReadiness {
    pub l1: SecurityLevelReadiness,
    pub l2: SecurityLevelReadiness,
    pub l3: SecurityLevelReadiness,
}

/// Readiness of model assets on disk before runtime warmup.
///
/// L1 is intentionally absent because native L1 scanners require no model
/// assets. Runtime readiness remains a separate contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAssetReadiness {
    pub l2: SecurityLevelReadiness,
    pub l3: SecurityLevelReadiness,
}

/// Progress emitted while configured model assets are downloaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAssetProgress {
    /// Pipeline category whose assets are currently being prepared.
    pub category: SecurityCategory,
    /// Public model identifier from the asset manifest.
    pub model: String,
    /// Files already present or downloaded for this model.
    pub completed_files: usize,
    /// Total files required by this model.
    pub total_files: usize,
}

/// Thread-safe callback used by asset preparation workers.
pub type SecurityAssetProgressCallback =
    std::sync::Arc<dyn Fn(SecurityAssetProgress) + Send + Sync>;

/// Readiness of one security level before request execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityLevelReadiness {
    Ready,
    NotConfigured,
    NotReady { failures: Vec<SecurityFailure> },
}

impl std::fmt::Display for SecurityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.message)
    }
}

impl std::error::Error for SecurityFailure {}

impl SecurityFailureStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Warmup => "warmup",
            Self::Asset => "asset",
            Self::Scanner => "scanner",
            Self::Inference => "inference",
            Self::Queue => "queue",
            Self::Worker => "worker",
        }
    }
}

impl SecurityFailureKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotReady => "not_ready",
            Self::MissingAsset => "missing_asset",
            Self::IntegrityFailure => "integrity_failure",
            Self::InitializationFailure => "initialization_failure",
            Self::InferenceFailure => "inference_failure",
            Self::Timeout => "timeout",
            Self::WorkerUnavailable => "worker_unavailable",
            Self::Internal => "internal",
        }
    }
}

/// Ordered event published by the queue.
#[derive(Debug, Clone)]
pub enum QueuedSecurityEvent {
    /// One usable scanner result.
    Result(QueuedSecurityScanResult),
    /// The unique terminal event for an accepted request.
    Finished {
        request_id: RequestId,
        completion: SecurityRequestCompletion,
    },
}

impl QueuedSecurityEvent {
    /// Return the request id carried by this event.
    pub fn request_id(&self) -> &str {
        match self {
            Self::Result(queued) => &queued.request_id,
            Self::Finished { request_id, .. } => request_id,
        }
    }
}

#[derive(Debug, Clone)]
/// A completed queued scan result together with the request that produced it.
pub struct QueuedSecurityScanResult {
    /// Request id returned by `SecurityGateway::enqueue`.
    pub request_id: RequestId,
    /// Complete classifier result published by L1/L2 or the L3 worker.
    pub result: SecurityScanResult,
}

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
    /// Exact entity evidence returned by span-producing pipelines.
    pub evidence_spans: Vec<crate::dynamic_pii::EvidenceSpan>,
    /// Per-label scores for multi-label classifier outputs.
    pub label_scores: Vec<LabelScore>,
}

#[derive(Debug, Clone, PartialEq)]
/// One scored label returned by a multi-label classifier head.
pub struct LabelScore {
    pub label: String,
    pub confidence: f64,
    pub matched: bool,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// How model pipelines execute ONNX L3 fallback batches.
pub enum OnnxBatchMode {
    /// Keep the existing lazy per-text ONNX execution path.
    LazyBatches,
    /// Execute all L3 fallback texts as one ONNX tensor batch where possible.
    TensorBatch,
}

impl OnnxBatchMode {
    /// Return the canonical snake_case mode string.
    pub fn as_str(self) -> &'static str {
        match self {
            OnnxBatchMode::LazyBatches => "lazy_batches",
            OnnxBatchMode::TensorBatch => "tensor_batch",
        }
    }
}

impl Default for OnnxBatchMode {
    fn default() -> Self {
        Self::LazyBatches
    }
}

impl std::str::FromStr for OnnxBatchMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "lazy" | "lazy_batches" | "lazybatches" => Ok(OnnxBatchMode::LazyBatches),
            "tensor" | "tensor_batch" | "tensorbatch" => Ok(OnnxBatchMode::TensorBatch),
            _ => Err(format!("Unknown ONNX batch mode: {}", s)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Calibrated NTDB operating point selected from each package manifest.
pub enum NtdbOperatingPoint {
    BestF1,
    BestPromote,
    BestFprInF1,
    BestFnrInF1,
    BestLatencyInF1,
}

impl NtdbOperatingPoint {
    /// Return the manifest key for this operating point.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BestF1 => "best_f1",
            Self::BestPromote => "best_promote",
            Self::BestFprInF1 => "best_fpr_in_f1",
            Self::BestFnrInF1 => "best_fnr_in_f1",
            Self::BestLatencyInF1 => "best_latency_in_f1",
        }
    }
}

impl Default for NtdbOperatingPoint {
    fn default() -> Self {
        Self::BestPromote
    }
}

impl std::str::FromStr for NtdbOperatingPoint {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "best_f1" => Ok(Self::BestF1),
            "best_promote" => Ok(Self::BestPromote),
            "best_fpr_in_f1" => Ok(Self::BestFprInF1),
            "best_fnr_in_f1" => Ok(Self::BestFnrInF1),
            "best_latency_in_f1" => Ok(Self::BestLatencyInF1),
            _ => Err(format!("Unknown NTDB operating point: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Runtime backend profile used to choose default L3 execution behavior.
pub enum ExecutionBackend {
    /// Keep conservative CPU defaults unless a caller overrides execution mode.
    Auto,
    /// CPU execution: prefer lazy L3 execution and low concurrency.
    Cpu,
    /// Platform GPU alias: DirectML on Windows, CUDA on Linux, unsupported on macOS.
    Gpu,
    /// CoreML execution provider.
    CoreMl,
    /// CUDA execution provider.
    Cuda,
    /// DirectML execution provider.
    DirectMl,
    /// TensorRT execution provider.
    TensorRt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Physical L3 classifier topology.
pub enum L3Strategy {
    /// Each promoted pipeline executes its own L3 model.
    Dedicated,
    /// Promoted classifier pipelines share one request-local multi-head model run.
    Multi,
}

impl L3Strategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dedicated => "dedicated",
            Self::Multi => "multi",
        }
    }
}

impl Default for L3Strategy {
    fn default() -> Self {
        Self::Dedicated
    }
}

impl std::str::FromStr for L3Strategy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_lowercase().replace('-', "_").as_str() {
            "dedicated" | "single" | "single_model" => Ok(Self::Dedicated),
            "multi" | "multitask" | "multi_task" => Ok(Self::Multi),
            _ => Err(format!("Unknown L3 strategy: {value}")),
        }
    }
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

impl Default for ExecutionBackend {
    fn default() -> Self {
        Self::Auto
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

#[derive(Debug, Clone)]
/// Caller-controlled execution gates for one scanner execution profile.
///
/// Unspecified gates default to enabled. `max_level` is still enforced by
/// `ScanExecution`, so a gate can only further restrict the configured scanner.
pub struct ScanGateMatrix {
    /// Optional L1 override. `None` means enabled.
    pub l1: Option<bool>,
    /// Optional L2 override. `None` means enabled.
    pub l2: Option<bool>,
    /// Optional L3 override. `None` means enabled.
    pub l3: Option<bool>,
    /// Optional per-model or per-native-scanner overrides keyed by result model
    /// names such as `native:mcp_runtime_risk` or `unified-v3-tool-action`.
    pub models: HashMap<String, bool>,
    /// L3 worker scheduling policy.
    pub l3_policy: L3SchedulerPolicy,
}

#[derive(Debug, Clone)]
/// Priority and timeout policy for centrally scheduled L3 work.
pub struct L3SchedulerPolicy {
    /// Whether model L3 work should be centrally queued by scan methods.
    pub enabled: bool,
    /// Ordered category/model priority list. Earlier entries run first.
    pub priority: Vec<String>,
    /// Per category/model timeout before an unstarted L3 job degrades.
    pub ttl_ms: HashMap<String, u64>,
    /// Initial execution-cost estimate per category/model. The worker replaces
    /// this gradually with observed wall time while it is running.
    pub estimated_cost_ms: HashMap<String, u64>,
    /// Compute-time credit granted during one fair-scheduling round.
    pub fairness_quantum_ms: u64,
    /// Maximum queue wait before the oldest job bypasses priority and cost.
    pub max_wait_ms: u64,
    /// Multiplier applied to L2 confidence when L3 degrades.
    pub degraded_factor: f64,
}

impl Default for L3SchedulerPolicy {
    fn default() -> Self {
        let mut ttl_ms = HashMap::new();
        ttl_ms.insert("injection".to_string(), 15_000);
        ttl_ms.insert("wolf-defender-small".to_string(), 15_000);
        ttl_ms.insert("dynamic-pii".to_string(), 12_000);
        ttl_ms.insert("gliner_small-v2.5-edge".to_string(), 12_000);
        ttl_ms.insert("sensitive_document".to_string(), 12_000);
        ttl_ms.insert("orca-sonar-document-classifier".to_string(), 12_000);
        for name in [
            "tool_class",
            "tool_action",
            "tool_tags",
            "routing",
            "threat",
            "unified-v3-tool-class",
            "unified-v3-tool-action",
            "unified-v3-tool-tags",
            "unified-v3-routing",
            "unified-v3-threat",
        ] {
            ttl_ms.insert(name.to_string(), 10_500);
        }
        ttl_ms.insert("unified-multitask-model-augmented-v3".to_string(), 15_000);
        let mut estimated_cost_ms = HashMap::new();
        estimated_cost_ms.insert("injection".to_string(), 200);
        estimated_cost_ms.insert("wolf-defender-small".to_string(), 200);
        estimated_cost_ms.insert("dynamic-pii".to_string(), 240);
        estimated_cost_ms.insert("gliner_small-v2.5-edge".to_string(), 240);
        estimated_cost_ms.insert("sensitive_document".to_string(), 150);
        estimated_cost_ms.insert("orca-sonar-document-classifier".to_string(), 150);
        for name in [
            "tool_class",
            "tool_action",
            "tool_tags",
            "routing",
            "threat",
            "unified-v3-tool-class",
            "unified-v3-tool-action",
            "unified-v3-tool-tags",
            "unified-v3-routing",
            "unified-v3-threat",
        ] {
            estimated_cost_ms.insert(name.to_string(), 150);
        }
        estimated_cost_ms.insert("unified-multitask-model-augmented-v3".to_string(), 200);
        Self {
            enabled: true,
            priority: vec![
                "injection".to_string(),
                "wolf-defender-small".to_string(),
                "dynamic-pii".to_string(),
                "gliner_small-v2.5-edge".to_string(),
                "sensitive_document".to_string(),
                "orca-sonar-document-classifier".to_string(),
                "tool_class".to_string(),
                "tool_action".to_string(),
                "tool_tags".to_string(),
                "routing".to_string(),
                "threat".to_string(),
                "unified-multitask-model-augmented-v3".to_string(),
            ],
            ttl_ms,
            estimated_cost_ms,
            fairness_quantum_ms: 50,
            max_wait_ms: 2_000,
            degraded_factor: 0.75,
        }
    }
}

impl Default for ScanGateMatrix {
    fn default() -> Self {
        Self::all_enabled()
    }
}

impl ScanGateMatrix {
    /// Create a matrix where every level and model is enabled by default.
    pub fn all_enabled() -> Self {
        Self {
            l1: None,
            l2: None,
            l3: None,
            models: HashMap::new(),
            l3_policy: L3SchedulerPolicy::default(),
        }
    }

    /// Create a matrix with explicit level gates.
    pub fn levels(l1: bool, l2: bool, l3: bool) -> Self {
        Self {
            l1: Some(l1),
            l2: Some(l2),
            l3: Some(l3),
            models: HashMap::new(),
            l3_policy: L3SchedulerPolicy::default(),
        }
    }

    /// Set one level gate.
    pub fn set_level(&mut self, level: SecurityLevel, enabled: bool) {
        match level {
            SecurityLevel::L1 => self.l1 = Some(enabled),
            SecurityLevel::L2 => self.l2 = Some(enabled),
            SecurityLevel::L3 => self.l3 = Some(enabled),
        }
    }

    /// Set one model/native scanner gate.
    pub fn set_model(&mut self, model: impl Into<String>, enabled: bool) {
        self.models.insert(model.into(), enabled);
    }

    /// Builder-style model/native scanner gate setter.
    pub fn with_model(mut self, model: impl Into<String>, enabled: bool) -> Self {
        self.set_model(model, enabled);
        self
    }

    /// Return whether the level is allowed by this matrix before max-level
    /// enforcement.
    pub fn allows_level(&self, level: SecurityLevel) -> bool {
        match level {
            SecurityLevel::L1 => self.l1.unwrap_or(true),
            SecurityLevel::L2 => self.l2.unwrap_or(true),
            SecurityLevel::L3 => self.l3.unwrap_or(true),
        }
    }

    /// Return whether the model/native scanner is allowed by this matrix.
    pub fn allows_model(&self, model: &str) -> bool {
        self.models.get(model).copied().unwrap_or(true)
    }

    /// Replace the L3 worker scheduling policy.
    pub fn set_l3_policy(&mut self, policy: L3SchedulerPolicy) {
        self.l3_policy = policy;
    }
}

#[derive(Debug, Clone)]
/// Effective execution state consumed by scan methods and model pipelines.
pub struct ScanExecution {
    max_level: SecurityLevel,
    gates: ScanGateMatrix,
    backend: ExecutionBackend,
    onnx_batch_mode: OnnxBatchMode,
    ntdb_operating_point: NtdbOperatingPoint,
    l3_strategy: L3Strategy,
    defer_l3: bool,
}

impl ScanExecution {
    /// Create an execution with every gate enabled up to `max_level`.
    pub fn new(max_level: SecurityLevel) -> Self {
        Self {
            max_level,
            gates: ScanGateMatrix::all_enabled(),
            backend: ExecutionBackend::default(),
            onnx_batch_mode: OnnxBatchMode::LazyBatches,
            ntdb_operating_point: NtdbOperatingPoint::default(),
            l3_strategy: L3Strategy::default(),
            defer_l3: false,
        }
    }

    /// Create an execution with explicit gates up to `max_level`.
    pub fn with_gates(max_level: SecurityLevel, gates: ScanGateMatrix) -> Self {
        Self {
            max_level,
            gates,
            backend: ExecutionBackend::default(),
            onnx_batch_mode: OnnxBatchMode::LazyBatches,
            ntdb_operating_point: NtdbOperatingPoint::default(),
            l3_strategy: L3Strategy::default(),
            defer_l3: false,
        }
    }

    /// Replace the gate matrix.
    pub fn set_gates(&mut self, gates: ScanGateMatrix) {
        self.gates = gates;
    }

    /// Replace the ONNX batch execution mode.
    pub fn set_onnx_batch_mode(&mut self, mode: OnnxBatchMode) {
        self.onnx_batch_mode = mode;
    }

    /// Replace the execution backend and apply its default L3 batch mode.
    pub fn set_backend(&mut self, backend: ExecutionBackend) {
        self.backend = backend;
        self.onnx_batch_mode = match backend {
            ExecutionBackend::Auto | ExecutionBackend::Cpu => OnnxBatchMode::LazyBatches,
            ExecutionBackend::Gpu
            | ExecutionBackend::CoreMl
            | ExecutionBackend::Cuda
            | ExecutionBackend::DirectMl
            | ExecutionBackend::TensorRt => OnnxBatchMode::TensorBatch,
        };
    }

    /// Select the calibrated NTDB operating point used by subsequent scans.
    pub fn set_ntdb_operating_point(&mut self, point: NtdbOperatingPoint) {
        self.ntdb_operating_point = point;
    }

    /// Select the physical L3 classifier topology.
    pub fn set_l3_strategy(&mut self, strategy: L3Strategy) {
        self.l3_strategy = strategy;
    }

    /// Set whether L3 should be marked pending instead of executed immediately.
    pub fn set_defer_l3(&mut self, defer_l3: bool) {
        self.defer_l3 = defer_l3;
    }

    /// Return a copy with a different max-level cap.
    pub fn with_max_level(mut self, max_level: SecurityLevel) -> Self {
        self.max_level = max_level;
        self
    }

    /// Return whether a level is enabled for this execution after max-level
    /// enforcement.
    pub fn allows_level(&self, level: SecurityLevel) -> bool {
        level <= self.max_level && self.gates.allows_level(level)
    }

    /// Return whether a model/native scanner is enabled for this execution.
    pub fn allows_model(&self, model: &str) -> bool {
        self.gates.allows_model(model)
    }

    /// Return the matrix backing this execution.
    pub fn gates(&self) -> &ScanGateMatrix {
        &self.gates
    }

    /// Return the ONNX batch mode backing this execution.
    pub fn onnx_batch_mode(&self) -> OnnxBatchMode {
        self.onnx_batch_mode
    }

    /// Return the configured execution backend.
    pub fn backend(&self) -> ExecutionBackend {
        self.backend
    }

    /// Return the selected NTDB operating point.
    pub fn ntdb_operating_point(&self) -> NtdbOperatingPoint {
        self.ntdb_operating_point
    }

    /// Return the selected physical L3 classifier topology.
    pub fn l3_strategy(&self) -> L3Strategy {
        self.l3_strategy
    }

    /// Return whether L3 should be centrally scheduled.
    pub fn defer_l3(&self) -> bool {
        self.defer_l3
    }

    /// Return the L3 worker policy.
    pub fn l3_policy(&self) -> &L3SchedulerPolicy {
        &self.gates.l3_policy
    }

    /// Return the max-level cap backing this execution.
    pub fn max_level(&self) -> SecurityLevel {
        self.max_level
    }
}

impl Default for ScanExecution {
    fn default() -> Self {
        Self::new(SecurityLevel::L3)
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
            _ => Err(format!("Unknown security category: {}", s)),
        }
    }
}
