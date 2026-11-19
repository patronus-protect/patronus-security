// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

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
    QueueFull,
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
/// Native L1 rule scanners require no model assets, so `l1` is configured only
/// for model-backed L1 categories such as `shell_command`. Runtime readiness
/// remains a separate contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityAssetReadiness {
    pub l1: SecurityLevelReadiness,
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
            Self::QueueFull => "queue_full",
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
    /// Non-authoritative progress for UI status.
    Progress(QueuedSecurityProgress),
    /// Non-authoritative interim result for UI preview.
    Provisional(QueuedSecurityScanResult),
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
            Self::Progress(progress) => &progress.request_id,
            Self::Provisional(queued) => &queued.request_id,
            Self::Finished { request_id, .. } => request_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// Progress emitted while L3 resolves a multi-chunk request.
pub struct QueuedSecurityProgress {
    pub request_id: RequestId,
    pub category: String,
    pub model: String,
    pub stage: String,
    pub completed_chunks: usize,
    pub total_chunks: usize,
    pub inferred_chunks: usize,
    pub propagated_chunks: usize,
    pub cache_hits: usize,
    pub early_exit: bool,
    pub coverage: f64,
    pub details: HashMap<String, serde_json::Value>,
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
    /// Internal L2 chunk outputs reused by L3 planning. This field is cleared
    /// before results are published outside the gateway.
    #[doc(hidden)]
    pub internal_l2_chunk_outputs: Vec<crate::ml::ntdb_executor::L2ChunkOutput>,
    /// Exact entity evidence returned by span-producing pipelines.
    pub evidence_spans: Vec<crate::dynamic_pii::EvidenceSpan>,
    /// Per-label scores for multi-label classifier outputs.
    pub label_scores: Vec<LabelScore>,
    /// Structured classifier decision contract for policy consumers.
    pub decision: Option<DecisionEnvelope>,
    /// Stage that gave the category its final answer (`heuristic` for an L1
    /// result, `l2`, `l3`); `None` while a later layer still answers.
    pub decided_by: Option<Stage>,
    /// With the opt-in cascade, L1's answer (`detected` or `clear`) when L1
    /// decided the category, as Core's `ModuleDecision::outcome`: a detection
    /// at a lowered `detect_threshold` shows here even when the native class
    /// stays `safe`. `None` otherwise.
    pub l1_outcome: Option<StageOutcome>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
/// How model pipelines execute ONNX L3 fallback batches.
pub enum OnnxBatchMode {
    /// Keep the existing lazy per-text ONNX execution path.
    #[default]
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
/// Calibrated NTDB operating point selected from each package manifest.
pub enum NtdbOperatingPoint {
    BestF1,
    #[default]
    BestPromote,
    /// Internal Ark API routing profile: use utility promotion only for an
    /// Injection document with at most two normal chunks.
    ArkApiShortInjectionUtility,
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
            Self::ArkApiShortInjectionUtility => "ark_api_short_injection_utility",
            Self::BestFprInF1 => "best_fpr_in_f1",
            Self::BestFnrInF1 => "best_fnr_in_f1",
            Self::BestLatencyInF1 => "best_latency_in_f1",
        }
    }
}

impl std::str::FromStr for NtdbOperatingPoint {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('-', "_").as_str() {
            "best_f1" => Ok(Self::BestF1),
            "best_promote" => Ok(Self::BestPromote),
            "ark_api_short_injection_utility" => Ok(Self::ArkApiShortInjectionUtility),
            "best_fpr_in_f1" => Ok(Self::BestFprInF1),
            "best_fnr_in_f1" => Ok(Self::BestFnrInF1),
            "best_latency_in_f1" => Ok(Self::BestLatencyInF1),
            _ => Err(format!("Unknown NTDB operating point: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Physical L3 classifier topology.
pub enum L3Strategy {
    /// Each promoted pipeline executes its own L3 model.
    Dedicated,
    /// Promoted classifier pipelines share one request-local multi-head model run.
    Multi,
}

impl Default for L3Strategy {
    fn default() -> Self {
        defaults::RUST_L3_STRATEGY
    }
}

/// The defaults of Ark's three entry points, named in one place. They differ
/// on purpose and each entry point reads its own value from here:
///
/// | entry point | max level | L3 strategy | NTDB operating point |
/// |---|---|---|---|
/// | Rust `SecurityGateway` / `ScanExecution` | `L3` | `dedicated` | `best_promote` |
/// | Python `SecurityGateway(...)` | `l2` | `dedicated` | `best_f1` |
/// | Ark API server (`pipeline.l3_strategy`) | per config | `multi` | per config |
pub mod defaults {
    use super::L3Strategy;

    /// L3 topology of the Rust API (`L3Strategy::default()`).
    pub const RUST_L3_STRATEGY: L3Strategy = L3Strategy::Dedicated;
    /// Deepest layer of the Python `SecurityGateway`.
    pub const PYTHON_MAX_LEVEL: &str = "l2";
    /// L3 topology of the Python `SecurityGateway`.
    pub const PYTHON_L3_STRATEGY: &str = "dedicated";
    /// NTDB operating point of the Python `SecurityGateway`.
    pub const PYTHON_NTDB_OPERATING_POINT: &str = "best_f1";
    /// L3 topology of the Ark API server when `pipeline.l3_strategy` is unset.
    pub const ARK_API_L3_STRATEGY: L3Strategy = L3Strategy::Multi;
}

impl L3Strategy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dedicated => "dedicated",
            Self::Multi => "multi",
        }
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

#[derive(Debug, Clone)]
/// Effective execution state consumed by scan methods and model pipelines:
/// the Core [`LayerExecution`] (max level and gates, reached through `Deref`)
/// plus Ark's runtime and NTDB settings.
pub struct ScanExecution {
    layers: LayerExecution,
    backend: ExecutionBackend,
    onnx_runtime_options: OnnxRuntimeOptions,
    onnx_batch_mode: OnnxBatchMode,
    ntdb_operating_point: NtdbOperatingPoint,
    ntdb_decision_threshold_point: NtdbOperatingPoint,
    l3_strategy: L3Strategy,
    defer_l3: bool,
    chunk_overlap_tokens: usize,
    wolf_execution_options: crate::WolfExecutionOptions,
    wolf_selection: WolfSelection,
}

/// The Wolf Defender model and ONNX export the dedicated injection L3 loads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WolfSelection {
    pub model: crate::WolfModel,
    pub precision: crate::WolfPrecision,
}

impl std::ops::Deref for ScanExecution {
    type Target = LayerExecution;

    fn deref(&self) -> &LayerExecution {
        &self.layers
    }
}

impl std::ops::DerefMut for ScanExecution {
    fn deref_mut(&mut self) -> &mut LayerExecution {
        &mut self.layers
    }
}

impl ScanExecution {
    /// Create an execution with shared rule defaults up to `max_level`.
    pub fn new(max_level: SecurityLevel) -> Self {
        Self::with_gates(max_level, ScanGateMatrix::default())
    }

    /// Create an execution with explicit gates up to `max_level`.
    pub fn with_gates(max_level: SecurityLevel, gates: ScanGateMatrix) -> Self {
        Self {
            layers: LayerExecution::with_gates(max_level, gates),
            backend: ExecutionBackend::default(),
            onnx_runtime_options: OnnxRuntimeOptions::default(),
            onnx_batch_mode: OnnxBatchMode::LazyBatches,
            ntdb_operating_point: NtdbOperatingPoint::default(),
            ntdb_decision_threshold_point: NtdbOperatingPoint::BestF1,
            l3_strategy: L3Strategy::default(),
            defer_l3: false,
            chunk_overlap_tokens: 0,
            wolf_execution_options: crate::WolfExecutionOptions::default(),
            wolf_selection: WolfSelection::default(),
        }
    }

    /// Choose the Wolf model and export; an unknown `auto` override fails here, not on first use.
    pub fn set_wolf_selection(&mut self, selection: WolfSelection) -> Result<(), String> {
        selection.precision.resolve().map_err(|e| e.to_string())?;
        self.wolf_selection = selection;
        Ok(())
    }

    pub fn wolf_selection(&self) -> WolfSelection {
        self.wolf_selection
    }

    /// Configure dedicated Wolf execution using the shared Core validation.
    pub fn set_wolf_execution_options(
        &mut self,
        options: crate::WolfExecutionOptions,
    ) -> Result<(), String> {
        options.validate().map_err(|e| e.to_string())?;
        self.wolf_execution_options = options;
        Ok(())
    }

    pub fn wolf_execution_options(&self) -> crate::WolfExecutionOptions {
        self.wolf_execution_options
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

    /// Replace ONNX Runtime session options used by L3 ONNX classifiers.
    pub fn set_onnx_runtime_options(&mut self, options: OnnxRuntimeOptions) {
        self.onnx_runtime_options = options.normalized();
    }

    /// Select the calibrated NTDB operating point used by subsequent scans.
    pub fn set_ntdb_operating_point(&mut self, point: NtdbOperatingPoint) {
        self.ntdb_operating_point = point;
    }

    /// Select the calibrated NTDB final-decision threshold set.
    pub fn set_ntdb_decision_threshold_point(&mut self, point: NtdbOperatingPoint) {
        self.ntdb_decision_threshold_point = point;
    }

    /// Select the physical L3 classifier topology.
    pub fn set_l3_strategy(&mut self, strategy: L3Strategy) {
        self.l3_strategy = strategy;
    }

    /// Set whether L3 should be marked pending instead of executed immediately.
    pub fn set_defer_l3(&mut self, defer_l3: bool) {
        self.defer_l3 = defer_l3;
    }

    /// Set the request-local overlap between adjacent classifier chunks.
    pub fn set_chunk_overlap_tokens(&mut self, overlap: usize) -> Result<(), String> {
        self.set_validated_chunk_overlap_tokens(crate::ChunkOverlapTokens::try_from(overlap)?);
        Ok(())
    }

    pub(crate) fn set_validated_chunk_overlap_tokens(
        &mut self,
        overlap: crate::ChunkOverlapTokens,
    ) {
        self.chunk_overlap_tokens = overlap.get();
    }

    /// Return a copy with a different max-level cap.
    pub fn with_max_level(mut self, max_level: SecurityLevel) -> Self {
        self.layers.set_max_level(max_level);
        self
    }

    /// Return the ONNX batch mode backing this execution.
    pub fn onnx_batch_mode(&self) -> OnnxBatchMode {
        self.onnx_batch_mode
    }

    /// Return the configured execution backend.
    pub fn backend(&self) -> ExecutionBackend {
        self.backend
    }

    /// Return the ONNX Runtime session options backing this execution.
    pub fn onnx_runtime_options(&self) -> OnnxRuntimeOptions {
        self.onnx_runtime_options
    }

    /// Return the selected NTDB operating point.
    pub fn ntdb_operating_point(&self) -> NtdbOperatingPoint {
        self.ntdb_operating_point
    }

    /// Return the selected NTDB final-decision threshold set.
    pub fn ntdb_decision_threshold_point(&self) -> NtdbOperatingPoint {
        self.ntdb_decision_threshold_point
    }

    /// Return the selected physical L3 classifier topology.
    pub fn l3_strategy(&self) -> L3Strategy {
        self.l3_strategy
    }

    /// Return whether L3 should be centrally scheduled.
    pub fn defer_l3(&self) -> bool {
        self.defer_l3
    }

    /// Return the overlap between adjacent classifier chunks.
    pub fn chunk_overlap_tokens(&self) -> usize {
        self.chunk_overlap_tokens
    }
}

impl Default for ScanExecution {
    fn default() -> Self {
        Self::new(SecurityLevel::L3)
    }
}

pub use patronus_ark_core::cascade::{
    ConditionalPipelineGate, EffectiveL3PipelinePolicy, GateExpression, GateResult,
    L3AggregationStrategy, L3ClusteringStrategy, L3EarlyExitMode, L3PipelineEarlyExit,
    L3PipelinePolicy, L3ProgressMode, L3SchedulerPolicy, LayerExecution, MetadataCondition,
    ResultCondition, ScanGateMatrix, SecurityLevel, Stage, StageOutcome,
};

pub use patronus_ark_core::{
    DecisionCandidate, DecisionEnvelope, DecisionProvenance, DecisionRecommendation,
    DecisionResult, DecisionTerminality, EvaluationResult, LabelScore, LayerResult,
    SecurityCategory,
};

impl From<patronus_ark_core::NativeResult> for SecurityScanResult {
    fn from(value: patronus_ark_core::NativeResult) -> Self {
        Self {
            category: value.category,
            class_name: value.class_name,
            confidence: value.confidence,
            level: value.level,
            model: value.model,
            duration_ms: value.duration_ms,
            layers: value.layers,
            evidence_spans: value.evidence_spans,
            label_scores: value.label_scores,
            decision: value.decision,
            internal_l2_chunk_outputs: Vec::new(),
            decided_by: None,
            l1_outcome: None,
        }
    }
}

impl From<SecurityScanResult> for patronus_ark_core::NativeResult {
    fn from(value: SecurityScanResult) -> Self {
        Self {
            category: value.category,
            class_name: value.class_name,
            confidence: value.confidence,
            level: value.level,
            model: value.model,
            duration_ms: value.duration_ms,
            layers: value.layers,
            evidence_spans: value.evidence_spans,
            label_scores: value.label_scores,
            decision: value.decision,
        }
    }
}

pub use patronus_ark_core::{ExecutionBackend, OnnxRuntimeOptions};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_point_defaults_keep_their_documented_values() {
        assert_eq!(L3Strategy::default(), L3Strategy::Dedicated);
        assert_eq!(
            defaults::PYTHON_MAX_LEVEL.parse::<SecurityLevel>(),
            Ok(SecurityLevel::L2)
        );
        assert_eq!(
            defaults::PYTHON_L3_STRATEGY.parse::<L3Strategy>(),
            Ok(L3Strategy::Dedicated)
        );
        assert_eq!(
            defaults::PYTHON_NTDB_OPERATING_POINT.parse::<NtdbOperatingPoint>(),
            Ok(NtdbOperatingPoint::BestF1)
        );
        assert_eq!(defaults::ARK_API_L3_STRATEGY, L3Strategy::Multi);
        assert_eq!(
            NtdbOperatingPoint::default(),
            NtdbOperatingPoint::BestPromote
        );
        assert_eq!(ScanExecution::default().max_level(), SecurityLevel::L3);
    }
}
