// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;
use std::sync::Arc;

use patronus_ark_core::wolf::WolfConfig;
use patronus_ark_core::ScannerConfig;
use serde::{Deserialize, Serialize};

use crate::NtdbOperatingPoint;

pub type RequestId = String;

/// Lifecycle state for an accepted queued request until its terminal event is consumed.
/// How often a scan under Ark Core's `ScanControl` checks the control while
/// it waits; also the Python binding's period for the caller's control.
pub const CONTROL_POLL: std::time::Duration = std::time::Duration::from_millis(10);

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
    /// The input or its findings exceed `max_input_bytes` or `max_findings`.
    LimitExceeded,
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
            Self::LimitExceeded => "limit_exceeded",
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

#[derive(Debug, Clone, Serialize)]
/// A completed queued scan result together with the request that produced it.
/// Serializes as the result with its `request_id`.
pub struct QueuedSecurityScanResult {
    /// Request id returned by `SecurityGateway::enqueue`.
    pub request_id: RequestId,
    /// Complete classifier result published by L1/L2 or the L3 worker.
    #[serde(flatten)]
    pub result: SecurityScanResult,
}

#[derive(Debug, Clone, Serialize)]
/// Public scan result returned by `SecurityGateway` methods: Core's
/// [`patronus_ark_core::NativeResult`] (category, class, confidence, level,
/// model, layers, evidence, label scores, decision envelope) plus what only
/// the layered gateway reports. It dereferences to the Core result.
pub struct SecurityScanResult {
    /// The result fields Ark Core defines; Ark serializes them flat.
    #[serde(flatten)]
    pub native: patronus_ark_core::NativeResult,
    /// Internal L2 chunk outputs reused by L3 planning. This field is cleared
    /// before results are published outside the gateway.
    #[doc(hidden)]
    #[serde(skip)]
    pub internal_l2_chunk_outputs: Vec<crate::ml::ntdb_executor::L2ChunkOutput>,
    /// With the opt-in cascade, the category's final answer as Core's
    /// [`patronus_ark_core::cascade::ModuleDecision`] (`outcome`, `decided_by`,
    /// `score`) on every result that gives it; `None` without a cascade and
    /// while a later layer still answers. On L1 results it is Core's L1
    /// decision: a detection at a lowered `detect_threshold` shows as
    /// `detected` even when the native class stays `safe`, and its `layers`
    /// are the L1 model's. An L2 or L3 result keeps its layer in its own
    /// `layers`. The synchronous `scan_*` reports move it to the report's
    /// `decision` list, once per module.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_decision: Option<crate::ModuleDecision>,
}

impl std::ops::Deref for SecurityScanResult {
    type Target = patronus_ark_core::NativeResult;

    fn deref(&self) -> &Self::Target {
        &self.native
    }
}

impl std::ops::DerefMut for SecurityScanResult {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.native
    }
}

/// Lets Core's result passes, such as
/// [`patronus_ark_core::post_prediction::resolve_dlp_pii_overlaps`], work on
/// Ark results.
impl std::borrow::Borrow<patronus_ark_core::NativeResult> for SecurityScanResult {
    fn borrow(&self) -> &patronus_ark_core::NativeResult {
        &self.native
    }
}

impl std::borrow::BorrowMut<patronus_ark_core::NativeResult> for SecurityScanResult {
    fn borrow_mut(&mut self) -> &mut patronus_ark_core::NativeResult {
        &mut self.native
    }
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
/// Physical L3 classifier topology. `Dedicated` is the default of every entry
/// point (Rust, Python and the Ark API server).
pub enum L3Strategy {
    /// Each promoted pipeline executes its own L3 model.
    #[default]
    Dedicated,
    /// Promoted classifier pipelines share one request-local multi-head model run.
    Multi,
}

/// `Deserialize` through the type's `FromStr` names and aliases.
macro_rules! deserialize_from_str {
    ($($type:ty),*) => {$(
        impl<'de> Deserialize<'de> for $type {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                String::deserialize(deserializer)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    )*};
}
deserialize_from_str!(OnnxBatchMode, L3Strategy);

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
/// the Core [`LayerExecution`] (max level and gates, reached through `Deref`),
/// the gateway's Core config (its ONNX backend and runtime options) and
/// Ark's NTDB settings.
pub struct ScanExecution {
    layers: LayerExecution,
    /// The gateway's Core config; `backend` and `onnx_runtime_options` read it.
    core: Arc<ScannerConfig>,
    /// Ark's L3 batch mode; unset follows the backend.
    onnx_batch_mode: Option<OnnxBatchMode>,
    ntdb_operating_point: NtdbOperatingPoint,
    ntdb_decision_threshold_point: NtdbOperatingPoint,
    l3_strategy: L3Strategy,
    defer_l3: bool,
    chunk_overlap_tokens: usize,
    /// The dedicated injection L3: Core's Wolf config, its unset window
    /// sizes filled with Ark's serving profile.
    wolf: WolfConfig,
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

    /// Create an execution with explicit gates up to `max_level` and Core's
    /// default ONNX backend and runtime options.
    pub fn with_gates(max_level: SecurityLevel, gates: ScanGateMatrix) -> Self {
        Self::from_core(Arc::new(ScannerConfig {
            max_level,
            gates,
            ..ScannerConfig::default()
        }))
    }

    /// Create the execution of a gateway built from Core's `core` config: its
    /// max level and gates, its ONNX backend and runtime options. Wolf keeps
    /// Ark's serving profile until [`Self::set_wolf`].
    pub(crate) fn from_core(core: Arc<ScannerConfig>) -> Self {
        Self {
            layers: LayerExecution::with_gates(core.max_level, core.gates.clone()),
            core,
            onnx_batch_mode: None,
            ntdb_operating_point: NtdbOperatingPoint::default(),
            ntdb_decision_threshold_point: NtdbOperatingPoint::BestF1,
            l3_strategy: L3Strategy::default(),
            defer_l3: false,
            chunk_overlap_tokens: 0,
            wolf: WolfConfig {
                execution: patronus_ark_core::WolfServingProfile::ARK
                    .fill(crate::WolfExecutionOptions::default()),
                ..WolfConfig::default()
            },
        }
    }

    /// Choose the Wolf model, export and windows; unset window sizes take
    /// Ark's serving profile. Invalid sizes or an unknown `auto` precision
    /// override fail here, not on first use.
    pub fn set_wolf(&mut self, wolf: WolfConfig) -> Result<(), String> {
        let wolf = WolfConfig {
            execution: patronus_ark_core::WolfServingProfile::ARK.fill(wolf.execution),
            ..wolf
        };
        wolf.validate().map_err(|e| e.to_string())?;
        self.wolf = wolf;
        Ok(())
    }

    /// The dedicated injection L3's Wolf config.
    pub fn wolf(&self) -> &WolfConfig {
        &self.wolf
    }

    /// Replace the ONNX batch execution mode.
    pub fn set_onnx_batch_mode(&mut self, mode: OnnxBatchMode) {
        self.onnx_batch_mode = Some(mode);
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

    /// Return the ONNX batch mode backing this execution: the set one, else
    /// lazy batches on the CPU and tensor batches on an accelerator.
    pub fn onnx_batch_mode(&self) -> OnnxBatchMode {
        self.onnx_batch_mode.unwrap_or(match self.backend() {
            ExecutionBackend::Auto | ExecutionBackend::Cpu => OnnxBatchMode::LazyBatches,
            ExecutionBackend::Gpu
            | ExecutionBackend::CoreMl
            | ExecutionBackend::Cuda
            | ExecutionBackend::DirectMl
            | ExecutionBackend::TensorRt => OnnxBatchMode::TensorBatch,
        })
    }

    /// Return Core's `execution_backend`.
    pub fn backend(&self) -> ExecutionBackend {
        self.core.execution_backend
    }

    /// Return Core's `onnx_runtime` session options.
    pub fn onnx_runtime_options(&self) -> OnnxRuntimeOptions {
        self.core.onnx_runtime.normalized()
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

pub(crate) use patronus_ark_core::cascade::{LayerExecution, ScanGateMatrix, SecurityLevel};

pub(crate) use patronus_ark_core::SecurityCategory;

impl From<patronus_ark_core::NativeResult> for SecurityScanResult {
    fn from(native: patronus_ark_core::NativeResult) -> Self {
        Self {
            native,
            internal_l2_chunk_outputs: Vec::new(),
            module_decision: None,
        }
    }
}

pub(crate) use patronus_ark_core::{ExecutionBackend, OnnxRuntimeOptions};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ark_keeps_its_own_wolf_windows_for_unset_sizes() {
        let full = |batch_size| crate::WolfExecutionOptions {
            window_tokens: Some(256),
            overlap_tokens: Some(0),
            batch_size,
        };
        assert_eq!(ScanExecution::default().wolf().execution, full(1));
        let mut execution = ScanExecution::default();
        let wolf = |execution| WolfConfig {
            execution,
            ..WolfConfig::default()
        };
        execution
            .set_wolf(wolf(crate::WolfExecutionOptions {
                batch_size: 4,
                ..Default::default()
            }))
            .unwrap();
        assert_eq!(execution.wolf().execution, full(4));
        assert!(execution
            .set_wolf(wolf(crate::WolfExecutionOptions {
                overlap_tokens: Some(254),
                ..Default::default()
            }))
            .is_err());
    }

    #[test]
    fn backend_and_runtime_options_come_from_the_core_config() {
        let execution = ScanExecution::from_core(Arc::new(ScannerConfig {
            execution_backend: ExecutionBackend::CoreMl,
            onnx_runtime: OnnxRuntimeOptions {
                intra_threads: Some(0),
                inter_threads: Some(2),
                ..OnnxRuntimeOptions::default()
            },
            ..ScannerConfig::default()
        }));
        assert_eq!(execution.backend(), ExecutionBackend::CoreMl);
        assert_eq!(execution.onnx_runtime_options().intra_threads, None);
        assert_eq!(execution.onnx_runtime_options().inter_threads, Some(2));
        // Unset, the batch mode follows the backend; a set one wins.
        assert_eq!(execution.onnx_batch_mode(), OnnxBatchMode::TensorBatch);
        assert_eq!(
            ScanExecution::default().onnx_batch_mode(),
            OnnxBatchMode::LazyBatches
        );
        let mut execution = execution;
        execution.set_onnx_batch_mode(OnnxBatchMode::LazyBatches);
        assert_eq!(execution.onnx_batch_mode(), OnnxBatchMode::LazyBatches);
    }

    #[test]
    fn entry_points_share_one_default() {
        assert_eq!(L3Strategy::default(), L3Strategy::Dedicated);
        assert_eq!(
            NtdbOperatingPoint::default(),
            NtdbOperatingPoint::BestPromote
        );
        assert_eq!(ScanExecution::default().max_level(), SecurityLevel::L3);
    }
}
