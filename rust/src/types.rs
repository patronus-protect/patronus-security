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

/// Serializes the canonical [`SecurityLevel::as_str`] name.
impl Serialize for SecurityLevel {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Deserializes every name [`str::parse`] accepts (`L1`, `l1`, `1`, ...).
impl<'de> Deserialize<'de> for SecurityLevel {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
/// Physical L3 classifier topology.
pub enum L3Strategy {
    /// Each promoted pipeline executes its own L3 model.
    #[default]
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

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(try_from = "GateConfig")]
/// Caller-controlled execution gates for one scanner execution profile.
///
/// Unspecified rules use the shared credentials/secrets-only DLP default;
/// other execution gates default to enabled. Diagnostic `explain` and the
/// scored PII and DLP modes are opt-in. `max_level` is still enforced by
/// `ScanExecution`, so a gate can only further restrict the configured scanner.
///
/// Deserializes from the one gate schema of every host (Python
/// `execution_gates`, Ark API `gates`): the native keys `rules`, `models`,
/// `pii_mode`, `dlp_mode` and `explain`, the level switches `l1`, `l2` and
/// `l3`, `conditional` and the L3 worker policy `l3_policy`. Unknown keys and
/// out-of-range values are refused.
pub struct ScanGateMatrix {
    /// Native rule, model, mode and `explain` gates, shared with Ark Core.
    pub native: crate::NativeGates,
    /// Optional L1 override. `None` means enabled.
    pub l1: Option<bool>,
    /// Optional L2 override. `None` means enabled.
    pub l2: Option<bool>,
    /// Optional L3 override. `None` means enabled.
    pub l3: Option<bool>,
    /// Request-context and prior-result conditions applied before L2 or L3.
    pub conditional: Vec<ConditionalPipelineGate>,
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
    /// Whether L3 may stop once the final class is stable.
    pub early_exit: L3EarlyExitMode,
    /// Whether L3 should emit non-authoritative progress/provisional events.
    pub progress: L3ProgressMode,
    /// Logical chunk ordering strategy. This does not enable tensor batching.
    pub clustering: L3ClusteringStrategy,
    /// Number of high-priority members inferred per similarity cluster for
    /// representative scheduling. Values below 1 are treated as 1.
    pub representatives_per_cluster: usize,
    /// Number of least-similar verification members inferred per cluster for
    /// verify-representative scheduling. Values below 1 are treated as 1.
    pub verify_representatives_per_cluster: usize,
    /// Minimum request-local similarity required to place two chunks in the
    /// same representative cluster.
    pub min_cluster_similarity: f64,
    /// Maximum number of chunks assigned to one representative cluster.
    pub max_cluster_size: usize,
    /// Optional execution-policy overrides keyed by pipeline category or model.
    /// Category keys take precedence over model keys.
    pub pipelines: HashMap<String, L3PipelinePolicy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
/// Optional per-pipeline overrides for L3 chunk execution.
pub struct L3PipelinePolicy {
    /// Chunk execution strategy. `None` inherits the request-wide default.
    #[serde(default)]
    pub clustering: Option<L3ClusteringStrategy>,
    /// Representatives inferred from the high-priority side of each cluster.
    #[serde(default)]
    pub representatives_per_cluster: Option<usize>,
    /// Least-similar members used to verify a representative cluster.
    #[serde(default)]
    pub verify_representatives_per_cluster: Option<usize>,
    /// Minimum request-local similarity required for cluster membership.
    #[serde(default)]
    pub min_cluster_similarity: Option<f64>,
    /// Maximum number of members allowed in one cluster.
    #[serde(default)]
    pub max_cluster_size: Option<usize>,
    /// Chunk-output aggregation. `None` keeps the pipeline's built-in rule.
    #[serde(default)]
    pub aggregation: Option<L3AggregationStrategy>,
    /// Early-exit scope. `None` inherits the request-wide default semantics.
    #[serde(default)]
    pub early_exit: Option<L3PipelineEarlyExit>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
/// Configurable aggregation for one L3 pipeline.
pub enum L3AggregationStrategy {
    AnyPositiveOrHighest {
        positive_class: String,
        threshold: f64,
    },
    HighestRiskAboveThresholdOrConfidence {
        threshold: f64,
    },
    MajorityVoteOrHighest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Scope at which a stable per-pipeline L3 decision stops work.
pub enum L3PipelineEarlyExit {
    Disabled,
    HeadStable,
    RequestWidePositive,
}

#[derive(Debug, Clone, PartialEq)]
/// Fully resolved execution settings for one pipeline and request.
pub struct EffectiveL3PipelinePolicy {
    pub clustering: L3ClusteringStrategy,
    pub representatives_per_cluster: usize,
    pub verify_representatives_per_cluster: usize,
    pub min_cluster_similarity: f64,
    pub max_cluster_size: usize,
    pub aggregation: Option<L3AggregationStrategy>,
    pub early_exit: L3PipelineEarlyExit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3EarlyExitMode {
    Disabled,
    ClassStable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3ProgressMode {
    Disabled,
    Progress,
    Provisional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L3ClusteringStrategy {
    Disabled,
    RankOnly,
    Representative,
    VerifyRepresentative,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// One conditional L2/L3 pipeline gate.
pub struct ConditionalPipelineGate {
    /// Phase controlled by this gate. L1 is intentionally not supported.
    pub level: SecurityLevel,
    /// Optional category/model selector. `None` applies to every pipeline at the level.
    #[serde(default)]
    pub pipeline: Option<String>,
    /// Condition that enables a normal gate or activates an `l3_policy` override.
    pub when: GateExpression,
    /// Optional L3 execution-policy override applied when `when` matches.
    /// Policy gates do not suppress the pipeline when the condition is false.
    #[serde(default)]
    pub l3_policy: Option<L3PipelinePolicy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Recursive expression over enqueue metadata and completed L1/L2 results.
pub enum GateExpression {
    All(Vec<GateExpression>),
    Any(Vec<GateExpression>),
    Not(Box<GateExpression>),
    Metadata(MetadataCondition),
    Result(ResultCondition),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Predicate over a dotted path in request metadata.
pub struct MetadataCondition {
    pub path: String,
    #[serde(default)]
    pub equals: Option<serde_json::Value>,
    #[serde(default, rename = "in")]
    pub in_values: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub exists: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Predicate over a previously completed L1/L2 pipeline result.
pub struct ResultCondition {
    pub pipeline: String,
    #[serde(default)]
    pub classes: Vec<String>,
    #[serde(default)]
    pub min_confidence: Option<f64>,
}

#[derive(Debug, Clone, PartialEq)]
/// Minimal result view exposed to conditional gate evaluation.
pub struct GateResult {
    pub pipeline: String,
    pub class_name: String,
    pub confidence: f64,
    pub level: SecurityLevel,
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
                "threat".to_string(),
                "unified-v3-threat".to_string(),
                "dynamic-pii".to_string(),
                "gliner_small-v2.5-edge".to_string(),
                "sensitive_document".to_string(),
                "orca-sonar-document-classifier".to_string(),
                "tool_class".to_string(),
                "tool_action".to_string(),
                "tool_tags".to_string(),
                "routing".to_string(),
                "unified-multitask-model-augmented-v3".to_string(),
            ],
            ttl_ms,
            estimated_cost_ms,
            fairness_quantum_ms: 50,
            max_wait_ms: 2_000,
            degraded_factor: 0.75,
            early_exit: L3EarlyExitMode::ClassStable,
            progress: L3ProgressMode::Disabled,
            clustering: L3ClusteringStrategy::RankOnly,
            representatives_per_cluster: 1,
            verify_representatives_per_cluster: 1,
            min_cluster_similarity: 0.90,
            max_cluster_size: 8,
            pipelines: HashMap::new(),
        }
    }
}

impl L3SchedulerPolicy {
    /// Resolve request-wide defaults and a category/model override.
    pub fn pipeline_policy(&self, category: &str, model: &str) -> EffectiveL3PipelinePolicy {
        let pipeline = self
            .pipelines
            .get(category)
            .or_else(|| self.pipelines.get(model));
        let inherited_early_exit = match self.early_exit {
            L3EarlyExitMode::Disabled => L3PipelineEarlyExit::Disabled,
            L3EarlyExitMode::ClassStable
                if category == "injection"
                    || category == "threat"
                    || model == "wolf-defender-small"
                    || model == "unified-v3-threat" =>
            {
                L3PipelineEarlyExit::RequestWidePositive
            }
            L3EarlyExitMode::ClassStable => L3PipelineEarlyExit::HeadStable,
        };
        EffectiveL3PipelinePolicy {
            clustering: pipeline
                .and_then(|policy| policy.clustering)
                .unwrap_or(self.clustering),
            representatives_per_cluster: pipeline
                .and_then(|policy| policy.representatives_per_cluster)
                .unwrap_or(self.representatives_per_cluster)
                .max(1),
            verify_representatives_per_cluster: pipeline
                .and_then(|policy| policy.verify_representatives_per_cluster)
                .unwrap_or(self.verify_representatives_per_cluster)
                .max(1),
            min_cluster_similarity: pipeline
                .and_then(|policy| policy.min_cluster_similarity)
                .unwrap_or(self.min_cluster_similarity)
                .clamp(0.0, 1.0),
            max_cluster_size: pipeline
                .and_then(|policy| policy.max_cluster_size)
                .unwrap_or(self.max_cluster_size)
                .max(1),
            aggregation: pipeline.and_then(|policy| policy.aggregation.clone()),
            early_exit: pipeline
                .and_then(|policy| policy.early_exit)
                .unwrap_or(inherited_early_exit),
        }
    }
}

impl ScanGateMatrix {
    /// Explicitly enable all native rules, including opt-in DLP content families.
    pub fn all_enabled() -> Self {
        Self {
            native: crate::NativeGates::all_enabled(),
            ..Self::default()
        }
    }

    /// Create a matrix with explicit level gates.
    pub fn levels(l1: bool, l2: bool, l3: bool) -> Self {
        Self {
            l1: Some(l1),
            l2: Some(l2),
            l3: Some(l3),
            ..Self::default()
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
        self.native.models.insert(model.into(), enabled);
    }

    /// Builder-style model/native scanner gate setter.
    pub fn with_model(mut self, model: impl Into<String>, enabled: bool) -> Self {
        self.set_model(model, enabled);
        self
    }

    /// Set one stable rule-id gate.
    pub fn set_rule(&mut self, rule_id: impl Into<String>, enabled: bool) {
        self.native.rules.insert(rule_id.into(), enabled);
    }

    /// Builder-style stable rule-id gate setter.
    pub fn with_rule(mut self, rule_id: impl Into<String>, enabled: bool) -> Self {
        self.set_rule(rule_id, enabled);
        self
    }

    /// Replace request-context and prior-result gates.
    pub fn set_conditional(&mut self, gates: Vec<ConditionalPipelineGate>) -> Result<(), String> {
        for gate in &gates {
            gate.validate()?;
        }
        self.conditional = gates;
        Ok(())
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

    /// Replace the L3 worker scheduling policy.
    pub fn set_l3_policy(&mut self, policy: L3SchedulerPolicy) {
        self.l3_policy = policy;
    }
}

/// The serialized [`ScanGateMatrix`]; missing keys keep the defaults.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct GateConfig {
    #[serde(flatten)]
    native: crate::NativeGates,
    l1: Option<bool>,
    l2: Option<bool>,
    l3: Option<bool>,
    conditional: Vec<ConditionalPipelineGate>,
    l3_policy: L3PolicyConfig,
}

/// The serialized [`L3SchedulerPolicy`]: each key overrides its default;
/// `ttl_ms` and `estimated_cost_ms` entries override the default per key.
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct L3PolicyConfig {
    enabled: Option<bool>,
    priority: Option<Vec<String>>,
    ttl_ms: HashMap<String, u64>,
    estimated_cost_ms: HashMap<String, u64>,
    fairness_quantum_ms: Option<u64>,
    max_wait_ms: Option<u64>,
    degraded_factor: Option<f64>,
    early_exit: Option<L3EarlyExitMode>,
    progress: Option<L3ProgressMode>,
    clustering: Option<L3ClusteringStrategy>,
    representatives_per_cluster: Option<usize>,
    verify_representatives_per_cluster: Option<usize>,
    min_cluster_similarity: Option<f64>,
    max_cluster_size: Option<usize>,
    pipelines: HashMap<String, L3PipelinePolicy>,
}

impl TryFrom<GateConfig> for ScanGateMatrix {
    type Error = String;

    fn try_from(config: GateConfig) -> Result<Self, String> {
        let raw = config.l3_policy;
        let mut policy = L3SchedulerPolicy::default();
        macro_rules! set {
            ($($field:ident),*) => {$(
                if let Some(value) = raw.$field {
                    policy.$field = value;
                }
            )*};
        }
        set!(
            enabled,
            priority,
            fairness_quantum_ms,
            max_wait_ms,
            degraded_factor,
            early_exit,
            progress,
            clustering,
            representatives_per_cluster,
            verify_representatives_per_cluster,
            min_cluster_similarity,
            max_cluster_size
        );
        policy.ttl_ms.extend(raw.ttl_ms);
        policy.estimated_cost_ms.extend(raw.estimated_cost_ms);
        policy.pipelines = raw.pipelines;
        policy.validate()?;
        let mut gates = Self {
            native: config.native,
            l1: config.l1,
            l2: config.l2,
            l3: config.l3,
            l3_policy: policy,
            ..Self::default()
        };
        gates.set_conditional(config.conditional)?;
        Ok(gates)
    }
}

fn check_fraction(value: f64, field: &str) -> Result<(), String> {
    if (0.0..=1.0).contains(&value) {
        Ok(())
    } else {
        Err(format!("{field} must be between 0.0 and 1.0"))
    }
}

fn check_count(value: usize, field: &str) -> Result<(), String> {
    if value == 0 {
        Err(format!("{field} must be >= 1"))
    } else {
        Ok(())
    }
}

impl L3SchedulerPolicy {
    /// Refuse out-of-range values: zero counts, costs and fairness quantum,
    /// fractions outside `0..=1` and invalid pipeline overrides.
    pub fn validate(&self) -> Result<(), String> {
        check_count(
            usize::try_from(self.fairness_quantum_ms).unwrap_or(usize::MAX),
            "l3_policy.fairness_quantum_ms",
        )?;
        check_count(
            self.representatives_per_cluster,
            "l3_policy.representatives_per_cluster",
        )?;
        check_count(
            self.verify_representatives_per_cluster,
            "l3_policy.verify_representatives_per_cluster",
        )?;
        check_count(self.max_cluster_size, "l3_policy.max_cluster_size")?;
        check_fraction(self.degraded_factor, "l3_policy.degraded_factor")?;
        check_fraction(
            self.min_cluster_similarity,
            "l3_policy.min_cluster_similarity",
        )?;
        if let Some(name) = self.estimated_cost_ms.iter().find(|(_, &cost)| cost == 0) {
            return Err(format!(
                "l3_policy.estimated_cost_ms.{} must be >= 1",
                name.0
            ));
        }
        for (name, pipeline) in &self.pipelines {
            if name.trim().is_empty() {
                return Err("l3_policy.pipelines keys must not be empty".to_string());
            }
            pipeline
                .validate()
                .map_err(|error| format!("l3_policy.pipelines.{name}.{error}"))?;
        }
        Ok(())
    }
}

impl L3PipelinePolicy {
    /// Refuse zero counts, fractions outside `0..=1` and an empty positive class.
    pub fn validate(&self) -> Result<(), String> {
        for (field, value) in [
            (
                "representatives_per_cluster",
                self.representatives_per_cluster,
            ),
            (
                "verify_representatives_per_cluster",
                self.verify_representatives_per_cluster,
            ),
            ("max_cluster_size", self.max_cluster_size),
        ] {
            value.map_or(Ok(()), |value| check_count(value, field))?;
        }
        if let Some(value) = self.min_cluster_similarity {
            check_fraction(value, "min_cluster_similarity")?;
        }
        match &self.aggregation {
            Some(L3AggregationStrategy::AnyPositiveOrHighest {
                positive_class,
                threshold,
            }) => {
                if positive_class.trim().is_empty() {
                    return Err("aggregation.positive_class must not be empty".to_string());
                }
                check_fraction(*threshold, "aggregation.threshold")
            }
            Some(L3AggregationStrategy::HighestRiskAboveThresholdOrConfidence { threshold }) => {
                check_fraction(*threshold, "aggregation.threshold")
            }
            Some(L3AggregationStrategy::MajorityVoteOrHighest) | None => Ok(()),
        }
    }
}

impl ConditionalPipelineGate {
    pub fn validate(&self) -> Result<(), String> {
        if self.level == SecurityLevel::L1 {
            return Err("conditional gates may only target L2 or L3".to_string());
        }
        if self
            .pipeline
            .as_ref()
            .is_some_and(|value| value.trim().is_empty())
        {
            return Err("conditional gate pipeline must not be empty".to_string());
        }
        if self.l3_policy.is_some() && (self.level != SecurityLevel::L3 || self.pipeline.is_none())
        {
            return Err(
                "conditional l3_policy overrides require level l3 and a pipeline".to_string(),
            );
        }
        if let Some(policy) = &self.l3_policy {
            policy
                .validate()
                .map_err(|error| format!("conditional l3_policy.{error}"))?;
        }
        self.when.validate()
    }
}

impl L3PipelinePolicy {
    pub(crate) fn apply_override(&mut self, override_policy: &Self) {
        if override_policy.clustering.is_some() {
            self.clustering = override_policy.clustering;
        }
        if override_policy.representatives_per_cluster.is_some() {
            self.representatives_per_cluster = override_policy.representatives_per_cluster;
        }
        if override_policy.verify_representatives_per_cluster.is_some() {
            self.verify_representatives_per_cluster =
                override_policy.verify_representatives_per_cluster;
        }
        if override_policy.min_cluster_similarity.is_some() {
            self.min_cluster_similarity = override_policy.min_cluster_similarity;
        }
        if override_policy.max_cluster_size.is_some() {
            self.max_cluster_size = override_policy.max_cluster_size;
        }
        if override_policy.aggregation.is_some() {
            self.aggregation = override_policy.aggregation.clone();
        }
        if override_policy.early_exit.is_some() {
            self.early_exit = override_policy.early_exit;
        }
    }
}

impl GateExpression {
    fn validate(&self) -> Result<(), String> {
        match self {
            Self::All(items) | Self::Any(items) => {
                if items.is_empty() {
                    return Err("conditional gate all/any must not be empty".to_string());
                }
                for item in items {
                    item.validate()?;
                }
                Ok(())
            }
            Self::Not(item) => item.validate(),
            Self::Metadata(condition) => condition.validate(),
            Self::Result(condition) => condition.validate(),
        }
    }
}

impl MetadataCondition {
    fn validate(&self) -> Result<(), String> {
        if self.path.trim().is_empty() {
            return Err("metadata gate path must not be empty".to_string());
        }
        let predicates = usize::from(self.equals.is_some())
            + usize::from(self.in_values.is_some())
            + usize::from(self.exists.is_some());
        if predicates != 1 {
            return Err(
                "metadata gate must configure exactly one of equals, in, or exists".to_string(),
            );
        }
        if self.in_values.as_ref().is_some_and(Vec::is_empty) {
            return Err("metadata gate in list must not be empty".to_string());
        }
        Ok(())
    }
}

impl ResultCondition {
    fn validate(&self) -> Result<(), String> {
        if self.pipeline.trim().is_empty() {
            return Err("result gate pipeline must not be empty".to_string());
        }
        if self
            .min_confidence
            .is_some_and(|value| !(0.0..=1.0).contains(&value))
        {
            return Err("result gate min_confidence must be between 0.0 and 1.0".to_string());
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
/// Effective execution state consumed by scan methods and model pipelines.
pub struct ScanExecution {
    max_level: SecurityLevel,
    gates: ScanGateMatrix,
    backend: ExecutionBackend,
    onnx_runtime_options: OnnxRuntimeOptions,
    onnx_batch_mode: OnnxBatchMode,
    ntdb_operating_point: NtdbOperatingPoint,
    ntdb_decision_threshold_point: NtdbOperatingPoint,
    l3_strategy: L3Strategy,
    defer_l3: bool,
    chunk_overlap_tokens: usize,
    wolf_execution_options: crate::WolfExecutionOptions,
}

impl ScanExecution {
    /// Create an execution with shared rule defaults up to `max_level`.
    pub fn new(max_level: SecurityLevel) -> Self {
        Self {
            max_level,
            gates: ScanGateMatrix::default(),
            backend: ExecutionBackend::default(),
            onnx_runtime_options: OnnxRuntimeOptions::default(),
            onnx_batch_mode: OnnxBatchMode::LazyBatches,
            ntdb_operating_point: NtdbOperatingPoint::default(),
            ntdb_decision_threshold_point: NtdbOperatingPoint::BestF1,
            l3_strategy: L3Strategy::default(),
            defer_l3: false,
            chunk_overlap_tokens: 0,
            wolf_execution_options: crate::WolfExecutionOptions::default(),
        }
    }

    /// Create an execution with explicit gates up to `max_level`.
    pub fn with_gates(max_level: SecurityLevel, gates: ScanGateMatrix) -> Self {
        Self {
            max_level,
            gates,
            backend: ExecutionBackend::default(),
            onnx_runtime_options: OnnxRuntimeOptions::default(),
            onnx_batch_mode: OnnxBatchMode::LazyBatches,
            ntdb_operating_point: NtdbOperatingPoint::default(),
            ntdb_decision_threshold_point: NtdbOperatingPoint::BestF1,
            l3_strategy: L3Strategy::default(),
            defer_l3: false,
            chunk_overlap_tokens: 0,
            wolf_execution_options: crate::WolfExecutionOptions::default(),
        }
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
        self.max_level = max_level;
        self
    }

    /// Return whether a level is enabled for this execution after max-level
    /// enforcement.
    pub fn allows_level(&self, level: SecurityLevel) -> bool {
        level <= self.max_level && self.gates.allows_level(level)
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
mod gate_schema_tests {
    use super::*;

    fn gates(value: serde_json::Value) -> Result<ScanGateMatrix, String> {
        serde_json::from_value(value).map_err(|error| error.to_string())
    }

    #[test]
    fn one_gate_schema_reads_every_key() {
        let gates = gates(serde_json::json!({
            "rules": {"pii_email": false, "core.remote_to_exec": false},
            "models": {"native:pii": false},
            "pii_mode": "recall",
            "dlp_mode": "balanced",
            "explain": true,
            "l1": true,
            "l2": false,
            "l3": false,
            "conditional": [{
                "level": "l3",
                "pipeline": "injection",
                "when": {"metadata": {"path": "tenant", "equals": "a"}},
                "l3_policy": {"clustering": "representative"}
            }],
            "l3_policy": {
                "enabled": false,
                "priority": ["tool_class"],
                "ttl_ms": {"tool_class": 1234},
                "estimated_cost_ms": {"tool_class": 30},
                "fairness_quantum_ms": 10,
                "max_wait_ms": 100,
                "degraded_factor": 0.5,
                "early_exit": "disabled",
                "progress": "provisional",
                "clustering": "verify_representative",
                "representatives_per_cluster": 2,
                "verify_representatives_per_cluster": 2,
                "min_cluster_similarity": 0.8,
                "max_cluster_size": 4,
                "pipelines": {"injection": {
                    "clustering": "representative",
                    "aggregation": {"type": "any_positive_or_highest", "positive_class": "attack", "threshold": 0.93},
                    "early_exit": "request_wide_positive"
                }}
            }
        }))
        .unwrap();
        assert!(!gates.native.allows_rule("core.remote_to_exec"));
        assert!(!gates.native.allows_model("native:pii"));
        assert_eq!(gates.native.pii_mode, crate::ScoreMode::Recall);
        assert!(gates.native.explain);
        assert_eq!(
            (gates.l1, gates.l2, gates.l3),
            (Some(true), Some(false), Some(false))
        );
        assert_eq!(gates.conditional.len(), 1);
        let policy = &gates.l3_policy;
        assert!(!policy.enabled);
        assert_eq!(policy.ttl_ms["tool_class"], 1234);
        // Map entries override the defaults per key.
        assert_eq!(policy.ttl_ms["injection"], 15_000);
        assert_eq!(
            policy.clustering,
            L3ClusteringStrategy::VerifyRepresentative
        );
        assert_eq!(policy.max_cluster_size, 4);
        assert_eq!(
            policy.pipelines["injection"].clustering,
            Some(L3ClusteringStrategy::Representative)
        );
        let default = self::gates(serde_json::json!({})).unwrap();
        assert_eq!(
            default.l3_policy.priority,
            L3SchedulerPolicy::default().priority
        );
        assert!(default.native.allows_rule("pii_email"));
    }

    #[test]
    fn gate_schema_refuses_old_keys_and_bad_values() {
        for invalid in [
            serde_json::json!({"levels": {"l1": true}}),
            serde_json::json!({"model_areas": {"native:pii": false}}),
            serde_json::json!({"policy": {"enabled": true}}),
            serde_json::json!({"l3": {"enabled": true}}),
            serde_json::json!({"l3_policy": {"execution": "rank_only"}}),
            serde_json::json!({"l3_policy": {"min_similarity": 0.9}}),
            serde_json::json!({"l3_policy": {"pipelines": {"injection": {"execution": "representative"}}}}),
            serde_json::json!({"rules": {"pii_email": "no"}}),
            serde_json::json!({"l1": "yes"}),
            serde_json::json!({"pii_mode": "fast"}),
            serde_json::json!({"l3_policy": {"priority": "injection"}}),
            serde_json::json!({"l3_policy": {"ttl_ms": {"injection": "soon"}}}),
            serde_json::json!({"l3_policy": {"estimated_cost_ms": {"dynamic-pii": 0}}}),
            serde_json::json!({"l3_policy": {"fairness_quantum_ms": 0}}),
            serde_json::json!({"l3_policy": {"max_wait_ms": -1}}),
            serde_json::json!({"l3_policy": {"degraded_factor": 2.0}}),
            serde_json::json!({"l3_policy": {"min_cluster_similarity": 1.5}}),
            serde_json::json!({"l3_policy": {"early_exit": "sometimes"}}),
            serde_json::json!({"l3_policy": {"progress": "verbose"}}),
            serde_json::json!({"l3_policy": {"clustering": "aggressive"}}),
            serde_json::json!({"l3_policy": {"representatives_per_cluster": 0}}),
            serde_json::json!({"l3_policy": {"max_cluster_size": 0}}),
            serde_json::json!({"l3_policy": {"pipelines": {"": {}}}}),
            serde_json::json!({"l3_policy": {"pipelines": {"injection": {"max_cluster_size": 0}}}}),
            serde_json::json!({"l3_policy": {"pipelines": {"injection": {"min_cluster_similarity": 1.5}}}}),
            serde_json::json!({"l3_policy": {"pipelines": {"injection": {"aggregation": {"type": "any_positive_or_highest", "positive_class": " ", "threshold": 0.5}}}}}),
            serde_json::json!({"conditional": [{"level": "l1", "when": {"metadata": {"path": "a", "exists": true}}}]}),
            serde_json::json!({"conditional": [{"level": "l3", "pipeline": "injection", "when": {"metadata": {"path": "a", "exists": true}}, "l3_policy": {"max_cluster_size": 0}}]}),
        ] {
            assert!(gates(invalid.clone()).is_err(), "{invalid} must be refused");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn l3_pipeline_policy_overrides_request_defaults_by_category() {
        let mut policy = L3SchedulerPolicy {
            clustering: L3ClusteringStrategy::RankOnly,
            ..L3SchedulerPolicy::default()
        };
        policy.pipelines.insert(
            "injection".to_string(),
            L3PipelinePolicy {
                clustering: Some(L3ClusteringStrategy::VerifyRepresentative),
                representatives_per_cluster: Some(2),
                verify_representatives_per_cluster: Some(1),
                min_cluster_similarity: Some(0.96),
                max_cluster_size: Some(4),
                aggregation: Some(L3AggregationStrategy::AnyPositiveOrHighest {
                    positive_class: "attack".to_string(),
                    threshold: 0.9,
                }),
                early_exit: Some(L3PipelineEarlyExit::RequestWidePositive),
            },
        );

        let resolved = policy.pipeline_policy("injection", "wolf-defender-small");

        assert_eq!(
            resolved.clustering,
            L3ClusteringStrategy::VerifyRepresentative
        );
        assert_eq!(resolved.representatives_per_cluster, 2);
        assert_eq!(resolved.min_cluster_similarity, 0.96);
        assert_eq!(resolved.max_cluster_size, 4);
        assert_eq!(
            resolved.early_exit,
            L3PipelineEarlyExit::RequestWidePositive
        );
    }

    #[test]
    fn l3_pipeline_policy_uses_model_override_when_category_is_absent() {
        let mut policy = L3SchedulerPolicy::default();
        policy.pipelines.insert(
            "unified-v3-tool-class".to_string(),
            L3PipelinePolicy {
                clustering: Some(L3ClusteringStrategy::Representative),
                ..L3PipelinePolicy::default()
            },
        );

        assert_eq!(
            policy
                .pipeline_policy("tool_class", "unified-v3-tool-class")
                .clustering,
            L3ClusteringStrategy::Representative
        );
    }

    #[test]
    fn l3_default_early_exit_scope_matches_pipeline_semantics() {
        let policy = L3SchedulerPolicy::default();

        assert_eq!(
            policy
                .pipeline_policy("threat", "unified-v3-threat")
                .early_exit,
            L3PipelineEarlyExit::RequestWidePositive
        );
        assert_eq!(
            policy
                .pipeline_policy("tool_class", "unified-v3-tool-class")
                .early_exit,
            L3PipelineEarlyExit::HeadStable
        );
    }

    #[test]
    fn security_level_serde_accepts_from_str_names_and_writes_canonical_names() {
        for (name, level) in [
            ("L1", SecurityLevel::L1),
            ("l2", SecurityLevel::L2),
            ("3", SecurityLevel::L3),
        ] {
            let parsed: SecurityLevel = serde_json::from_value(serde_json::json!(name)).unwrap();
            assert_eq!(parsed, level);
            assert_eq!(serde_json::to_value(level).unwrap(), level.as_str());
        }
        assert!(serde_json::from_value::<SecurityLevel>(serde_json::json!("L4")).is_err());
    }
}
