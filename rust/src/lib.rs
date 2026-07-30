// SPDX-License-Identifier: GPL-3.0-only
pub mod assets;
#[allow(dead_code, unused_imports)]
mod cache;
pub mod detectors;
pub mod dynamic_pii;
pub mod external_l1;
pub mod gliner_onnx_engine;
pub mod ml;
pub mod normalization;
pub mod pipeline;
pub mod threat;
pub mod types;

pub use cache::{
    CacheEncryptionConfig, CacheError, CacheWriteMode, ExactCacheConfig, MemoryCacheConfig,
    PersistentCacheConfig, WriteBehindConfig,
};
pub use dynamic_pii::{
    DynamicPiiConditionalLabels, DynamicPiiConfig, DynamicPiiExecutionGate,
    DynamicPiiResultCondition, EvidenceSpan,
};
pub use external_l1::{ExternalL1Detector, ExternalL1Input};
pub use normalization::{canonical_security_text_v1, normalize_text, TextNormalizationConfig};
pub use pipeline::{Pipeline, SecurityGateway};
pub use types::{
    ConditionalPipelineGate, DecisionCandidate, DecisionEnvelope, DecisionProvenance,
    DecisionRecommendation, DecisionResult, DecisionTerminality, EffectiveL3PipelinePolicy,
    EvaluationResult, ExecutionBackend, GateExpression, GateResult, L3AggregationStrategy,
    L3ClusteringStrategy, L3EarlyExitMode, L3PipelineEarlyExit, L3PipelinePolicy, L3ProgressMode,
    L3SchedulerPolicy, L3Strategy, LabelScore, LayerResult, MetadataCondition, NtdbOperatingPoint,
    OnnxBatchMode, OnnxRuntimeOptions, QueuedSecurityEvent, QueuedSecurityProgress,
    QueuedSecurityScanResult, RequestId, ResultCondition, ScanExecution, ScanGateMatrix,
    SecurityAssetProgress, SecurityAssetProgressCallback, SecurityAssetReadiness, SecurityCategory,
    SecurityFailure, SecurityFailureKind, SecurityFailureStage, SecurityLevel,
    SecurityLevelReadiness, SecurityRequestCompletion, SecurityRequestState,
    SecurityRuntimeReadiness, SecurityScanResult,
};
