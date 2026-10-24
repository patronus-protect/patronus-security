// SPDX-License-Identifier: GPL-3.0-only
// Without the model layers parts of the shared plumbing are unused.
#![cfg_attr(not(feature = "ml"), allow(dead_code, unused_imports))]
#[cfg(feature = "ml")]
pub mod assets;
#[cfg(feature = "ml")]
#[allow(dead_code, unused_imports)]
mod cache;
pub mod detectors;
mod diagnostics;
pub mod dynamic_pii;
pub mod external_l1;
#[cfg(feature = "ml")]
pub mod gliner_onnx_engine;
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub mod golden_recipes;
#[cfg(feature = "ml")]
pub mod ml;
pub mod normalization;
#[cfg(feature = "ml")]
pub mod pipeline;
pub mod post_prediction;
pub mod threat;
pub mod types;

#[cfg(feature = "ml")]
pub use cache::{
    CacheEncryptionConfig, CacheError, CacheWriteMode, ExactCacheConfig, MemoryCacheConfig,
    PersistentCacheConfig, WriteBehindConfig,
};
pub use detectors::dlp::score::DlpMode;
pub use detectors::pii::score::PiiMode;
pub use dynamic_pii::{
    DynamicPiiConditionalLabels, DynamicPiiConfig, DynamicPiiExecutionGate,
    DynamicPiiRequestConfig, DynamicPiiResultCondition, EvidenceSpan, MAX_REQUEST_LABEL_BYTES,
};
pub use external_l1::{ExternalL1Detector, ExternalL1Input};
#[cfg(feature = "ml")]
pub use ml::tokenizer::{ChunkOverlapTokens, MAX_CHUNK_OVERLAP_TOKENS};
pub use normalization::{canonical_security_text_v1, normalize_text, TextNormalizationConfig};
#[cfg(feature = "ml")]
pub use pipeline::{Pipeline, SecurityGateway};
pub use post_prediction::{
    CredentialTemplateHook, LocalPathPersonHook, PostPredictionHook, PrivateNetworkDiagnosticHook,
};
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
