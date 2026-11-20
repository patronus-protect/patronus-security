// SPDX-License-Identifier: GPL-3.0-only
//! Patronus Ark: the layered (L1/L2/L3), queued security gateway. It runs
//! Ark Core's modules (`patronus_ark_core`) and extends them; types Ark
//! Core defines (categories, levels, gates, results, detectors) are imported
//! from `patronus_ark_core`, this crate exports only what Ark adds.
pub mod assets;
#[allow(dead_code, unused_imports)]
mod cache;
pub mod dynamic_pii;
pub mod gliner_onnx_engine;
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub mod golden_recipes;
pub mod ml;
pub mod pipeline;
mod post_prediction;
pub mod types;

// Ark Core's modules and types, used inside this crate as `crate::...`.
use ml::tokenizer::ChunkOverlapTokens;
use patronus_ark_core::{
    cascade::{
        EffectiveL3PipelinePolicy, ExternalL1Detector, ExternalL1Input, GateResult,
        L3AggregationStrategy, L3ClusteringStrategy, L3EarlyExitMode, L3PipelineEarlyExit,
        L3ProgressMode, L3SchedulerPolicy, ScanGateMatrix, SecurityLevel, Stage, StageOutcome,
    },
    detectors, diagnostics, threat,
    wolf::{WolfModel, WolfPrecision},
    DecisionCandidate, DecisionEnvelope, DecisionProvenance, DecisionRecommendation,
    DecisionResult, DecisionTerminality, EvaluationResult, EvidenceSpan, ExecutionBackend,
    LabelScore, LayerResult, OnnxRuntimeOptions, SecurityCategory, WolfExecutionOptions,
};

pub use cache::{
    CacheEncryptionConfig, CacheError, CacheWriteMode, ExactCacheConfig, MemoryCacheConfig,
    PersistentCacheConfig, WriteBehindConfig,
};
pub use dynamic_pii::{
    DynamicPiiConditionalLabels, DynamicPiiConfig, DynamicPiiExecutionGate,
    DynamicPiiRequestConfig, DynamicPiiResultCondition, MAX_REQUEST_LABEL_BYTES,
};
pub use pipeline::{Pipeline, SecurityGateway};
pub use types::defaults;
pub use types::{
    L3Strategy, NtdbOperatingPoint, OnnxBatchMode, QueuedSecurityEvent, QueuedSecurityProgress,
    QueuedSecurityScanResult, RequestId, ScanExecution, SecurityAssetProgress,
    SecurityAssetProgressCallback, SecurityAssetReadiness, SecurityFailure, SecurityFailureKind,
    SecurityFailureStage, SecurityLevelReadiness, SecurityRequestCompletion, SecurityRequestState,
    SecurityRuntimeReadiness, SecurityScanResult, WolfSelection,
};
