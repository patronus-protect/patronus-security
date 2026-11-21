// SPDX-License-Identifier: GPL-3.0-only
//! Patronus Ark: the layered (L1/L2/L3), queued security gateway. It runs
//! Ark Core's modules (`patronus_ark_core`) and extends them; types Ark
//! Core defines (categories, levels, gates, results, detectors) are imported
//! from `patronus_ark_core`, this crate exports only what Ark adds.
pub mod assets;
#[allow(dead_code, unused_imports)]
mod cache;
mod config;
pub mod dynamic_pii;
pub mod gliner_onnx_engine;
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub mod golden_recipes;
pub mod ml;
pub mod pipeline;
pub mod types;

// Ark Core's modules and types, used inside this crate as `crate::...`.
use patronus_ark_core::{
    cascade::{
        EffectiveL3PipelinePolicy, ExternalL1Detector, ExternalL1Input, GateResult,
        L3AggregationStrategy, L3ClusteringStrategy, L3EarlyExitMode, L3PipelineEarlyExit,
        L3ProgressMode, L3SchedulerPolicy, ModuleDecision, ScanGateMatrix, SecurityLevel, Stage,
        StageOutcome,
    },
    detectors, diagnostics, threat, ChunkOverlapTokens, DecisionCandidate, DecisionEnvelope,
    DecisionProvenance, DecisionRecommendation, DecisionResult, DecisionTerminality,
    EvaluationResult, EvidenceSpan, ExecutionBackend, LabelScore, LayerResult, NtdbOperatingPoint,
    OnnxRuntimeOptions, SecurityCategory, WolfExecutionOptions,
};

pub use cache::{
    CacheEncryptionConfig, CacheError, CacheWriteMode, ExactCacheConfig, MemoryCacheConfig,
    PersistentCacheConfig, WriteBehindConfig,
};
pub use config::GatewayConfig;
pub use dynamic_pii::DynamicPiiConfig;
pub use pipeline::SecurityGateway;
pub use types::defaults;
pub use types::{
    L3Strategy, OnnxBatchMode, QueuedSecurityEvent, QueuedSecurityProgress,
    QueuedSecurityScanResult, RequestId, ScanExecution, SecurityAssetProgress,
    SecurityAssetProgressCallback, SecurityAssetReadiness, SecurityFailure, SecurityFailureKind,
    SecurityFailureStage, SecurityLevelReadiness, SecurityRequestCompletion, SecurityRequestState,
    SecurityRuntimeReadiness, SecurityScanResult,
};
