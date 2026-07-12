mod decision_cache;
mod generic;
mod l3_result;
mod l3_routing;
mod l3_worker;
mod long_text;
mod security;
mod strategy;

pub use generic::Pipeline;
pub use l3_result::{
    degraded_error_result, degraded_fallback_confidence, degraded_timeout_result, has_l3_pending,
    l3_metadata_layer, l3_pending_layer,
};
pub use l3_routing::{priority_index, ttl_ms};
pub use security::SecurityGateway;

pub(crate) use l3_worker::{L3JobSpec, L3Worker, RequestRegistry, RequestState};
pub(crate) use strategy::{ChunkAggregation, PipelineStrategy};

/// Internal items re-exported for the integration test suite. Not public API.
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub mod test_util {
    pub use super::decision_cache::{DecisionCache, DecisionCacheConfig};
    pub use super::long_text::{
        aggregate_chunk_outputs, candidate_selection, chunk_text_bytes, l3_metadata,
    };
    pub use super::security::{
        ntdb_l2_enabled_for_category, ntdb_l2_model_config_for_id,
        ntdb_l2_model_configs_for_category, ntdb_l2_scan_result, NtdbL2ModelConfig,
        NTDB_TOOL_DESCRIPTIONS_MODEL_ID, NTDB_TOOL_EXECUTIONS_MODEL_ID, NTDB_TOOL_PROMPTS_MODEL_ID,
        TOOL_PROMPTS_MODEL,
    };
    pub use super::strategy::{ChunkAggregation, PipelineInput, PipelineScope, PipelineStrategy};
}
