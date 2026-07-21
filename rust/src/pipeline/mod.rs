// SPDX-License-Identifier: GPL-3.0-only
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

pub(crate) use l3_worker::{
    failure_from_scan_result, finish_request_if_ready, L3JobSpec, L3Worker, PendingDynamicPii,
    RequestRegistry, RequestState,
};
pub(crate) use strategy::{ChunkAggregation, PipelineStrategy};

/// Internal items re-exported for the integration test suite. Not public API.
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub mod test_util {
    pub use super::decision_cache::{DecisionCache, DecisionCacheConfig};
    pub use super::l3_worker::{
        aggregate_unified_head_for_test, public_unified_class_for_test,
        selected_l3_chunks_for_test, unified_coalescing_snapshot, UnifiedCoalescingSnapshot,
    };
    pub use super::long_text::{aggregate_chunk_outputs, candidate_selection, l3_metadata};
    pub use super::security::{
        ntdb_l2_enabled_for_category, ntdb_l2_model_config_for_id,
        ntdb_l2_model_configs_for_category, ntdb_l2_scan_result, NtdbL2ModelConfig,
    };
    pub use super::strategy::ChunkAggregation;
}
