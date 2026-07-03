mod decision_cache;
mod generic;
mod l3_result;
mod l3_routing;
mod l3_worker;
mod long_text;
mod prompt_injection;
mod security;
mod strategy;

pub use generic::Pipeline;
pub use l3_result::{
    degraded_error_result, degraded_fallback_confidence, degraded_timeout_result, has_l3_pending,
    l3_metadata_layer, l3_pending_layer,
};
pub use l3_routing::{priority_index, ttl_ms};
pub use prompt_injection::PromptInjectionPipeline;
pub use security::{PatronusSecurity, SecurityGateway};

pub(crate) use l3_worker::{L3JobSpec, L3Worker, RequestRegistry, RequestState};
pub(crate) use strategy::{ChunkAggregation, PipelineStrategy};
