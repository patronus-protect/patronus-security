use crate::LongTextPolicy;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChunkAggregation {
    HighestRiskOrConfidence,
    AnyPositiveOrHighest {
        positive_class: &'static str,
        threshold: f64,
    },
    MajorityVoteOrHighest,
}

#[derive(Debug, Clone, Copy)]
pub struct PipelineStrategy {
    pub aggregation: ChunkAggregation,
    pub chunk_size_bytes: usize,
    pub overlap_bytes: usize,
}

impl PipelineStrategy {
    pub const LOCAL_CHUNK_SIZE_BYTES: usize = 256;
    pub const GLOBAL_CHUNK_SIZE_BYTES: usize = 512;
    pub const LOCAL_OVERLAP_BYTES: usize = 96;
    pub const GLOBAL_OVERLAP_BYTES: usize = 128;

    pub fn for_category_model(category: &str, model: &str) -> Self {
        match (category, model) {
            ("injection", _) | (_, "wolf-defender-small") => Self::prompt_injection(),
            ("sensitive_documents", _) | (_, "orca-sonar-document-classifier") => {
                Self::sensitive_documents()
            }
            ("user_intent", _) | (_, "user-intent-model") => Self::user_intent(),
            (_, "tool-prompts-model") => Self::tool_classifier_prompts(),
            (_, "tool-executions-model") => Self::tool_classifier_executions(),
            (_, "tool-classifier-descriptions-model") => Self::tool_classifier_descriptions(),
            _ => Self::generic_text_local_multi(),
        }
    }

    pub fn prompt_injection() -> Self {
        Self {
            aggregation: ChunkAggregation::AnyPositiveOrHighest {
                positive_class: "attack",
                threshold: 0.93,
            },
            chunk_size_bytes: Self::LOCAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::LOCAL_OVERLAP_BYTES,
        }
    }

    pub fn sensitive_documents() -> Self {
        Self {
            aggregation: ChunkAggregation::MajorityVoteOrHighest,
            chunk_size_bytes: Self::GLOBAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::GLOBAL_OVERLAP_BYTES,
        }
    }

    pub fn user_intent() -> Self {
        Self {
            aggregation: ChunkAggregation::MajorityVoteOrHighest,
            chunk_size_bytes: Self::GLOBAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::GLOBAL_OVERLAP_BYTES,
        }
    }

    pub fn tool_classifier_prompts() -> Self {
        Self::tool_classifier_text()
    }

    pub fn tool_classifier_descriptions() -> Self {
        Self::tool_classifier_text()
    }

    pub fn tool_classifier_executions() -> Self {
        Self {
            aggregation: ChunkAggregation::HighestRiskOrConfidence,
            chunk_size_bytes: Self::LOCAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::LOCAL_OVERLAP_BYTES,
        }
    }

    pub fn generic_text_local_multi() -> Self {
        Self {
            aggregation: ChunkAggregation::HighestRiskOrConfidence,
            chunk_size_bytes: Self::LOCAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::LOCAL_OVERLAP_BYTES,
        }
    }

    pub fn long_text_policy(self, mut policy: LongTextPolicy) -> LongTextPolicy {
        policy.chunk_size_bytes = self.chunk_size_bytes;
        policy.overlap_bytes = self
            .overlap_bytes
            .min(self.chunk_size_bytes.saturating_sub(1));
        policy
    }

    fn tool_classifier_text() -> Self {
        Self {
            aggregation: ChunkAggregation::HighestRiskOrConfidence,
            chunk_size_bytes: Self::LOCAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::LOCAL_OVERLAP_BYTES,
        }
    }
}
