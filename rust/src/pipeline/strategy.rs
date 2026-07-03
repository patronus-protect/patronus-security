use crate::LongTextPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipelineScope {
    Local,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipelineOutput {
    Binary,
    MultiClass,
    Ner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PipelineInput {
    Text,
    Structural,
    Ner,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ChunkAggregation {
    HighestRiskOrConfidence,
    AnyPositiveOrHighest {
        positive_class: &'static str,
        threshold: f64,
    },
    MajorityVoteOrHighest,
    FirstPositive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChunkRouting {
    Disabled,
    Local,
    GlobalBoosted,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct PipelineStrategy {
    scope: PipelineScope,
    output: PipelineOutput,
    input: PipelineInput,
    chunk_routing: ChunkRouting,
    pub aggregation: ChunkAggregation,
    pub l3_max_bytes: Option<usize>,
    pub chunk_size_bytes: usize,
    pub overlap_bytes: usize,
}

impl PipelineStrategy {
    const LOCAL_CHUNK_SIZE_BYTES: usize = 256;
    const GLOBAL_CHUNK_SIZE_BYTES: usize = 512;
    const LOCAL_OVERLAP_BYTES: usize = 96;
    const GLOBAL_OVERLAP_BYTES: usize = 128;

    pub(crate) fn prompt_injection() -> Self {
        Self {
            scope: PipelineScope::Local,
            output: PipelineOutput::Binary,
            input: PipelineInput::Text,
            chunk_routing: ChunkRouting::Local,
            aggregation: ChunkAggregation::AnyPositiveOrHighest {
                positive_class: "attack",
                threshold: 0.93,
            },
            l3_max_bytes: None,
            chunk_size_bytes: Self::LOCAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::LOCAL_OVERLAP_BYTES,
        }
    }

    pub(crate) fn sensitive_documents() -> Self {
        Self {
            scope: PipelineScope::Global,
            output: PipelineOutput::MultiClass,
            input: PipelineInput::Text,
            chunk_routing: ChunkRouting::GlobalBoosted,
            aggregation: ChunkAggregation::MajorityVoteOrHighest,
            l3_max_bytes: None,
            chunk_size_bytes: Self::GLOBAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::GLOBAL_OVERLAP_BYTES,
        }
    }

    pub(crate) fn user_intent() -> Self {
        Self {
            scope: PipelineScope::Global,
            output: PipelineOutput::MultiClass,
            input: PipelineInput::Text,
            chunk_routing: ChunkRouting::GlobalBoosted,
            aggregation: ChunkAggregation::MajorityVoteOrHighest,
            l3_max_bytes: None,
            chunk_size_bytes: Self::GLOBAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::GLOBAL_OVERLAP_BYTES,
        }
    }

    pub(crate) fn tool_classifier_prompts() -> Self {
        Self::tool_classifier_text()
    }

    pub(crate) fn tool_classifier_descriptions() -> Self {
        Self::tool_classifier_text()
    }

    pub(crate) fn tool_classifier_executions() -> Self {
        Self {
            scope: PipelineScope::Local,
            output: PipelineOutput::MultiClass,
            input: PipelineInput::Structural,
            chunk_routing: ChunkRouting::Disabled,
            aggregation: ChunkAggregation::HighestRiskOrConfidence,
            l3_max_bytes: Some(2048),
            chunk_size_bytes: Self::LOCAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::LOCAL_OVERLAP_BYTES,
        }
    }

    pub(crate) fn pii_model() -> Self {
        Self {
            scope: PipelineScope::Local,
            output: PipelineOutput::Ner,
            input: PipelineInput::Ner,
            chunk_routing: ChunkRouting::Disabled,
            aggregation: ChunkAggregation::FirstPositive,
            l3_max_bytes: None,
            chunk_size_bytes: Self::LOCAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::LOCAL_OVERLAP_BYTES,
        }
    }

    pub(crate) fn generic_text_local_multi() -> Self {
        Self {
            scope: PipelineScope::Local,
            output: PipelineOutput::MultiClass,
            input: PipelineInput::Text,
            chunk_routing: ChunkRouting::Local,
            aggregation: ChunkAggregation::HighestRiskOrConfidence,
            l3_max_bytes: None,
            chunk_size_bytes: Self::LOCAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::LOCAL_OVERLAP_BYTES,
        }
    }

    pub(crate) fn should_skip_full_l2(self, text: &str, policy: LongTextPolicy) -> bool {
        if self.input != PipelineInput::Text || self.output == PipelineOutput::Ner {
            return false;
        }
        matches!(
            (self.scope, self.chunk_routing),
            (PipelineScope::Local, ChunkRouting::Local)
        ) && self.long_text_policy(policy).should_skip_full_l2(text)
    }

    pub(crate) fn long_text_policy(self, mut policy: LongTextPolicy) -> LongTextPolicy {
        policy.chunk_size_bytes = self.chunk_size_bytes;
        policy.overlap_bytes = self
            .overlap_bytes
            .min(self.chunk_size_bytes.saturating_sub(1));
        policy
    }

    pub(crate) fn l3_allowed_for_text(self, text: &str) -> bool {
        self.l3_max_bytes
            .map(|max_bytes| text.len() <= max_bytes)
            .unwrap_or(true)
    }

    #[cfg(test)]
    fn input(self) -> PipelineInput {
        self.input
    }

    fn tool_classifier_text() -> Self {
        Self {
            scope: PipelineScope::Local,
            output: PipelineOutput::MultiClass,
            input: PipelineInput::Text,
            chunk_routing: ChunkRouting::Disabled,
            aggregation: ChunkAggregation::HighestRiskOrConfidence,
            l3_max_bytes: Some(2048),
            chunk_size_bytes: Self::LOCAL_CHUNK_SIZE_BYTES,
            overlap_bytes: Self::LOCAL_OVERLAP_BYTES,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_text_pipelines_do_not_skip_full_l2() {
        let policy = LongTextPolicy {
            enabled: true,
            no_full_l2_byte_limit: 1,
            chunk_size_bytes: 256,
            overlap_bytes: 96,
            verify_non_benign_l2: true,
        };

        assert!(!PipelineStrategy::sensitive_documents().should_skip_full_l2("long text", policy));
        assert!(!PipelineStrategy::user_intent().should_skip_full_l2("long text", policy));
        assert_eq!(
            PipelineStrategy::sensitive_documents()
                .long_text_policy(policy)
                .chunk_size_bytes,
            512
        );
    }

    #[test]
    fn structural_tool_pipeline_disables_chunking_and_caps_l3() {
        let strategy = PipelineStrategy::tool_classifier_executions();
        let policy = LongTextPolicy {
            enabled: true,
            no_full_l2_byte_limit: 1,
            chunk_size_bytes: 256,
            overlap_bytes: 96,
            verify_non_benign_l2: true,
        };

        assert_eq!(strategy.input(), PipelineInput::Structural);
        assert!(!strategy.should_skip_full_l2(&"x".repeat(4096), policy));
        assert!(!strategy.l3_allowed_for_text(&"x".repeat(2049)));
        assert!(strategy.l3_allowed_for_text(&"x".repeat(2048)));
    }
}
