use crate::LongTextPolicy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineScope {
    Local,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineOutput {
    Binary,
    MultiClass,
    Ner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineInput {
    Text,
    Structural,
    Ner,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ChunkAggregation {
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
pub struct PipelineStrategy {
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

    pub fn sensitive_documents() -> Self {
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

    pub fn user_intent() -> Self {
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

    pub fn tool_classifier_prompts() -> Self {
        Self::tool_classifier_text()
    }

    pub fn tool_classifier_descriptions() -> Self {
        Self::tool_classifier_text()
    }

    pub fn tool_classifier_executions() -> Self {
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

    pub fn pii_model() -> Self {
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

    pub fn generic_text_local_multi() -> Self {
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

    pub fn should_skip_full_l2(self, text: &str, policy: LongTextPolicy) -> bool {
        if self.input != PipelineInput::Text || self.output == PipelineOutput::Ner {
            return false;
        }
        matches!(
            (self.scope, self.chunk_routing),
            (PipelineScope::Local, ChunkRouting::Local)
        ) && self.long_text_policy(policy).should_skip_full_l2(text)
    }

    pub fn long_text_policy(self, mut policy: LongTextPolicy) -> LongTextPolicy {
        policy.chunk_size_bytes = self.chunk_size_bytes;
        policy.overlap_bytes = self
            .overlap_bytes
            .min(self.chunk_size_bytes.saturating_sub(1));
        policy
    }

    pub fn l3_allowed_for_text(self, text: &str) -> bool {
        self.l3_max_bytes
            .map(|max_bytes| text.len() <= max_bytes)
            .unwrap_or(true)
    }

    pub fn scope(self) -> PipelineScope {
        self.scope
    }

    pub fn input(self) -> PipelineInput {
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
