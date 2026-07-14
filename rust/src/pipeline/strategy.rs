// SPDX-License-Identifier: AGPL-3.0-only
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
}

impl PipelineStrategy {
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
        }
    }

    pub fn sensitive_documents() -> Self {
        Self {
            aggregation: ChunkAggregation::MajorityVoteOrHighest,
        }
    }

    pub fn user_intent() -> Self {
        Self {
            aggregation: ChunkAggregation::MajorityVoteOrHighest,
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
        }
    }

    pub fn generic_text_local_multi() -> Self {
        Self {
            aggregation: ChunkAggregation::HighestRiskOrConfidence,
        }
    }

    fn tool_classifier_text() -> Self {
        Self {
            aggregation: ChunkAggregation::HighestRiskOrConfidence,
        }
    }
}
