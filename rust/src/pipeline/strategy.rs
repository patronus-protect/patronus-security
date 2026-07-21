// SPDX-License-Identifier: GPL-3.0-only
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
            ("sensitive_document", _) | (_, "orca-sonar-document-classifier") => {
                Self::majority_vote()
            }
            ("routing", _) | ("tool_class", _) | ("tool_action", _) => Self::majority_vote(),
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

    pub fn majority_vote() -> Self {
        Self {
            aggregation: ChunkAggregation::MajorityVoteOrHighest,
        }
    }

    pub fn generic_text_local_multi() -> Self {
        Self {
            aggregation: ChunkAggregation::HighestRiskOrConfidence,
        }
    }
}
