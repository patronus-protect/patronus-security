// SPDX-License-Identifier: GPL-3.0-only
//! Ark's built-in L3 chunk aggregation per category or model; a configured
//! `l3_policy` aggregation replaces it.
use crate::L3AggregationStrategy;

pub(crate) fn chunk_aggregation(category: &str, model: &str) -> L3AggregationStrategy {
    match (category, model) {
        ("injection", _) | (_, "wolf-defender-small") => {
            L3AggregationStrategy::AnyPositiveOrHighest {
                positive_class: "attack".to_string(),
                threshold: 0.93,
            }
        }
        ("sensitive_document", _)
        | (_, "orca-sonar-document-classifier")
        | ("routing", _)
        | ("tool_class", _)
        | ("tool_action", _) => L3AggregationStrategy::MajorityVoteOrHighest,
        _ => L3AggregationStrategy::HighestRiskAboveThresholdOrConfidence { threshold: 0.93 },
    }
}
