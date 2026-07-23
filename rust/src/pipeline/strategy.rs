// SPDX-License-Identifier: GPL-3.0-only
use std::collections::HashMap;

use crate::{L3AggregationStrategy, L3PipelineEarlyExit};

#[derive(Debug, Clone, PartialEq)]
pub enum ChunkAggregation {
    HighestRiskAboveThresholdOrConfidence {
        threshold: f64,
    },
    AnyPositiveOrHighest {
        positive_class: String,
        threshold: f64,
    },
    MajorityVoteOrHighest,
}

impl From<L3AggregationStrategy> for ChunkAggregation {
    fn from(value: L3AggregationStrategy) -> Self {
        match value {
            L3AggregationStrategy::AnyPositiveOrHighest {
                positive_class,
                threshold,
            } => Self::AnyPositiveOrHighest {
                positive_class,
                threshold,
            },
            L3AggregationStrategy::HighestRiskAboveThresholdOrConfidence { threshold } => {
                Self::HighestRiskAboveThresholdOrConfidence { threshold }
            }
            L3AggregationStrategy::MajorityVoteOrHighest => Self::MajorityVoteOrHighest,
        }
    }
}

#[derive(Debug, Clone)]
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
                positive_class: "attack".to_string(),
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
            aggregation: ChunkAggregation::HighestRiskAboveThresholdOrConfidence {
                threshold: 0.93,
            },
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ChunkDecision<'a> {
    pub(crate) class_name: &'a str,
    pub(crate) confidence: f64,
}

pub(crate) fn aggregate_decision_index(
    candidates: &[ChunkDecision<'_>],
    aggregation: &ChunkAggregation,
    safe_class: &str,
) -> Option<usize> {
    let highest_confidence = || {
        candidates
            .iter()
            .enumerate()
            .max_by(|(_, left), (_, right)| left.confidence.total_cmp(&right.confidence))
            .map(|(index, _)| index)
    };
    match aggregation {
        ChunkAggregation::AnyPositiveOrHighest {
            positive_class,
            threshold,
        } => candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| {
                candidate.class_name == positive_class && candidate.confidence >= *threshold
            })
            .max_by(|(_, left), (_, right)| left.confidence.total_cmp(&right.confidence))
            .map(|(index, _)| index)
            .or_else(highest_confidence),
        ChunkAggregation::HighestRiskAboveThresholdOrConfidence { threshold } => candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| {
                !is_safe_label(candidate.class_name, safe_class)
                    && candidate.confidence >= *threshold
            })
            .max_by(|(_, left), (_, right)| left.confidence.total_cmp(&right.confidence))
            .map(|(index, _)| index)
            .or_else(highest_confidence),
        ChunkAggregation::MajorityVoteOrHighest => {
            let mut votes = HashMap::<&str, (usize, f64, f64)>::new();
            for candidate in candidates {
                if is_safe_label(candidate.class_name, safe_class) {
                    continue;
                }
                let entry = votes.entry(candidate.class_name).or_default();
                entry.0 += 1;
                entry.1 += candidate.confidence;
                entry.2 = entry.2.max(candidate.confidence);
            }
            let winning_class = votes
                .into_iter()
                .max_by(|(_, left), (_, right)| {
                    left.0
                        .cmp(&right.0)
                        .then_with(|| left.1.total_cmp(&right.1))
                        .then_with(|| left.2.total_cmp(&right.2))
                })
                .map(|(class_name, _)| class_name);
            winning_class
                .and_then(|winning_class| {
                    candidates
                        .iter()
                        .enumerate()
                        .filter(|(_, candidate)| candidate.class_name == winning_class)
                        .max_by(|(_, left), (_, right)| {
                            left.confidence.total_cmp(&right.confidence)
                        })
                        .map(|(index, _)| index)
                })
                .or_else(highest_confidence)
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HeadDecisionState {
    aggregation: ChunkAggregation,
    safe_class: String,
    early_exit: L3PipelineEarlyExit,
    total_chunks: usize,
    observed_chunks: usize,
    counts: HashMap<String, usize>,
    stable_positive_found: bool,
}

impl HeadDecisionState {
    pub(crate) fn new(
        aggregation: ChunkAggregation,
        safe_class: impl Into<String>,
        early_exit: L3PipelineEarlyExit,
        total_chunks: usize,
    ) -> Self {
        Self {
            aggregation,
            safe_class: safe_class.into(),
            early_exit,
            total_chunks,
            observed_chunks: 0,
            counts: HashMap::new(),
            stable_positive_found: false,
        }
    }

    pub(crate) fn observe(&mut self, class_name: &str, confidence: f64) {
        self.observed_chunks += 1;
        *self.counts.entry(class_name.to_string()).or_default() += 1;
        match &self.aggregation {
            ChunkAggregation::AnyPositiveOrHighest {
                positive_class,
                threshold,
            } => {
                if class_name == positive_class && confidence >= *threshold {
                    self.stable_positive_found = true;
                }
            }
            ChunkAggregation::HighestRiskAboveThresholdOrConfidence { threshold } => {
                if !is_safe_label(class_name, &self.safe_class) && confidence >= *threshold {
                    self.stable_positive_found = true;
                }
            }
            ChunkAggregation::MajorityVoteOrHighest => {}
        }
    }

    pub(crate) fn head_is_stable(&self) -> bool {
        if self.early_exit == L3PipelineEarlyExit::Disabled
            || self.observed_chunks >= self.total_chunks
        {
            return false;
        }
        match self.aggregation {
            ChunkAggregation::AnyPositiveOrHighest { .. }
            | ChunkAggregation::HighestRiskAboveThresholdOrConfidence { .. } => {
                self.stable_positive_found
            }
            ChunkAggregation::MajorityVoteOrHighest => self.non_safe_majority_is_stable(),
        }
    }

    pub(crate) fn request_should_stop(&self) -> bool {
        self.early_exit == L3PipelineEarlyExit::RequestWidePositive && self.stable_positive_found
    }

    pub(crate) fn observed_chunks(&self) -> usize {
        self.observed_chunks
    }

    fn non_safe_majority_is_stable(&self) -> bool {
        let unresolved = self.total_chunks.saturating_sub(self.observed_chunks);
        let mut leader_count = 0usize;
        let mut competitor_count = 0usize;
        for (class_name, count) in &self.counts {
            if is_safe_label(class_name, &self.safe_class) {
                continue;
            }
            if *count > leader_count {
                competitor_count = leader_count;
                leader_count = *count;
            } else {
                competitor_count = competitor_count.max(*count);
            }
        }
        leader_count > 0 && leader_count > competitor_count + unresolved
    }
}

pub(crate) fn is_safe_label(class_name: &str, safe_class: &str) -> bool {
    class_name == safe_class || matches!(class_name, "benign" | "safe" | "none" | "no_entities")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wide_positive_stops_only_after_threshold() {
        let mut state = HeadDecisionState::new(
            ChunkAggregation::AnyPositiveOrHighest {
                positive_class: "attack".to_string(),
                threshold: 0.93,
            },
            "benign",
            L3PipelineEarlyExit::RequestWidePositive,
            4,
        );
        state.observe("attack", 0.92);
        assert!(!state.request_should_stop());
        state.observe("attack", 0.95);
        assert!(state.request_should_stop());
    }

    #[test]
    fn majority_never_finalizes_a_safe_majority() {
        let mut state = HeadDecisionState::new(
            ChunkAggregation::MajorityVoteOrHighest,
            "safe",
            L3PipelineEarlyExit::HeadStable,
            5,
        );
        for _ in 0..4 {
            state.observe("safe", 0.99);
        }
        assert!(!state.head_is_stable());
    }

    #[test]
    fn non_safe_majority_stops_when_remaining_chunks_cannot_change_it() {
        let mut state = HeadDecisionState::new(
            ChunkAggregation::MajorityVoteOrHighest,
            "safe",
            L3PipelineEarlyExit::HeadStable,
            5,
        );
        state.observe("legal", 0.8);
        state.observe("legal", 0.7);
        state.observe("legal", 0.6);
        assert!(state.head_is_stable());
    }
}
