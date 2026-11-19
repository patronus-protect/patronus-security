//! Chunk aggregation for long inputs: pick the decisive chunk under an
//! [`L3AggregationStrategy`], track early-exit stability while chunks arrive
//! and fold the per-chunk layer evidence into one result.
use std::collections::HashMap;

use super::{L3AggregationStrategy, L3PipelineEarlyExit};
use crate::{EvaluationResult, LayerResult};

/// One chunk's class and confidence, as seen by the aggregation.
#[derive(Debug, Clone, Copy)]
pub struct ChunkDecision<'a> {
    pub class_name: &'a str,
    pub confidence: f64,
}

/// Index of the decisive chunk, or `None` for no chunks.
pub fn aggregate_decision_index(
    candidates: &[ChunkDecision<'_>],
    aggregation: &L3AggregationStrategy,
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
        L3AggregationStrategy::AnyPositiveOrHighest {
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
        L3AggregationStrategy::HighestRiskAboveThresholdOrConfidence { threshold } => candidates
            .iter()
            .enumerate()
            .filter(|(_, candidate)| {
                !is_safe_label(candidate.class_name, safe_class)
                    && candidate.confidence >= *threshold
            })
            .max_by(|(_, left), (_, right)| left.confidence.total_cmp(&right.confidence))
            .map(|(index, _)| index)
            .or_else(highest_confidence),
        L3AggregationStrategy::MajorityVoteOrHighest => {
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

/// Incremental per-head state that tells when the remaining chunks can no
/// longer change the aggregated answer.
#[derive(Debug, Clone)]
pub struct HeadDecisionState {
    aggregation: L3AggregationStrategy,
    safe_class: String,
    early_exit: L3PipelineEarlyExit,
    total_chunks: usize,
    observed_chunks: usize,
    counts: HashMap<String, usize>,
    stable_positive_found: bool,
}

impl HeadDecisionState {
    pub fn new(
        aggregation: L3AggregationStrategy,
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

    pub fn observe(&mut self, class_name: &str, confidence: f64) {
        self.observed_chunks += 1;
        *self.counts.entry(class_name.to_string()).or_default() += 1;
        match &self.aggregation {
            L3AggregationStrategy::AnyPositiveOrHighest {
                positive_class,
                threshold,
            } => {
                if class_name == positive_class && confidence >= *threshold {
                    self.stable_positive_found = true;
                }
            }
            L3AggregationStrategy::HighestRiskAboveThresholdOrConfidence { threshold } => {
                if !is_safe_label(class_name, &self.safe_class) && confidence >= *threshold {
                    self.stable_positive_found = true;
                }
            }
            L3AggregationStrategy::MajorityVoteOrHighest => {}
        }
    }

    pub fn head_is_stable(&self) -> bool {
        if self.early_exit == L3PipelineEarlyExit::Disabled
            || self.observed_chunks >= self.total_chunks
        {
            return false;
        }
        match self.aggregation {
            L3AggregationStrategy::AnyPositiveOrHighest { .. }
            | L3AggregationStrategy::HighestRiskAboveThresholdOrConfidence { .. } => {
                self.stable_positive_found
            }
            L3AggregationStrategy::MajorityVoteOrHighest => self.non_safe_majority_is_stable(),
        }
    }

    pub fn request_should_stop(&self) -> bool {
        self.early_exit == L3PipelineEarlyExit::RequestWidePositive && self.stable_positive_found
    }

    pub fn observed_chunks(&self) -> usize {
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

/// Whether `class_name` is the pipeline's safe class or a generic safe label.
pub fn is_safe_label(class_name: &str, safe_class: &str) -> bool {
    class_name == safe_class || matches!(class_name, "benign" | "safe" | "none" | "no_entities")
}

/// The decisive chunk's result plus the full-text layers, the decisive
/// chunk's layers and one summary layer per level for the omitted work.
pub struct LongTextAggregate {
    pub result: EvaluationResult,
    pub layers: Vec<LayerResult>,
}

/// Fold per-chunk outputs into one result under `aggregation`.
pub fn aggregate_chunk_outputs(
    full_text_layers: Vec<LayerResult>,
    chunk_outputs: Vec<(EvaluationResult, Vec<LayerResult>)>,
    chunk_count: usize,
    safe_class: &str,
    aggregation: L3AggregationStrategy,
) -> Option<LongTextAggregate> {
    let decisions = chunk_outputs
        .iter()
        .map(|(result, _)| ChunkDecision {
            class_name: &result.class_name,
            confidence: result.confidence,
        })
        .collect::<Vec<_>>();
    let chunk_id = aggregate_decision_index(&decisions, &aggregation, safe_class)?;
    let (result, mut chunk_layers) = chunk_outputs[chunk_id].clone();
    let mut layers = full_text_layers;
    let selected_layer_totals = layer_duration_totals(&chunk_layers);
    let all_layers = || chunk_outputs.iter().flat_map(|(_, layers)| layers.iter());
    let all_layer_totals = layer_duration_totals(all_layers());
    let all_layer_counts =
        all_layers().fold(HashMap::<String, usize>::new(), |mut counts, layer| {
            *counts.entry(layer.level.clone()).or_insert(0) += 1;
            counts
        });

    for layer in &mut chunk_layers {
        layer
            .details
            .insert("chunk_id".to_string(), serde_json::json!(chunk_id));
        layer
            .details
            .insert("chunk_count".to_string(), serde_json::json!(chunk_count));
        layer
            .details
            .insert("long_text_routing".to_string(), serde_json::json!(true));
    }

    for level in ["L1", "L2", "L3"] {
        let total_ms = *all_layer_totals.get(level).unwrap_or(&0.0);
        let selected_ms = *selected_layer_totals.get(level).unwrap_or(&0.0);
        let omitted_ms = (total_ms - selected_ms).max(0.0);
        if omitted_ms <= f64::EPSILON {
            continue;
        }
        let representative_details = all_layers()
            .find(|layer| layer.level == level && !layer.details.is_empty())
            .map(|layer| layer.details.clone());
        layers.push(summary_layer(
            level,
            &result,
            omitted_ms,
            SummaryCounts {
                chunk_count,
                selected_chunk_id: chunk_id,
                selected_ms,
                total_ms,
                total_layer_count: all_layer_counts.get(level).copied().unwrap_or(0),
            },
            representative_details,
        ));
    }
    layers.extend(chunk_layers);
    Some(LongTextAggregate { result, layers })
}

struct SummaryCounts {
    chunk_count: usize,
    selected_chunk_id: usize,
    selected_ms: f64,
    total_ms: f64,
    total_layer_count: usize,
}

fn summary_layer(
    level: &str,
    result: &EvaluationResult,
    duration_ms: f64,
    counts: SummaryCounts,
    representative_details: Option<HashMap<String, serde_json::Value>>,
) -> LayerResult {
    let mut details = HashMap::from([
        (
            "chunk_count".to_string(),
            serde_json::json!(counts.chunk_count),
        ),
        (
            "selected_chunk_id".to_string(),
            serde_json::json!(counts.selected_chunk_id),
        ),
        ("long_text_routing".to_string(), serde_json::json!(true)),
        ("summary".to_string(), serde_json::json!(true)),
        (
            "omitted_selected_chunk_ms".to_string(),
            serde_json::json!(counts.selected_ms),
        ),
        (
            "total_chunk_ms".to_string(),
            serde_json::json!(counts.total_ms),
        ),
        (
            "total_chunk_layer_count".to_string(),
            serde_json::json!(counts.total_layer_count),
        ),
    ]);
    if let Some(representative_details) = representative_details {
        for (key, value) in representative_details {
            details.entry(key).or_insert(value);
        }
    }

    LayerResult {
        level: level.to_string(),
        layer_type: "chunked_batch_summary".to_string(),
        class_name: result.class_name.clone(),
        confidence: result.confidence,
        matched: false,
        duration_ms,
        thresholds: HashMap::new(),
        details,
    }
}

fn layer_duration_totals<'a>(
    layers: impl IntoIterator<Item = &'a LayerResult>,
) -> HashMap<String, f64> {
    layers
        .into_iter()
        .fold(HashMap::new(), |mut totals, layer| {
            *totals.entry(layer.level.clone()).or_insert(0.0) += layer.duration_ms;
            totals
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attack(threshold: f64) -> L3AggregationStrategy {
        L3AggregationStrategy::AnyPositiveOrHighest {
            positive_class: "attack".to_string(),
            threshold,
        }
    }

    #[test]
    fn request_wide_positive_stops_only_after_threshold() {
        let mut state = HeadDecisionState::new(
            attack(0.93),
            "benign",
            L3PipelineEarlyExit::RequestWidePositive,
            4,
        );
        state.observe("attack", 0.92);
        assert!(!state.request_should_stop());
        state.observe("attack", 0.95);
        assert!(state.request_should_stop());
        assert_eq!(state.observed_chunks(), 2);
    }

    #[test]
    fn majority_never_finalizes_a_safe_majority() {
        let mut state = HeadDecisionState::new(
            L3AggregationStrategy::MajorityVoteOrHighest,
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
            L3AggregationStrategy::MajorityVoteOrHighest,
            "safe",
            L3PipelineEarlyExit::HeadStable,
            5,
        );
        state.observe("legal", 0.8);
        state.observe("legal", 0.7);
        state.observe("legal", 0.6);
        assert!(state.head_is_stable());
    }

    #[test]
    fn decisive_chunk_prefers_positive_above_threshold_then_highest_confidence() {
        let chunks = [
            ChunkDecision {
                class_name: "benign",
                confidence: 0.99,
            },
            ChunkDecision {
                class_name: "attack",
                confidence: 0.95,
            },
        ];
        assert_eq!(
            aggregate_decision_index(&chunks, &attack(0.93), "benign"),
            Some(1)
        );
        assert_eq!(
            aggregate_decision_index(&chunks, &attack(0.96), "benign"),
            Some(0)
        );
        assert_eq!(aggregate_decision_index(&[], &attack(0.5), "benign"), None);
    }

    fn output(class_name: &str, confidence: f64, ms: f64) -> (EvaluationResult, Vec<LayerResult>) {
        (
            EvaluationResult {
                class_name: class_name.to_string(),
                confidence,
                level: "L3".to_string(),
            },
            vec![LayerResult {
                level: "L3".to_string(),
                layer_type: "onnx".to_string(),
                class_name: class_name.to_string(),
                confidence,
                matched: true,
                duration_ms: ms,
                thresholds: HashMap::new(),
                details: HashMap::new(),
            }],
        )
    }

    #[test]
    fn aggregate_selects_the_decisive_chunk_and_summarizes_the_rest() {
        let aggregate = aggregate_chunk_outputs(
            Vec::new(),
            vec![output("benign", 0.9, 2.0), output("attack", 0.97, 3.0)],
            2,
            "benign",
            attack(0.93),
        )
        .unwrap();
        assert_eq!(aggregate.result.class_name, "attack");
        assert_eq!(aggregate.layers.len(), 2);
        let summary = &aggregate.layers[0];
        assert_eq!(summary.layer_type, "chunked_batch_summary");
        assert_eq!(summary.duration_ms, 2.0);
        assert_eq!(summary.details["selected_chunk_id"], 1);
        assert_eq!(aggregate.layers[1].details["chunk_id"], 1);
    }
}
