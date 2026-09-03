// SPDX-License-Identifier: GPL-3.0-only
use super::{
    ntdb_error,
    package::{ByteSpan, L2ChunkOutput, L3Candidate},
    NtdbResult, ScoreOutput,
};

#[derive(Debug, Clone)]
pub struct NtdbDecision {
    pub model_id: String,
    pub aggregator_id: String,
    pub task: String,
    pub labels: Vec<String>,
    pub fallback_label: String,
    pub fallback_confidence: f64,
    pub route_to_l3: bool,
    pub promote_score: Option<f64>,
    pub promote_threshold: Option<f64>,
    pub class_scores: Vec<f32>,
    pub class_logits: Vec<f32>,
    pub chunks: usize,
    pub chunk_promote_scores: Vec<Option<f32>>,
    pub l3_candidate_spans: Vec<ByteSpan>,
    pub l3_candidates: Vec<L3Candidate>,
    pub l2_chunk_outputs: Vec<L2ChunkOutput>,
}

impl NtdbDecision {
    pub fn from_score_output(model_id: String, output: ScoreOutput) -> NtdbResult<Self> {
        let predicted_index = output.predicted_index;
        let fallback_label = output
            .labels
            .get(predicted_index)
            .cloned()
            .ok_or_else(|| ntdb_error("NTDB output predicted index is out of bounds"))?;
        let fallback_confidence = output
            .class_scores
            .get(predicted_index)
            .copied()
            .unwrap_or(0.0)
            .clamp(0.0, 1.0);
        let route_to_l3 = output
            .promote_score
            .zip(output.promote_threshold)
            .is_some_and(|(score, threshold)| score >= threshold);

        let mut l3_candidates = output.l3_candidates;
        for candidate in &mut l3_candidates {
            candidate.source_model = model_id.clone();
            candidate.l2_class = fallback_label.clone();
        }
        let mut l2_chunk_outputs = output.l2_chunk_outputs;
        for chunk in &mut l2_chunk_outputs {
            chunk.source_model = model_id.clone();
        }
        Ok(NtdbDecision {
            model_id,
            aggregator_id: output.aggregator_id,
            task: output.task,
            labels: output.labels,
            fallback_label,
            fallback_confidence: f64::from(fallback_confidence),
            route_to_l3,
            promote_score: output.promote_score.map(f64::from),
            promote_threshold: output.promote_threshold.map(f64::from),
            class_scores: output.class_scores,
            class_logits: output.class_logits,
            chunks: output.chunks,
            chunk_promote_scores: output.chunk_promote_scores,
            l3_candidate_spans: output.l3_candidate_spans,
            l3_candidates,
            l2_chunk_outputs,
        })
    }
}
