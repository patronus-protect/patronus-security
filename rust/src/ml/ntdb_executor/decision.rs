use super::{ntdb_error, package::ByteSpan, NtdbResult, ScoreOutput};

#[derive(Debug, Clone)]
pub struct NtdbDecision {
    pub model_id: String,
    pub aggregator_id: String,
    pub task: String,
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
}

impl NtdbDecision {
    pub fn from_score_output(model_id: String, output: ScoreOutput) -> NtdbResult<Self> {
        if output.task == "binary_promote" || has_binary_promote_labels(&output.labels) {
            return binary_promote_decision(model_id, output);
        }
        multiclass_or_plain_decision(model_id, output)
    }
}

fn binary_promote_decision(model_id: String, output: ScoreOutput) -> NtdbResult<NtdbDecision> {
    let attack_index = label_index(&output.labels, "attack").unwrap_or(1);
    let promote_index = label_index(&output.labels, "promote").unwrap_or(2);
    let attack_score = *output
        .class_scores
        .get(attack_index)
        .ok_or_else(|| ntdb_error("binary_promote output missing attack score"))?;
    let promote_score = *output
        .class_scores
        .get(promote_index)
        .or(output.promote_score.as_ref())
        .ok_or_else(|| ntdb_error("binary_promote output missing promote score"))?;
    let attack_threshold = output.attack_threshold.unwrap_or(0.5);
    let promote_threshold = output.promote_threshold.unwrap_or(1.0);
    let attack = attack_score >= attack_threshold;
    let fallback_label = if attack { "attack" } else { "benign" }.to_string();
    let fallback_confidence = if attack {
        attack_score
    } else {
        1.0 - attack_score
    };

    Ok(NtdbDecision {
        model_id,
        aggregator_id: output.aggregator_id,
        task: output.task,
        fallback_label,
        fallback_confidence: f64::from(fallback_confidence.clamp(0.0, 1.0)),
        route_to_l3: promote_score >= promote_threshold,
        promote_score: Some(f64::from(promote_score)),
        promote_threshold: Some(f64::from(promote_threshold)),
        class_scores: output.class_scores,
        class_logits: output.class_logits,
        chunks: output.chunks,
        chunk_promote_scores: output.chunk_promote_scores,
        l3_candidate_spans: output.l3_candidate_spans,
    })
}

fn multiclass_or_plain_decision(model_id: String, output: ScoreOutput) -> NtdbResult<NtdbDecision> {
    let predicted_index = if output.predicted_label == "promote" {
        best_non_promote_index(&output.labels, &output.class_scores)
            .ok_or_else(|| ntdb_error("multiclass promote output has no fallback label"))?
    } else {
        output.predicted_index
    };
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

    Ok(NtdbDecision {
        model_id,
        aggregator_id: output.aggregator_id,
        task: output.task,
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
    })
}

fn label_index(labels: &[String], needle: &str) -> Option<usize> {
    labels.iter().position(|label| label == needle)
}

fn has_binary_promote_labels(labels: &[String]) -> bool {
    label_index(labels, "benign").is_some()
        && label_index(labels, "attack").is_some()
        && label_index(labels, "promote").is_some()
}

fn best_non_promote_index(labels: &[String], scores: &[f32]) -> Option<usize> {
    scores
        .iter()
        .copied()
        .enumerate()
        .filter(|(index, _)| labels.get(*index).is_some_and(|label| label != "promote"))
        .max_by(|left, right| left.1.total_cmp(&right.1))
        .map(|(index, _)| index)
}
