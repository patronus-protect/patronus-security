use std::collections::HashMap;

use super::ChunkAggregation;
use crate::{EvaluationResult, LayerResult, TextChunking};

pub struct LongTextAggregate {
    pub result: EvaluationResult,
    pub layers: Vec<LayerResult>,
}

#[cfg(feature = "test-util")]
pub struct L3CandidateSelection {
    pub indexes: Vec<usize>,
    pub raw_count: usize,
    pub deduped_count: usize,
    pub strategy: &'static str,
}

pub fn chunk_text_bytes(text: &str, chunking: TextChunking) -> Vec<String> {
    let raw = text.as_bytes();
    if raw.len() <= chunking.chunk_size_bytes {
        return vec![text.to_string()];
    }

    let mut chunks = Vec::new();
    let step = chunking.chunk_size_bytes - chunking.overlap_bytes;
    let mut start = 0;
    while start < raw.len() {
        let end = (start + chunking.chunk_size_bytes).min(raw.len());
        let chunk = String::from_utf8_lossy(&raw[start..end]).to_string();
        if !chunk.is_empty() {
            chunks.push(chunk);
        }
        if end == raw.len() {
            break;
        }
        start += step;
    }
    chunks
}

#[cfg(feature = "test-util")]
pub fn candidate_selection<F>(
    chunk_outputs: &[(EvaluationResult, Vec<LayerResult>)],
    mut needs_l3: F,
) -> L3CandidateSelection
where
    F: FnMut(&EvaluationResult, &[LayerResult]) -> bool,
{
    let mut raw_candidates: Vec<usize> = chunk_outputs
        .iter()
        .enumerate()
        .filter(|(_, (result, layers))| needs_l3(result, layers))
        .map(|(index, _)| index)
        .collect();
    let raw_count = raw_candidates.len();
    raw_candidates.sort_unstable();

    let mut candidates = Vec::new();
    let mut run: Vec<usize> = Vec::new();
    let mut run_class: Option<String> = None;

    for index in raw_candidates {
        let class_name = chunk_outputs[index].0.class_name.clone();
        let contiguous = run
            .last()
            .is_some_and(|previous| index == previous.saturating_add(1));
        let same_class = run_class.as_deref() == Some(class_name.as_str());
        if !run.is_empty() && (!contiguous || !same_class) {
            candidates.push(best_candidate_in_run(&run, chunk_outputs));
            run.clear();
        }
        if run.is_empty() {
            run_class = Some(class_name);
        }
        run.push(index);
    }

    if !run.is_empty() {
        candidates.push(best_candidate_in_run(&run, chunk_outputs));
    }

    candidates.sort_by(|left, right| {
        let left_conf = chunk_outputs[*left].0.confidence;
        let right_conf = chunk_outputs[*right].0.confidence;
        right_conf.total_cmp(&left_conf)
    });

    let deduped_count = candidates.len();
    L3CandidateSelection {
        indexes: candidates,
        raw_count,
        deduped_count,
        strategy: "contiguous_same_class_best_confidence",
    }
}

#[cfg(feature = "test-util")]
fn best_candidate_in_run(
    run: &[usize],
    chunk_outputs: &[(EvaluationResult, Vec<LayerResult>)],
) -> usize {
    run.iter()
        .copied()
        .max_by(|left, right| {
            let left_conf = chunk_outputs[*left].0.confidence;
            let right_conf = chunk_outputs[*right].0.confidence;
            left_conf.total_cmp(&right_conf)
        })
        .expect("candidate run must not be empty")
}

pub fn aggregate_chunk_outputs(
    full_text_layers: Vec<LayerResult>,
    chunk_outputs: Vec<(EvaluationResult, Vec<LayerResult>)>,
    chunk_count: usize,
    safe_class: &str,
    verify_non_benign_l2: bool,
    aggregation: ChunkAggregation,
) -> Option<LongTextAggregate> {
    let selected = select_chunk_output(&chunk_outputs, safe_class, aggregation)?;

    let chunk_id = selected.0;
    let result = (selected.1).0.clone();
    let mut layers = full_text_layers;
    let mut chunk_layers = (selected.1).1.clone();
    let selected_layer_totals = layer_duration_totals(&chunk_layers);
    let all_layer_totals = chunk_outputs
        .iter()
        .flat_map(|(_, layers)| layers.iter())
        .fold(HashMap::<String, f64>::new(), |mut totals, layer| {
            *totals.entry(layer.level.clone()).or_insert(0.0) += layer.duration_ms;
            totals
        });
    let all_layer_counts = chunk_outputs
        .iter()
        .flat_map(|(_, layers)| layers.iter())
        .fold(HashMap::<String, usize>::new(), |mut counts, layer| {
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
        layer.details.insert(
            "verify_non_benign_l2".to_string(),
            serde_json::json!(verify_non_benign_l2),
        );
    }

    for level in ["L1", "L2", "L3"] {
        let total_ms = *all_layer_totals.get(level).unwrap_or(&0.0);
        let selected_ms = *selected_layer_totals.get(level).unwrap_or(&0.0);
        let omitted_ms = (total_ms - selected_ms).max(0.0);
        if omitted_ms <= f64::EPSILON {
            continue;
        }
        let representative_details = chunk_outputs
            .iter()
            .flat_map(|(_, layers)| layers.iter())
            .find(|layer| layer.level == level && !layer.details.is_empty())
            .map(|layer| layer.details.clone());
        layers.push(summary_layer(
            level,
            &result,
            omitted_ms,
            chunk_count,
            chunk_id,
            selected_ms,
            total_ms,
            all_layer_counts.get(level).copied().unwrap_or(0),
            representative_details,
        ));
    }
    layers.extend(chunk_layers);
    Some(LongTextAggregate { result, layers })
}

fn select_chunk_output<'a>(
    chunk_outputs: &'a [(EvaluationResult, Vec<LayerResult>)],
    safe_class: &str,
    aggregation: ChunkAggregation,
) -> Option<(usize, &'a (EvaluationResult, Vec<LayerResult>))> {
    match aggregation {
        ChunkAggregation::AnyPositiveOrHighest {
            positive_class,
            threshold,
        } => chunk_outputs
            .iter()
            .enumerate()
            .filter(|(_, (result, _))| {
                result.class_name == positive_class && result.confidence >= threshold
            })
            .max_by(|(_, (left, _)), (_, (right, _))| left.confidence.total_cmp(&right.confidence))
            .or_else(|| highest_confidence_chunk(chunk_outputs)),
        ChunkAggregation::MajorityVoteOrHighest => {
            majority_vote_chunk(chunk_outputs).or_else(|| highest_confidence_chunk(chunk_outputs))
        }
        ChunkAggregation::HighestRiskOrConfidence => {
            highest_risk_or_confidence_chunk(chunk_outputs, safe_class)
        }
    }
}

fn highest_confidence_chunk<'a>(
    chunk_outputs: &'a [(EvaluationResult, Vec<LayerResult>)],
) -> Option<(usize, &'a (EvaluationResult, Vec<LayerResult>))> {
    chunk_outputs
        .iter()
        .enumerate()
        .max_by(|(_, (left, _)), (_, (right, _))| left.confidence.total_cmp(&right.confidence))
}

fn highest_risk_or_confidence_chunk<'a>(
    chunk_outputs: &'a [(EvaluationResult, Vec<LayerResult>)],
    safe_class: &str,
) -> Option<(usize, &'a (EvaluationResult, Vec<LayerResult>))> {
    chunk_outputs
        .iter()
        .enumerate()
        .filter(|(_, (result, _))| result.class_name != safe_class)
        .max_by(|(_, (left, _)), (_, (right, _))| left.confidence.total_cmp(&right.confidence))
        .or_else(|| highest_confidence_chunk(chunk_outputs))
}

fn majority_vote_chunk<'a>(
    chunk_outputs: &'a [(EvaluationResult, Vec<LayerResult>)],
) -> Option<(usize, &'a (EvaluationResult, Vec<LayerResult>))> {
    let mut votes: HashMap<&str, (usize, f64, f64)> = HashMap::new();
    for (result, _) in chunk_outputs {
        let entry = votes
            .entry(result.class_name.as_str())
            .or_insert((0, 0.0, 0.0));
        entry.0 += 1;
        entry.1 += result.confidence;
        entry.2 = entry.2.max(result.confidence);
    }
    let (winning_class, _) = votes.into_iter().max_by(|(_, left), (_, right)| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.total_cmp(&right.1))
            .then_with(|| left.2.total_cmp(&right.2))
    })?;

    chunk_outputs
        .iter()
        .enumerate()
        .filter(|(_, (result, _))| result.class_name == winning_class)
        .max_by(|(_, (left, _)), (_, (right, _))| left.confidence.total_cmp(&right.confidence))
}

fn summary_layer(
    level: &str,
    result: &EvaluationResult,
    duration_ms: f64,
    chunk_count: usize,
    selected_chunk_id: usize,
    selected_ms: f64,
    total_ms: f64,
    total_layer_count: usize,
    representative_details: Option<HashMap<String, serde_json::Value>>,
) -> LayerResult {
    let mut details = HashMap::from([
        ("chunk_count".to_string(), serde_json::json!(chunk_count)),
        (
            "selected_chunk_id".to_string(),
            serde_json::json!(selected_chunk_id),
        ),
        ("long_text_routing".to_string(), serde_json::json!(true)),
        ("summary".to_string(), serde_json::json!(true)),
        (
            "omitted_selected_chunk_ms".to_string(),
            serde_json::json!(selected_ms),
        ),
        ("total_chunk_ms".to_string(), serde_json::json!(total_ms)),
        (
            "total_chunk_layer_count".to_string(),
            serde_json::json!(total_layer_count),
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

fn layer_duration_totals(layers: &[LayerResult]) -> HashMap<String, f64> {
    layers.iter().fold(HashMap::new(), |mut totals, layer| {
        *totals.entry(layer.level.clone()).or_insert(0.0) += layer.duration_ms;
        totals
    })
}

#[cfg(feature = "test-util")]
pub fn l3_metadata(
    precision: Option<&str>,
    model_path: Option<&std::path::Path>,
    model_name: &str,
    execution_provider: Option<&str>,
    batch_mode: &str,
    batch_size: usize,
) -> HashMap<String, serde_json::Value> {
    let mut details = HashMap::new();
    details.insert("runtime".to_string(), serde_json::json!("onnxruntime"));
    details.insert(
        "execution_provider".to_string(),
        serde_json::json!(execution_provider.unwrap_or("unloaded")),
    );
    details.insert("batch_mode".to_string(), serde_json::json!(batch_mode));
    details.insert("batch_size".to_string(), serde_json::json!(batch_size));
    if let Some(precision) = precision {
        details.insert("precision".to_string(), serde_json::json!(precision));
    }
    if let Some(model_path) = model_path {
        details.insert(
            "model_file".to_string(),
            serde_json::json!(model_path.to_string_lossy().to_string()),
        );
    }
    details.insert("model_name".to_string(), serde_json::json!(model_name));
    details
}
