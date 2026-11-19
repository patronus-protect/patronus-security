// SPDX-License-Identifier: GPL-3.0-only
//! Test-only views of the long-text L3 planning; the chunk aggregation
//! itself is `patronus_ark_core::cascade::aggregate_chunk_outputs`.
use std::collections::HashMap;

use crate::{EvaluationResult, LayerResult};

pub struct L3CandidateSelection {
    pub indexes: Vec<usize>,
    pub raw_count: usize,
    pub deduped_count: usize,
    pub strategy: &'static str,
}

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
