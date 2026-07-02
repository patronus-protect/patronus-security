use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::ml::onnx::LazyOnnxTextClassifier;
use crate::{EvaluationResult, LayerResult, OnnxBatchMode, ScanExecution, TextChunking};

pub(crate) struct LongTextAggregate {
    pub result: EvaluationResult,
    pub layers: Vec<LayerResult>,
}

pub(crate) type L3CandidateInference = (EvaluationResult, HashMap<String, serde_json::Value>, f64);

pub(crate) struct L3CandidateSelection {
    pub indexes: Vec<usize>,
    pub raw_count: usize,
    pub deduped_count: usize,
    pub strategy: &'static str,
}

pub(crate) struct L3CandidateError {
    pub details: HashMap<String, serde_json::Value>,
    pub duration_ms: f64,
}

pub(crate) fn chunk_text_bytes(text: &str, chunking: TextChunking) -> Vec<String> {
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

pub(crate) fn infer_l3_candidate_texts(
    l3: &Option<Mutex<LazyOnnxTextClassifier>>,
    texts: &[String],
    execution: &ScanExecution,
) -> Option<Result<Vec<L3CandidateInference>, L3CandidateError>> {
    if texts.is_empty() {
        return Some(Ok(Vec::new()));
    }
    let mut model = l3.as_ref()?.lock().ok()?;
    let started = Instant::now();
    let result = match execution.onnx_batch_mode() {
        OnnxBatchMode::LazyBatches => texts
            .iter()
            .map(|text| model.infer(text, execution.backend()))
            .collect::<Result<Vec<_>, _>>(),
        OnnxBatchMode::TensorBatch => model.infer_batch(texts, execution.backend()),
    };
    let duration_ms = elapsed_ms(started) / texts.len() as f64;
    let metadata = l3_metadata(
        model.precision(),
        model.model_path(),
        model.model_name(),
        model.execution_provider(),
        execution.onnx_batch_mode().as_str(),
        texts.len(),
    );
    Some(match result {
        Ok(results) => Ok(results
            .into_iter()
            .map(|result| (result, metadata.clone(), duration_ms))
            .collect()),
        Err(err) => {
            let mut details = metadata;
            details.insert("error".to_string(), serde_json::json!(err.to_string()));
            details.insert("fallback_due_to_error".to_string(), serde_json::json!(true));
            Err(L3CandidateError {
                details,
                duration_ms,
            })
        }
    })
}

pub(crate) fn candidate_selection<F>(
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

pub(crate) fn aggregate_chunk_outputs(
    full_text_layers: Vec<LayerResult>,
    chunk_outputs: Vec<(EvaluationResult, Vec<LayerResult>)>,
    chunk_count: usize,
    safe_class: &str,
    verify_non_benign_l2: bool,
) -> Option<LongTextAggregate> {
    let selected = chunk_outputs
        .iter()
        .enumerate()
        .filter(|(_, (result, _))| result.class_name != safe_class)
        .max_by(|(_, (left, _)), (_, (right, _))| left.confidence.total_cmp(&right.confidence))
        .or_else(|| {
            chunk_outputs
                .iter()
                .enumerate()
                .max_by(|(_, (left, _)), (_, (right, _))| {
                    left.confidence.total_cmp(&right.confidence)
                })
        })?;

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

pub(crate) fn l3_metadata(
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

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(class_name: &str, confidence: f64, level: &str) -> EvaluationResult {
        EvaluationResult {
            class_name: class_name.to_string(),
            confidence,
            level: level.to_string(),
        }
    }

    fn layer(
        level: &str,
        class_name: &str,
        confidence: f64,
        matched: bool,
        duration_ms: f64,
    ) -> LayerResult {
        LayerResult {
            level: level.to_string(),
            layer_type: "test".to_string(),
            class_name: class_name.to_string(),
            confidence,
            matched,
            duration_ms,
            thresholds: HashMap::new(),
            details: HashMap::new(),
        }
    }

    #[test]
    fn chunk_text_bytes_preserves_tail_and_overlap() {
        let chunking = TextChunking::new(5, 2).unwrap();

        let chunks = chunk_text_bytes("abcdefghijkl", chunking);

        assert_eq!(chunks, vec!["abcde", "defgh", "ghijk", "jkl"]);
        assert_eq!(chunks.last().unwrap(), "jkl");
    }

    #[test]
    fn candidate_selection_dedupes_contiguous_same_class_by_best_confidence() {
        let chunk_outputs = vec![
            (
                result("secret", 0.60, "L2"),
                vec![layer("L2", "secret", 0.60, true, 1.0)],
            ),
            (
                result("secret", 0.90, "L2"),
                vec![layer("L2", "secret", 0.90, true, 1.0)],
            ),
            (
                result("credential", 0.80, "L2"),
                vec![layer("L2", "credential", 0.80, true, 1.0)],
            ),
            (
                result("safe", 1.0, "L1"),
                vec![layer("L1", "safe", 1.0, true, 1.0)],
            ),
        ];

        let selection =
            candidate_selection(&chunk_outputs, |result, _| result.class_name != "safe");

        assert_eq!(selection.raw_count, 3);
        assert_eq!(selection.deduped_count, 2);
        assert_eq!(selection.indexes, vec![1, 2]);
        assert_eq!(selection.strategy, "contiguous_same_class_best_confidence");
    }

    #[test]
    fn aggregate_chunk_outputs_selects_highest_risk_and_summarizes_omitted_work() {
        let full_text_layers = vec![layer("L1", "safe", 0.0, false, 0.5)];
        let chunk_outputs = vec![
            (
                result("safe", 0.99, "L1"),
                vec![layer("L1", "safe", 0.99, true, 1.0)],
            ),
            (
                result("secret", 0.70, "L2"),
                vec![layer("L2", "secret", 0.70, true, 2.0)],
            ),
            (
                result("credential", 0.95, "L2"),
                vec![layer("L2", "credential", 0.95, true, 3.0)],
            ),
        ];

        let aggregate =
            aggregate_chunk_outputs(full_text_layers, chunk_outputs, 3, "safe", true).unwrap();

        assert_eq!(aggregate.result.class_name, "credential");
        assert_eq!(aggregate.result.confidence, 0.95);
        let selected_chunk_layer = aggregate
            .layers
            .iter()
            .find(|layer| {
                layer.class_name == "credential"
                    && layer.details.get("chunk_id") == Some(&serde_json::json!(2))
            })
            .expect("selected chunk layer should be retained");
        assert_eq!(
            selected_chunk_layer.details.get("chunk_count"),
            Some(&serde_json::json!(3))
        );

        let l2_summary = aggregate
            .layers
            .iter()
            .find(|layer| layer.level == "L2" && layer.layer_type == "chunked_batch_summary")
            .expect("omitted L2 work should be summarized");
        assert_eq!(l2_summary.duration_ms, 2.0);
        assert_eq!(
            l2_summary.details.get("total_chunk_layer_count"),
            Some(&serde_json::json!(2))
        );
    }

    #[test]
    fn l3_metadata_records_runtime_backend_and_batch_shape() {
        let metadata = l3_metadata(
            Some("fp16"),
            Some(std::path::Path::new("/tmp/model.onnx")),
            "demo-model",
            Some("CPUExecutionProvider"),
            "tensor_batch",
            4,
        );

        assert_eq!(
            metadata.get("runtime"),
            Some(&serde_json::json!("onnxruntime"))
        );
        assert_eq!(metadata.get("precision"), Some(&serde_json::json!("fp16")));
        assert_eq!(
            metadata.get("model_name"),
            Some(&serde_json::json!("demo-model"))
        );
        assert_eq!(
            metadata.get("batch_mode"),
            Some(&serde_json::json!("tensor_batch"))
        );
        assert_eq!(metadata.get("batch_size"), Some(&serde_json::json!(4)));
    }
}
