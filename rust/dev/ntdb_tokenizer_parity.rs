use patronus_security::{
    ml::ntdb_executor::{NtdbDecision, NtdbExecutor},
    NtdbOperatingPoint,
};
use serde::Deserialize;
use std::{collections::BTreeMap, fs, path::Path, time::Instant};

#[derive(Deserialize)]
struct Row {
    text: String,
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        return Err(
            "usage: ntdb_tokenizer_parity <hf-package-dir> <kit-package-dir> <dataset-dir>".into(),
        );
    }

    let started = Instant::now();
    let mut executor = NtdbExecutor::load([
        ("hf".to_string(), args[1].as_str()),
        ("kit".to_string(), args[2].as_str()),
    ])?;
    let load_ms = started.elapsed().as_secs_f64() * 1000.0;
    let texts = load_texts(Path::new(&args[3]))?;
    let started = Instant::now();
    for (index, text) in texts.iter().enumerate() {
        let results = executor.score_all(text, NtdbOperatingPoint::default())?;
        let mut hf = BTreeMap::new();
        let mut kit = BTreeMap::new();
        for result in results {
            let target = if result.model_id == "hf" {
                &mut hf
            } else {
                &mut kit
            };
            target.insert(result.aggregator_id.clone(), result);
        }
        if hf.keys().ne(kit.keys()) {
            return Err(format!("aggregator mismatch at row {index}").into());
        }
        for (aggregator, left) in hf {
            let right = &kit[&aggregator];
            if !same_decision(&left, right) {
                return Err(format!(
                    "decision mismatch at row {index}, aggregator {aggregator}, text={text:?}\nhf={left:?}\nkit={right:?}"
                )
                .into());
            }
        }
    }
    println!(
        "texts={} mismatches=0 score_tolerance=1e-4 load_ms={load_ms:.2} score_ms={:.2}",
        texts.len(),
        started.elapsed().as_secs_f64() * 1000.0
    );
    Ok(())
}

fn load_texts(dir: &Path) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut paths = fs::read_dir(dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut texts = Vec::new();
    for path in paths {
        for line in fs::read_to_string(path)?.lines() {
            texts.push(serde_json::from_str::<Row>(line)?.text);
        }
    }
    Ok(texts)
}

fn same_decision(left: &NtdbDecision, right: &NtdbDecision) -> bool {
    left.aggregator_id == right.aggregator_id
        && left.task == right.task
        && left.fallback_label == right.fallback_label
        && close_f64(left.fallback_confidence, right.fallback_confidence)
        && left.route_to_l3 == right.route_to_l3
        && close_option_f64(left.promote_score, right.promote_score)
        && close_option_f64(left.promote_threshold, right.promote_threshold)
        && close_f32_slices(&left.class_scores, &right.class_scores)
        && close_f32_slices(&left.class_logits, &right.class_logits)
        && left.chunks == right.chunks
        && left.chunk_promote_scores.len() == right.chunk_promote_scores.len()
        && left
            .chunk_promote_scores
            .iter()
            .zip(&right.chunk_promote_scores)
            .all(|(left, right)| close_option_f32(*left, *right))
        && left.l3_candidate_spans.len() == right.l3_candidate_spans.len()
        && left
            .l3_candidate_spans
            .iter()
            .zip(&right.l3_candidate_spans)
            .all(|(left, right)| left.start == right.start && left.end == right.end)
}

fn close_f64(left: f64, right: f64) -> bool {
    (left - right).abs() <= 1e-4
}

fn close_option_f64(left: Option<f64>, right: Option<f64>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => close_f64(left, right),
        (None, None) => true,
        _ => false,
    }
}

fn close_option_f32(left: Option<f32>, right: Option<f32>) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => (left - right).abs() <= 1e-4,
        (None, None) => true,
        _ => false,
    }
}

fn close_f32_slices(left: &[f32], right: &[f32]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| (*left - *right).abs() <= 1e-4)
}
