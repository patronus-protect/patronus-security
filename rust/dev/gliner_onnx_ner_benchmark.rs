use patronus_security::gliner_onnx_engine::GlinerEngine;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{collections::HashSet, fs, path::Path, time::Instant};

const INFERENCE_FLOOR: f32 = 0.05;
const THRESHOLDS: &[f32] = &[0.3, 0.4, 0.5, 0.6, 0.7];
const DEFAULT_LABELS: &[&str] = &[
    "person",
    "organization",
    "location",
    "date",
    "email",
    "phone_number",
];

#[derive(Deserialize)]
struct Dataset {
    source: serde_json::Value,
    selection: serde_json::Value,
    labels: Vec<String>,
    samples: Vec<Sample>,
}

#[derive(Deserialize)]
struct Sample {
    entities: Vec<GoldEntity>,
    text: String,
}

#[derive(Deserialize)]
struct GoldEntity {
    start: usize,
    end: usize,
    label: String,
}

struct Prediction {
    start: usize,
    end: usize,
    label: String,
    score: f32,
}

struct Engine(GlinerEngine);

impl Engine {
    fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self(GlinerEngine::from_path(path)?))
    }

    fn name(&self) -> &'static str {
        "patronus-studio/gliner_small-v2.5-edge"
    }

    fn extract(
        &mut self,
        text: &str,
        labels: &[String],
    ) -> Result<Vec<Prediction>, Box<dyn std::error::Error>> {
        Ok(self
            .0
            .extract_entities(text, labels, INFERENCE_FLOOR)?
            .into_iter()
            .map(|entity| Prediction {
                start: entity.start_char,
                end: entity.end_char,
                label: entity.label,
                score: entity.score,
            })
            .collect())
    }
}

#[derive(Default, Serialize)]
struct Metrics {
    tp: usize,
    fp: usize,
    #[serde(rename = "fn")]
    fn_: usize,
    precision: f64,
    recall: f64,
    f1: f64,
}

impl Metrics {
    fn update(&mut self, gold: &EntitySet, predicted: &EntitySet) {
        self.tp += gold.intersection(predicted).count();
        self.fp += predicted.difference(gold).count();
        self.fn_ += gold.difference(predicted).count();
    }

    fn finish(mut self) -> Self {
        self.precision = ratio(self.tp, self.tp + self.fp);
        self.recall = ratio(self.tp, self.tp + self.fn_);
        self.f1 = if self.precision + self.recall == 0.0 {
            0.0
        } else {
            2.0 * self.precision * self.recall / (self.precision + self.recall)
        };
        self
    }
}

type EntitySet = HashSet<(usize, usize, String)>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 3 {
        return Err("usage: gliner_onnx_ner_benchmark <model-dir> <dataset.json>".into());
    }
    let dataset = load_dataset(Path::new(&args[2]))?;

    let load_started = Instant::now();
    let mut engine = Engine::load(Path::new(&args[1]))?;
    let load_ms = load_started.elapsed().as_secs_f64() * 1_000.0;
    engine.extract("Benedikt works at Patronus in Berlin.", &dataset.labels)?;

    let mut latencies = Vec::with_capacity(dataset.samples.len());
    let mut predictions = Vec::with_capacity(dataset.samples.len());
    for (index, sample) in dataset.samples.iter().enumerate() {
        let started = Instant::now();
        predictions.push(engine.extract(&sample.text, &dataset.labels)?);
        latencies.push(started.elapsed().as_secs_f64() * 1_000.0);
        if (index + 1) % 25 == 0 {
            eprintln!("completed {}/{} samples", index + 1, dataset.samples.len());
        }
    }

    let threshold_reports = THRESHOLDS
        .iter()
        .map(|threshold| threshold_report(&dataset, &predictions, *threshold))
        .collect::<Vec<_>>();
    let bucket_f1 = dataset
        .samples
        .chunks(50)
        .zip(predictions.chunks(50))
        .map(|(samples, predicted)| metrics(samples, predicted, 0.5).finish().f1)
        .collect::<Vec<_>>();

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "model": engine.name(),
            "runtime": ort::info(),
            "dataset": {
                "source": dataset.source,
                "selection": dataset.selection,
                "samples": dataset.samples.len(),
                "gold_entities": dataset.samples.iter().map(|sample| sample.entities.len()).sum::<usize>(),
                "labels": dataset.labels,
            },
            "inference_floor": INFERENCE_FLOOR,
            "thresholds": threshold_reports,
            "f1_at_0_5_by_consecutive_50_sample_bucket": bucket_f1,
            "latency_ms": latency(&mut latencies),
            "load_ms": load_ms,
        }))?
    );
    Ok(())
}

fn load_dataset(path: &Path) -> Result<Dataset, Box<dyn std::error::Error>> {
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(path)?)?;
    if value.is_array() {
        return Ok(Dataset {
            source: json!({"path": path}),
            selection: json!({"format": "eval_quant_fixture"}),
            labels: DEFAULT_LABELS
                .iter()
                .map(|label| (*label).to_string())
                .collect(),
            samples: serde_json::from_value(value)?,
        });
    }
    Ok(serde_json::from_value(value)?)
}

fn threshold_report(
    dataset: &Dataset,
    predictions: &[Vec<Prediction>],
    threshold: f32,
) -> serde_json::Value {
    let overall = metrics(&dataset.samples, predictions, threshold).finish();
    let per_label = dataset
        .labels
        .iter()
        .map(|label| {
            let mut result = Metrics::default();
            for (sample, predicted) in dataset.samples.iter().zip(predictions) {
                let gold = gold_set(sample, Some(label));
                let predicted = prediction_set(predicted, threshold, Some(label));
                result.update(&gold, &predicted);
            }
            (label.clone(), json!(result.finish()))
        })
        .collect::<serde_json::Map<_, _>>();
    let exact_samples = dataset
        .samples
        .iter()
        .zip(predictions)
        .filter(|(sample, predicted)| {
            gold_set(sample, None) == prediction_set(predicted, threshold, None)
        })
        .count();
    json!({
        "threshold": threshold,
        "micro": overall,
        "per_label": per_label,
        "exact_sample_matches": exact_samples,
        "exact_sample_match_rate": ratio(exact_samples, dataset.samples.len()),
    })
}

fn metrics(samples: &[Sample], predictions: &[Vec<Prediction>], threshold: f32) -> Metrics {
    let mut result = Metrics::default();
    for (sample, predicted) in samples.iter().zip(predictions) {
        result.update(
            &gold_set(sample, None),
            &prediction_set(predicted, threshold, None),
        );
    }
    result
}

fn gold_set(sample: &Sample, label: Option<&str>) -> EntitySet {
    sample
        .entities
        .iter()
        .filter(|entity| label.is_none_or(|expected| entity.label == expected))
        .map(|entity| (entity.start, entity.end, entity.label.clone()))
        .collect()
}

fn prediction_set(predictions: &[Prediction], threshold: f32, label: Option<&str>) -> EntitySet {
    predictions
        .iter()
        .filter(|entity| {
            entity.score >= threshold && label.is_none_or(|expected| entity.label == expected)
        })
        .map(|entity| (entity.start, entity.end, entity.label.clone()))
        .collect()
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn latency(values: &mut [f64]) -> serde_json::Value {
    values.sort_by(f64::total_cmp);
    json!({
        "mean": values.iter().sum::<f64>() / values.len() as f64,
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "max": values[values.len() - 1],
    })
}

fn percentile(values: &[f64], percentile: f64) -> f64 {
    values[((values.len() - 1) as f64 * percentile).round() as usize]
}
