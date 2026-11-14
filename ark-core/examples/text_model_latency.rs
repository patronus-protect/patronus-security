// SPDX-License-Identifier: MIT OR Apache-2.0
//! Time a text category `model.json` on the 100 KiB latency windows: the
//! cost the model adds on top of the facts, which every stage shares. Reads
//! the windows (`windows.jsonl` of `scripts/l1_threat/latency.py`, rows with
//! a `text` field), extracts the facts of each once, then times only the
//! model score. The ablation (`scripts/l1_threat/ablation.py`) runs it per
//! model stage and prints `{"p50_ms", "p95_ms", "samples"}` normalised to
//! 100 KiB.
//!
//! `--tokens` names the token source of the model's token block: `tf1` (words
//! and fact tokens), `words` (`T:` words only) or `none` (char n-grams only).
//!
//! Run: `cargo run --release -q -p patronus-ark-core --example text_model_latency -- MODEL.json WINDOWS.jsonl --tokens words`

use std::time::Instant;

use patronus_ark_core::detectors::facts_common::model::TfidfLrModel;
use patronus_ark_core::detectors::text::{extract, model, visit_tf1, TEXT_MODEL};
use serde_json::{json, Value};

const SAMPLES: usize = 5;
const WINDOW_BYTES: f64 = 100.0 * 1024.0;

fn percentile(sorted: &[f64], q: f64) -> f64 {
    let rank = ((q * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (model_path, windows_path) = match args.as_slice() {
        [model, windows, ..] => (model, windows),
        _ => return Err("usage: text_model_latency MODEL.json WINDOWS.jsonl [--tokens tf1|words|none]".into()),
    };
    let tokens = match args.iter().position(|a| a == "--tokens") {
        Some(at) => args.get(at + 1).map(String::as_str).unwrap_or(""),
        None => "tf1",
    };
    if !matches!(tokens, "tf1" | "words" | "none") {
        return Err(format!("unknown --tokens {tokens}"));
    }
    let bytes = std::fs::read(model_path).map_err(|e| format!("{model_path}: {e}"))?;
    let model = TfidfLrModel::from_json_slice(&bytes, TEXT_MODEL)?;
    let windows = std::fs::read_to_string(windows_path).map_err(|e| format!("{windows_path}: {e}"))?;
    let mut samples = Vec::new();
    for line in windows.lines().filter(|l| !l.trim().is_empty()) {
        let row: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        let text = row["text"].as_str().ok_or("window without text")?;
        let facts = extract(text, &[], &[]);
        let scale = WINDOW_BYTES / text.len().max(1) as f64;
        for _ in 0..=SAMPLES {
            let start = Instant::now();
            let (score, _) = match tokens {
                "tf1" => model::score(&model, text, &facts),
                "words" => model.score(text, |emit| {
                    visit_tf1(text, &facts, &mut |t| {
                        if t.starts_with("T:") {
                            emit(t)
                        }
                    })
                }),
                _ => model.score(text, |_| {}),
            };
            samples.push(start.elapsed().as_secs_f64() * 1000.0 * scale);
            std::hint::black_box(score);
        }
        // The first sample of a window warms it up.
        samples.remove(samples.len() - SAMPLES - 1);
    }
    if samples.is_empty() {
        return Err("no windows".into());
    }
    samples.sort_by(f64::total_cmp);
    let out = json!({
        "p50_ms": percentile(&samples, 0.5),
        "p95_ms": percentile(&samples, 0.95),
        "samples": samples.len(),
    });
    println!("{out}");
    Ok(())
}
