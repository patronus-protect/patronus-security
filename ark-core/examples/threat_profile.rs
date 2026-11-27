// SPDX-License-Identifier: MIT OR Apache-2.0
//! Profile the L1 of the eleven attack classes in one process: per native
//! producer (the threat rules of a class, the injection rules, the
//! sub-detectors) and per L1 model, at short / 4 KiB / 100 KiB / 10 MiB.
//!
//! TEXTS is a JSONL file with a `text` field per row (benign prose); the
//! rows are packed into windows of each size, cut at a character boundary.
//! CONFIG is a `threat_cascade` config (`scanner` key); without one only the
//! rules run. The scanner is built and warmed once, so no process start or
//! first compile is in the measurement. Prints one JSON object per size:
//! `scan` p50/p95 ms and, per producer or `l1_model:<class>`, the p50/p95 ms
//! and the share of the summed producer time.
//!
//! Run: `cargo run --release -q -p patronus-ark-core --example threat_profile -- TEXTS.jsonl [CONFIG.json]`

use std::collections::BTreeMap;
use std::time::Instant;

use patronus_ark_core::{
    cascade::Cascade,
    native::{NativeEngine, NATIVE_CATEGORIES},
    threat::NativeText,
    ScanControl, Scanner, ScannerConfig, SecurityCategory,
};
use serde_json::{json, Value};

/// Window sizes in bytes and how many windows of each are scanned.
const SIZES: [(&str, usize, usize); 4] = [
    ("short", 256, 200),
    ("4KiB", 4 * 1024, 60),
    ("100KiB", 100 * 1024, 20),
    ("10MiB", 10 * 1024 * 1024, 2),
];

fn modules() -> Vec<SecurityCategory> {
    NATIVE_CATEGORIES
        .into_iter()
        .filter(|c| !matches!(c, SecurityCategory::Pii | SecurityCategory::Dlp))
        .collect()
}

fn percentile(values: &mut [f64], q: f64) -> f64 {
    values.sort_by(f64::total_cmp);
    let rank = ((q * values.len() as f64).ceil() as usize).clamp(1, values.len());
    (values[rank - 1] * 1000.0).round() / 1000.0
}

/// Up to `count` windows of `size` bytes, packed from `texts` in order and
/// repeated when the texts run out.
fn windows(texts: &[String], size: usize, count: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    for text in texts.iter().cycle() {
        if out.len() >= count {
            break;
        }
        current.push_str(text);
        current.push('\n');
        if current.len() >= size {
            let mut end = size;
            while !current.is_char_boundary(end) {
                end -= 1;
            }
            out.push(current[..end].to_string());
            current.clear();
        }
    }
    out
}

fn main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (texts_path, config_path) = match args.as_slice() {
        [texts] => (texts, None),
        [texts, config] => (texts, Some(config)),
        _ => return Err("usage: threat_profile TEXTS.jsonl [CONFIG.json]".into()),
    };
    let texts: Vec<String> = std::fs::read_to_string(texts_path)
        .map_err(|e| format!("{texts_path}: {e}"))?
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter_map(|row| row["text"].as_str().map(str::to_string))
        .filter(|text| !text.trim().is_empty())
        .collect();
    if texts.is_empty() {
        return Err(format!("{texts_path}: no texts"));
    }
    let scanner_config = match config_path {
        Some(path) => {
            let doc: Value =
                serde_json::from_slice(&std::fs::read(path).map_err(|e| format!("{path}: {e}"))?)
                    .map_err(|e| format!("{path}: {e}"))?;
            doc.get("scanner").cloned().unwrap_or_else(|| json!({}))
        }
        None => json!({"max_level": "l1", "cascade": {}}),
    };
    let mut config: ScannerConfig =
        serde_json::from_value(scanner_config).map_err(|e| e.to_string())?;
    config.categories = modules();
    config.gates.cascade.get_or_insert_with(Cascade::default);
    let gates = config.gates.clone();
    let mut scanner = Scanner::new(config).map_err(|e| e.to_string())?;
    let modules = modules();
    let engine = NativeEngine::new(&modules);
    engine.prepare(&gates);
    let control = ScanControl::default();
    for (name, size, count) in SIZES {
        let windows = windows(&texts, size, count);
        // Warm-up: compiles every rule the gates enable and loads the models.
        scanner
            .scan_categories(&windows[0], &modules)
            .map_err(|e| e.to_string())?;
        let mut scan = Vec::new();
        let mut parts: BTreeMap<String, Vec<f64>> = BTreeMap::new();
        for window in &windows {
            let started = Instant::now();
            let report = scanner
                .scan_categories(window, &modules)
                .map_err(|e| e.to_string())?;
            scan.push(started.elapsed().as_secs_f64() * 1000.0);
            let mut this_scan: BTreeMap<String, f64> = BTreeMap::new();
            for result in &report.native {
                *this_scan
                    .entry(format!("{}/{}", result.category, result.model))
                    .or_default() += result.duration_ms;
            }
            for decision in report.decision.iter().flatten() {
                for layer in &decision.layers {
                    *this_scan
                        .entry(format!("{}:{}", layer.layer_type, decision.module.as_str()))
                        .or_default() += layer.duration_ms;
                }
            }
            // Each producer on its own, on a fresh prepared text: the
            // per-rule-family split of the native time.
            let started = Instant::now();
            let prepared = NativeText::new(window);
            *this_scan.entry("prepare/native_text".into()).or_default() +=
                started.elapsed().as_secs_f64() * 1000.0;
            for &module in &modules {
                for producer in engine.producers(module) {
                    if !producer.enabled(&gates) {
                        continue;
                    }
                    let outcome = engine
                        .run_producer(producer, &prepared, &gates, &control)
                        .map_err(|e| e.to_string())?;
                    *this_scan
                        .entry(format!("producer:{}/{}", module.as_str(), producer.id()))
                        .or_default() += outcome.duration_ms;
                }
            }
            for (part, ms) in this_scan {
                parts.entry(part).or_default().push(ms);
            }
        }
        let total: f64 = parts
            .iter()
            .filter(|(part, _)| part.starts_with("producer:"))
            .flat_map(|(_, ms)| ms)
            .sum();
        let mut rows: Vec<(String, f64, f64, f64)> = parts
            .into_iter()
            .map(|(part, mut ms)| {
                let share = ms.iter().sum::<f64>() / total.max(f64::MIN_POSITIVE);
                (
                    part,
                    percentile(&mut ms, 0.5),
                    percentile(&mut ms, 0.95),
                    share,
                )
            })
            .collect();
        rows.sort_by(|a, b| b.3.total_cmp(&a.3));
        let parts: Vec<Value> = rows
            .into_iter()
            .map(|(part, p50, p95, share)| {
                json!({"part": part, "p50_ms": p50, "p95_ms": p95,
                       "share": (share * 1000.0).round() / 1000.0})
            })
            .collect();
        let p50 = percentile(&mut scan, 0.5);
        let p95 = percentile(&mut scan, 0.95);
        println!(
            "{}",
            json!({"size": name, "windows": windows.len(), "scan_p50_ms": p50,
                   "scan_p95_ms": p95, "parts": parts})
        );
    }
    Ok(())
}
