// SPDX-License-Identifier: GPL-3.0-only
//! Native timing worker for `scripts/l1_presidio/latency.py` (engine `ark-native`) and
//! `scripts/l1_threat/latency.py`.
//!
//! Reads JSON lines `{id, text, samples, warmup, min_samples, budget_ms, categories?}` from the
//! file in the first argument, scans each text with an L1 gateway for `categories` (default
//! `["pii"]`; one gateway per distinct list, all categories in one request) and prints one JSON
//! line per workload: `{id, spans, samples_ns, init_ms}`. After `min_samples` samples, timing
//! stops once `budget_ms` is spent. Percentiles are computed by the Python scripts, so all Ark
//! engines share one definition.
use patronus_ark::{SecurityCategory, SecurityGateway, SecurityLevel};
use serde::Deserialize;
use std::{collections::HashMap, fs, hint::black_box, time::Instant};

#[derive(Deserialize)]
struct Job {
    id: String,
    text: String,
    samples: usize,
    warmup: usize,
    min_samples: usize,
    budget_ms: f64,
    #[serde(default = "default_categories")]
    categories: Vec<SecurityCategory>,
}

fn default_categories() -> Vec<SecurityCategory> {
    vec![SecurityCategory::Pii]
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: l1_latency_workloads JOBS.jsonl")?;
    let jobs = fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(serde_json::from_str::<Job>)
        .collect::<Result<Vec<_>, _>>()?;
    let mut gateways: HashMap<Vec<SecurityCategory>, (SecurityGateway, f64)> = HashMap::new();
    for job in jobs {
        let (gateway, init_ms) = gateways.entry(job.categories.clone()).or_insert_with(|| {
            let started = Instant::now();
            let gateway =
                SecurityGateway::with_max_level(job.categories, SecurityLevel::L1, None, false);
            (gateway, started.elapsed().as_secs_f64() * 1000.0)
        });
        let scan = |text: &str| gateway.scan_all(black_box(text));
        for _ in 0..job.warmup {
            black_box(scan(&job.text));
        }
        let spans: usize = scan(&job.text)
            .iter()
            .map(|result| result.evidence_spans.len())
            .sum();
        let mut samples_ns = Vec::with_capacity(job.samples);
        let budget = Instant::now();
        while samples_ns.len() < job.samples {
            if samples_ns.len() >= job.min_samples
                && budget.elapsed().as_secs_f64() * 1000.0 > job.budget_ms
            {
                break;
            }
            let started = Instant::now();
            black_box(scan(&job.text));
            samples_ns.push(started.elapsed().as_nanos() as u64);
        }
        println!(
            "{}",
            serde_json::json!({
                "id": job.id,
                "spans": spans,
                "samples_ns": samples_ns,
                "init_ms": *init_ms,
            })
        );
    }
    Ok(())
}
