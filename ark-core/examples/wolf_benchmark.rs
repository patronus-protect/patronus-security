//! Offline CPU measurement with one warm Scanner. Results contain no scanned text.
use patronus_ark_core::{wolf::WolfConfig, Scanner, ScannerConfig, WolfExecutionOptions};
use std::{path::PathBuf, process::Command, time::Instant};
fn rss_kib() -> Option<u64> {
    let output = Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()?;
    String::from_utf8(output.stdout).ok()?.trim().parse().ok()
}
fn percentiles(mut samples: Vec<f64>) -> serde_json::Value {
    samples.sort_by(f64::total_cmp);
    let pick = |p: f64| {
        samples[((samples.len() as f64 * p).ceil() as usize)
            .saturating_sub(1)
            .min(samples.len() - 1)]
    };
    serde_json::json!({"samples":samples.len(),"p50_ms":pick(0.5),"p95_ms":pick(0.95)})
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let bundle = PathBuf::from(
        args.next()
            .ok_or("usage: wolf_benchmark BUNDLE THRESHOLD [WINDOW_TOKENS OVERLAP_TOKENS BATCH_SIZE SHORT_SAMPLES]")?,
    );
    let threshold: f64 = args
        .next()
        .ok_or("an explicit threshold is required")?
        .parse()?;
    let mut execution = WolfExecutionOptions::default();
    if let Some(value) = args.next() {
        execution.window_tokens = value.parse()?;
    }
    if let Some(value) = args.next() {
        execution.overlap_tokens = value.parse()?;
    }
    if let Some(value) = args.next() {
        execution.batch_size = value.parse()?;
    }
    let samples: usize = args.next().map(|n| n.parse()).transpose()?.unwrap_or(16);
    if samples == 0 {
        return Err("samples must be positive".into());
    }
    let before = rss_kib();
    let start = Instant::now();
    let mut scanner = Scanner::new_with_wolf_options(
        ScannerConfig {
            wolf: Some(WolfConfig {
                bundle_dir: bundle,
                threshold,
                precision: Default::default(),
                backend: Default::default(),
                runtime_options: Default::default(),
            }),
            ..Default::default()
        },
        execution,
    )?;
    let startup_ms = start.elapsed().as_secs_f64() * 1000.0;
    let short = "Please summarize the meeting agenda and opening hours.";
    let model = scanner.scan(short)?.wolf.ok_or("Wolf result missing")?;
    let warm = rss_kib();
    let mut short_samples = Vec::new();
    for _ in 0..samples {
        let start = Instant::now();
        std::hint::black_box(scanner.scan(short)?);
        short_samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let long = "Ordinary technical documentation about library opening hours and meeting agendas. "
        .repeat(210);
    let mut long_samples = Vec::new();
    let mut windows = 0;
    for _ in 0..3 {
        let start = Instant::now();
        let report = scanner.scan(&long)?;
        windows = report.wolf.ok_or("Wolf result missing")?.windows;
        long_samples.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"profile":if cfg!(debug_assertions){"debug"}else{"release"},"backend":"cpu","precision":model.precision,"revision":model.revision,"execution":execution,"concurrency":1,"native_categories":["pii","dlp","injection"],"startup_ms":startup_ms,"baseline_rss_kib":before,"warm_rss_kib":warm,"final_rss_kib":rss_kib(),"short":percentiles(short_samples),"long_input_bytes":long.len(),"long_windows":windows,"long":percentiles(long_samples)})
        )?
    );
    Ok(())
}
