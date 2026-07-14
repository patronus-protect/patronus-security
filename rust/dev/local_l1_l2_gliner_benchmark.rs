use patronus_security::{
    gliner_onnx_engine::GlinerEngine, NtdbOperatingPoint, SecurityCategory, SecurityGateway,
    SecurityLevel, SecurityScanResult,
};
use serde::Deserialize;
use serde_json::json;
use std::{fs, path::Path, process::Command, time::Instant};

const SAMPLES_PER_CLASS: usize = 10;
const MAX_TEXT_TOKENS: usize = 256;
const RESULT_MODEL: &str = "wolf-defender-small";
const LABELS: &[&str] = &[
    "instruction",
    "secret",
    "description of an action",
    "person",
    "organization",
    "location",
    "email address",
    "phone number",
    "credential",
    "password",
    "API key",
    "authentication token",
    "financial information",
    "source code",
    "file path",
    "URL",
    "command",
    "tool name",
    "external recipient",
    "sensitive document",
];

#[derive(Deserialize)]
struct Row {
    id: String,
    text: String,
    expected_class: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if !(4..=5).contains(&args.len()) {
        return Err("usage: local_l1_l2_gliner_benchmark <l2-dir> <gliner-dir> <injection.jsonl> [output.json]".into());
    }
    let output = args
        .get(4)
        .map(Path::new)
        .unwrap_or_else(|| Path::new("../benchmark/gliner_result.json"));
    std::env::set_var("PATRONUS_NTDB_INJECTION_DIR", &args[1]);
    std::env::set_var("PATRONUS_ONNX_EXECUTION_PROVIDER", "cpu");

    let rss_before_mb = rss_mb();
    let started = Instant::now();
    let mut scanner = SecurityGateway::with_max_level(
        vec![SecurityCategory::Injection],
        SecurityLevel::L2,
        None,
        false,
    );
    scanner.set_ntdb_operating_point(NtdbOperatingPoint::BestLatencyInF1);
    scanner.warmup()?;
    let l1_l2_load_ms = elapsed_ms(started);
    let rss_l1_l2_ready_mb = rss_mb();

    let started = Instant::now();
    let mut gliner = GlinerEngine::from_path(&args[2])?;
    let gliner_load_ms = elapsed_ms(started);
    let rss_gliner_loaded_mb = rss_mb();
    let labels = LABELS
        .iter()
        .map(|label| (*label).to_string())
        .collect::<Vec<_>>();

    let samples = select_samples(load_rows(Path::new(&args[3]))?, &gliner, SAMPLES_PER_CLASS)?;
    scanner.scan_category(SecurityCategory::Injection, "Local benchmark warmup only.");
    gliner.extract_entities("Local benchmark warmup only.", &labels, 0.5)?;
    let rss_warmed_mb = rss_mb();

    let mut tp = 0usize;
    let mut fp = 0usize;
    let mut tn = 0usize;
    let mut fn_ = 0usize;
    let mut entity_count = 0usize;
    let mut l1_l2_ms = Vec::with_capacity(samples.len());
    let mut gliner_ms = Vec::with_capacity(samples.len());
    let mut e2e_ms = Vec::with_capacity(samples.len());
    let mut sample_rss_mb = Vec::with_capacity(samples.len());
    let mut rows = Vec::with_capacity(samples.len());

    for sample in samples {
        let token_count = gliner.text_token_count(&sample.text)?;
        let e2e_started = Instant::now();
        let started = Instant::now();
        let results = scanner.scan_category(SecurityCategory::Injection, &sample.text);
        let scan_ms = elapsed_ms(started);
        let result = final_result(&results)
            .ok_or_else(|| format!("sample {} returned no injection result", sample.id))?;

        let started = Instant::now();
        let entities = gliner.extract_entities(&sample.text, &labels, 0.5)?;
        let extract_ms = elapsed_ms(started);
        let total_ms = elapsed_ms(e2e_started);
        let rss = rss_mb();

        let expected_attack = sample.expected_class == "attack";
        let predicted_attack = result.class_name == "attack";
        match (expected_attack, predicted_attack) {
            (true, true) => tp += 1,
            (false, true) => fp += 1,
            (false, false) => tn += 1,
            (true, false) => fn_ += 1,
        }
        entity_count += entities.len();
        l1_l2_ms.push(scan_ms);
        gliner_ms.push(extract_ms);
        e2e_ms.push(total_ms);
        sample_rss_mb.push(rss);
        rows.push(json!({
            "id": sample.id,
            "expected_class": sample.expected_class,
            "predicted_class": result.class_name,
            "text_tokens": token_count,
            "gliner_entities": entities.len(),
            "l1_l2_ms": scan_ms,
            "gliner_ms": extract_ms,
            "end_to_end_ms": total_ms,
            "rss_mb": rss,
        }));
    }

    let report = json!({
        "samples": rows.len(),
        "sample_selection": {
            "attack": SAMPLES_PER_CLASS,
            "benign": SAMPLES_PER_CLASS,
            "max_text_tokens": MAX_TEXT_TOKENS,
            "chunks_per_sample": 1,
        },
        "pipeline": ["injection_l1", "injection_l2", "dynamic-pii"],
        "gliner": {
            "labels": labels,
            "entities_returned": entity_count,
            "threshold": 0.5,
        },
        "quality": {
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn_,
            "f1": ratio(2 * tp, 2 * tp + fp + fn_),
            "fpr": ratio(fp, fp + tn),
            "fnr": ratio(fn_, fn_ + tp),
        },
        "latency_ms": {
            "l1_l2": stats(&l1_l2_ms),
            "gliner": stats(&gliner_ms),
            "end_to_end": stats(&e2e_ms),
        },
        "initialization_ms": {
            "l1_l2": l1_l2_load_ms,
            "gliner": gliner_load_ms,
        },
        "memory_mb": {
            "before": rss_before_mb,
            "l1_l2_ready": rss_l1_l2_ready_mb,
            "gliner_loaded": rss_gliner_loaded_mb,
            "warmed": rss_warmed_mb,
            "after_samples": rss_mb(),
            "max_sample_rss": sample_rss_mb.iter().copied().fold(0.0_f64, f64::max),
            "process_peak_rss": peak_rss_mb(),
        },
        "rows": rows,
    });
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(output, serde_json::to_string_pretty(&report)? + "\n")?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

fn select_samples(
    rows: Vec<Row>,
    gliner: &GlinerEngine,
    per_class: usize,
) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
    let mut attacks = Vec::with_capacity(per_class);
    let mut benign = Vec::with_capacity(per_class);
    for row in rows {
        if gliner.text_token_count(&row.text)? > MAX_TEXT_TOKENS {
            continue;
        }
        let target = if row.expected_class == "attack" {
            &mut attacks
        } else if row.expected_class == "benign" {
            &mut benign
        } else {
            continue;
        };
        if target.len() < per_class {
            target.push(row);
        }
        if attacks.len() == per_class && benign.len() == per_class {
            break;
        }
    }
    if attacks.len() != per_class || benign.len() != per_class {
        return Err(format!(
            "need {per_class} one-chunk samples per class; found {} attacks and {} benign",
            attacks.len(),
            benign.len()
        )
        .into());
    }
    let mut selected = Vec::with_capacity(per_class * 2);
    for (attack, safe) in attacks.into_iter().zip(benign) {
        selected.push(attack);
        selected.push(safe);
    }
    Ok(selected)
}

fn final_result(results: &[SecurityScanResult]) -> Option<&SecurityScanResult> {
    results.iter().find(|result| result.model == RESULT_MODEL)
}

fn load_rows(path: &Path) -> Result<Vec<Row>, Box<dyn std::error::Error>> {
    fs::read_to_string(path)?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).map_err(Into::into))
        .collect()
}

fn stats(values: &[f64]) -> serde_json::Value {
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let percentile = |p: f64| {
        let index = ((sorted.len() - 1) as f64 * p).round() as usize;
        sorted[index]
    };
    json!({
        "mean": sorted.iter().sum::<f64>() / sorted.len() as f64,
        "p50": percentile(0.50),
        "p95": percentile(0.95),
        "max": sorted[sorted.len() - 1],
    })
}

fn ratio(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

fn rss_mb() -> f64 {
    Command::new("ps")
        .args(["-o", "rss=", "-p", &std::process::id().to_string()])
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .and_then(|value| value.trim().parse::<f64>().ok())
        .map(|kilobytes| kilobytes / 1024.0)
        .unwrap_or(f64::NAN)
}

#[cfg(target_os = "macos")]
fn peak_rss_mb() -> f64 {
    #[repr(C)]
    struct TimeVal {
        seconds: i64,
        microseconds: i64,
    }
    #[repr(C)]
    struct ResourceUsage {
        user_time: TimeVal,
        system_time: TimeVal,
        max_rss: i64,
        remaining: [i64; 13],
    }
    unsafe extern "C" {
        fn getrusage(who: i32, usage: *mut ResourceUsage) -> i32;
    }
    let mut usage = std::mem::MaybeUninit::<ResourceUsage>::zeroed();
    if unsafe { getrusage(0, usage.as_mut_ptr()) } == 0 {
        unsafe { usage.assume_init().max_rss as f64 / (1024.0 * 1024.0) }
    } else {
        f64::NAN
    }
}

#[cfg(not(target_os = "macos"))]
fn peak_rss_mb() -> f64 {
    f64::NAN
}
